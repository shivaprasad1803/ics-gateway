"""
modbus_server.py  —  Protected Modbus TCP Server
=================================================
Layer 1 + 4 + 5 + 6  |  PhysicsGuard ICS Security Gateway
 
Defence-in-depth pipeline for every external write:
  1. A07: Function-code whitelist (FC03 read, FC06 write only)
  2. A06: DoS rate-limit per source IP (10 cmd/s sliding window)
  3. Read-only guard (HR[0], HR[10] are sensor registers)
  4. Layer 4 ValidationEngine  (R001–R008)
  5. Layer 5 AlertManager      (Telegram for CRITICAL/EMERGENCY)
  6. Layer 6 ForensicLogger    (non-blocking, async SQLite)
  7. Layer 1 WaterTankController / TemperatureController physics
 
Register Map:
  PLC_01 — Water Tank:
    HR[0]  40001  Tank Level        READ-ONLY  [0-100 %]
    HR[1]  40002  Valve Position    READ-WRITE [0-100 %, ≤5 %/s]
    HR[2]  40003  Pump State        READ-WRITE [0=OFF, 1=ON]
 
  PLC_02 — Temperature Controller:
    HR[10] 40011  Temperature       READ-ONLY  [0-200 °C]
    HR[11] 40012  Heater Power      READ-WRITE [0-100 %]
 
Design-fix notes:
  D14 — physics_loop wraps tick body in try/except; silent death prevented.
  D15 — last_cmd_time sourced from get_state(), not manual injection.
  D16 — physics_loop accepts stop_event; graceful shutdown on Ctrl+C.
  A06 — Sliding-window DoS rate limiter per source IP (10 cmd/s).
  A07 — Function-code whitelist enforced in IPAwareRequestHandler via
        pymodbus 3.x's request.function_code attribute (PDU-level check).
  C2  — Real client IP propagated via ContextVar through asyncio chain.
  H4  — cmd_timestamp (= t_start) injected into context for R008 ReplayRule.
  L6-1 — latency_us brackets engine.validate() for every DB record.
"""
 
import contextvars
import logging
import os
import sys
import threading
import time
from collections import deque

from dotenv import load_dotenv
load_dotenv()
 
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)
 
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusDeviceContext,
)
from pymodbus.server import ModbusTcpServer
from pymodbus.server.requesthandler import ServerRequestHandler
 
from src.water_tank             import WaterTankController
from src.temperature_controller import TemperatureController
from src.validation_engine import (
    ValidationEngine,
    build_water_tank_engine,
    load_rules_from_yaml,
)
from src.forensic_logger import ForensicLogger, get_logger
from src.alerting        import AlertManager
 
log = logging.getLogger(__name__)
 
_physics_thread_local = threading.local()
 
# ContextVar carries the real client IP from handle_request() → setValues()
# without modifying any call-stack signatures (C2 fix).
_current_client_ip: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_current_client_ip", default="unknown"
)
 
# A07 — Whitelisted Modbus function codes:
#   0x03 = Read Holding Registers
#   0x06 = Write Single Register
# Any other function code is silently dropped before reaching the datastore.
_ALLOWED_FUNCTION_CODES: frozenset[int] = frozenset({0x03, 0x06})
 
 
class IPAwareRequestHandler(ServerRequestHandler):
    """
    ServerRequestHandler subclass that:
      1. A07: Blocks non-whitelisted Modbus function codes (PDU-level).
      2. C2:  Injects the real client IP into _current_client_ip ContextVar
              so setValues() can read it without needing a call-stack change.
 
    pymodbus 3.x decodes the PDU before calling handle_request(), so
    self.request is the decoded Modbus PDU object.  Its .function_code
    attribute gives us the FC cleanly without touching raw bytes.
    """
 
    async def handle_request(self) -> None:
        # A07: function-code whitelist — check decoded PDU attribute.
        # self.request is set by the framer before this coroutine runs.
        try:
            fc = getattr(self.request, "function_code", None)
            if fc is not None and fc not in _ALLOWED_FUNCTION_CODES:
                log.warning(
                    "A07 FC BLOCK | function_code=0x%02X not whitelisted | "
                    "client=%s",
                    fc,
                    self.transport.get_extra_info("peername", ("?", 0))[0]
                    if self.transport else "?",
                )
                return  # drop silently — no Modbus exception frame returned
        except Exception:
            pass  # defensive — if request is not yet set, proceed normally
 
        # C2: extract real client IP and store it in the ContextVar so
        # setValues() can read it without needing it threaded through args.
        peername = None
        try:
            if self.transport is not None:
                peername = self.transport.get_extra_info("peername")
        except Exception:
            pass
 
        ip = peername[0] if peername else "unknown"
        token = _current_client_ip.set(ip)
        try:
            await super().handle_request()
        finally:
            _current_client_ip.reset(token)
 
 
class IPAwareModbusTcpServer(ModbusTcpServer):
    """Uses IPAwareRequestHandler for every connection."""
 
    def callback_new_connection(self) -> IPAwareRequestHandler:
        return IPAwareRequestHandler(
            self,
            self.trace_packet,
            self.trace_pdu,
            self.trace_connect,
        )
 
 
class ProtectedHoldingRegister(ModbusSequentialDataBlock):
    """
    Modbus holding register block with full defence-in-depth protection.
 
    Write pipeline (external writes only — physics loop is trusted):
      1. Read-only guard
      2. A06: DoS rate-limit per source IP
      3. Layer 4: ValidationEngine (R001–R008)
      4. Layer 5: AlertManager (Telegram for CRITICAL/EMERGENCY)
      5. Layer 6: ForensicLogger (async SQLite, non-blocking)
      6. Layer 1: Physics controllers (WaterTank / Temperature)
 
    Read-only registers (physics loop writes these via trusted bypass):
      HR[0]  — tank level (WaterTankController sensor)
      HR[10] — temperature (TemperatureController sensor)
    """
 
    # Registers that only the physics loop may write.
    _READ_ONLY_REGISTERS: frozenset[int] = frozenset({0, 10})
 
    # A06 — DoS rate-limiting: max 10 commands per 1-second window per IP.
    _MAX_RATE: int   = 10
    _WINDOW_S: float = 1.0
 
    # Address ranges mapped to PLCs.
    _TANK_REGISTERS: range = range(0, 10)   # HR[0-9]  → PLC_01 (water tank)
    _TEMP_REGISTERS: range = range(10, 20)  # HR[10-19] → PLC_02 (temperature)
 
    def __init__(
        self,
        tank:    WaterTankController,
        temp:    TemperatureController,
        engine:  ValidationEngine,
        flogger: ForensicLogger,
    ) -> None:
        # 20 registers: HR[0-9] for tank, HR[10-19] for temperature.
        initial_values = [0] * 20
        initial_values[0]  = round(tank.get_state()["tank_level"])
        initial_values[1]  = 0   # valve closed
        initial_values[2]  = 0   # pump off
        initial_values[10] = round(temp.get_state()["temperature"])  # ambient °C
        initial_values[11] = 0   # heater off
        super().__init__(address=0, values=initial_values)
 
        self._tank    = tank
        self._temp    = temp
        self._engine  = engine
        self._flogger = flogger
 
        # A06: per-IP command timestamp deques for sliding-window DoS detection.
        self._ip_history: dict[str, deque[float]] = {}
 
        # Layer 5: AlertManager constructed once — falls back to log-only if
        # env vars PHYSICSGUARD_BOT_TOKEN / PHYSICSGUARD_CHAT_ID are absent.
        self._alert_manager: AlertManager = AlertManager.from_env()
 
        log.info(
            "ProtectedHoldingRegister ready | "
            "tank=%.1f%% pump=OFF valve=0%% | temp=%.1f°C heater=OFF",
            tank.get_state()["tank_level"],
            temp.get_state()["temperature"],
        )
 
    # ── A06: DoS rate-limiter ─────────────────────────────────────────────────
 
    def _is_rate_limited(self, ip: str) -> bool:
        """
        Sliding-window rate limiter (A06, MITRE T0815).
 
        Returns True when the IP has exceeded _MAX_RATE commands within
        the last _WINDOW_S seconds.  A blocked call is NOT recorded so
        the attacker cannot inflate the window to push out their own history.
        """
        now = time.monotonic()
        if ip not in self._ip_history:
            self._ip_history[ip] = deque()
 
        window = self._ip_history[ip]
        # Evict timestamps outside the sliding window.
        while window and now - window[0] > self._WINDOW_S:
            window.popleft()
 
        if len(window) >= self._MAX_RATE:
            return True  # limit exceeded — caller must drop this command
 
        window.append(now)
        return False
 
    # ── Main write intercept ──────────────────────────────────────────────────
 
    def setValues(self, address: int, values: list) -> None:
        # ── Physics-loop bypass ───────────────────────────────────────────────
        # The physics thread sets this flag on its thread-local storage.
        # Its writes are always trusted — skip all guards.
        if getattr(_physics_thread_local, "is_physics_loop", False):
            super().setValues(address, values)
            return
 
        # ── Read-only guard ───────────────────────────────────────────────────
        if address in self._READ_ONLY_REGISTERS:
            log.warning(
                "BLOCKED READ-ONLY | reg=%d | external write rejected", address
            )
            return
 
        if not values:
            return
 
        value      = float(values[0])
        source_ip  = _current_client_ip.get()
 
        # ── A06: DoS rate-limit ───────────────────────────────────────────────
        if self._is_rate_limited(source_ip):
            log.warning(
                "A06 DOS BLOCK | ip=%s | exceeded %d cmd/%.1fs window",
                source_ip, self._MAX_RATE, self._WINDOW_S,
            )
            return  # dropped before reaching ValidationEngine
 
        # ── Route to the correct PLC context ─────────────────────────────────
        # IMPORTANT: this sets both 'context' AND 'target_plc' once,
        # and we do NOT overwrite 'context' anywhere below.
        if address in self._TANK_REGISTERS:
            context    = self._tank.get_state()
            target_plc = "PLC_01"
        elif address in self._TEMP_REGISTERS:
            context    = self._temp.get_state()
            target_plc = "PLC_02"
        else:
            log.warning(
                "BLOCKED UNKNOWN | reg=%d val=%s | not in register map",
                address, values,
            )
            return
 
        # ── Layer 4: ValidationEngine ─────────────────────────────────────────
        # H4 fix: t_start is reused as cmd_timestamp so R008 ReplayRule gets
        # a consistent monotonic timestamp — no second time.monotonic() call.
        t_start = time.monotonic()
        context["cmd_timestamp"] = t_start          # R008 replay detection
        context["target_plc_id"] = target_plc       # R007 topology check
        # Note: source_plc_id is intentionally NOT set from source_ip here.
        # R007 reads source_plc_id as a PLC name ("PLC_01"), which comes from
        # a higher-level SCADA context.  In the bare Modbus path, commands
        # originate from the default PLC so no source_plc_id injection needed —
        # R007 will skip (pass-through) when the key is absent, which is correct
        # behaviour for operator commands arriving without explicit PLC routing.
 
        engine_result = self._engine.validate(
            address=address, value=value, context=context
        )
        latency_us = round((time.monotonic() - t_start) * 1_000_000, 2)
 
        # ── Layer 6: ForensicLogger ───────────────────────────────────────────
        self._flogger.log_command(
            address    = address,
            value      = value,
            allowed    = engine_result.allowed,
            rule_id    = engine_result.rule_id   or "",
            reason     = engine_result.reason    or "",
            severity   = engine_result.severity  or "INFO",
            mitre_tag  = engine_result.mitre_tag or "",
            source_ip  = source_ip,
            latency_us = latency_us,
        )
 
        if not engine_result.allowed:
            # Layer 5: Telegram alert for CRITICAL / EMERGENCY (non-blocking).
            self._alert_manager.send(engine_result)
            return  # register unchanged
 
        # ── Layer 1: Physics controllers ──────────────────────────────────────
        if address == 1:          # valve position — water tank
            phys = self._tank.set_valve_position(value)
            if phys["allowed"]:
                super().setValues(1, [round(value)])
            else:
                log.warning("PHYSICS BLOCK | reg=1 val=%.2f | %s",
                            value, phys.get("reason", ""))
 
        elif address == 2:        # pump state — water tank
            phys = self._tank.set_pump_state(bool(values[0]))
            if phys["allowed"]:
                super().setValues(2, [int(bool(values[0]))])
            else:
                log.warning("PHYSICS BLOCK | reg=2 val=%.2f | %s",
                            value, phys.get("reason", ""))
 
        elif address == 11:       # heater power — temperature controller
            phys = self._temp.set_heater_power(value)
            if phys["allowed"]:
                super().setValues(11, [round(value)])
            else:
                log.warning("PHYSICS BLOCK | reg=11 val=%.2f | %s",
                            value, phys.get("reason", ""))
 
        else:
            log.warning(
                "BLOCKED UNKNOWN | reg=%d val=%s | not in register map",
                address, values,
            )
 
 
# ── Factory helpers ────────────────────────────────────────────────────────────
 
def build_context(
    tank:    WaterTankController,
    temp:    TemperatureController,
    engine:  ValidationEngine,
    flogger: ForensicLogger,
):
    hr_block = ProtectedHoldingRegister(tank, temp, engine, flogger)
    slave    = ModbusDeviceContext(hr=hr_block)
    context  = ModbusServerContext(devices=slave, single=True)
    return hr_block, context
 
 
def physics_loop(
    tank:       WaterTankController,
    temp:       TemperatureController,
    hr_block:   ProtectedHoldingRegister,
    stop_event: threading.Event,
    tick_s:     float = 0.1,
) -> None:
    """
    Trusted physics update loop — runs in a dedicated daemon thread.
    Sets the is_physics_loop flag so setValues() bypasses all guards.
    D14: entire tick body wrapped in try/except — thread never dies silently.
    """
    _physics_thread_local.is_physics_loop = True
    log.info("Physics loop started (tick=%.0f ms)", tick_s * 1000)
 
    while not stop_event.is_set():
        try:
            now   = time.monotonic()
 
            # Water tank physics
            state = tank.update_physics(now=now)
            hr_block.setValues(0,  [state["tank_level_int"]])
            hr_block.setValues(1,  [state["valve_int"]])
            hr_block.setValues(2,  [state["pump_int"]])
 
            # Temperature controller physics
            p_state = temp.update_physics(now=now)
            hr_block.setValues(10, [p_state["temp_int"]])
            # HR[11] (heater power) is written by the operator — physics does
            # not change it; it only applies its current value to the simulation.
 
        except Exception:
            log.exception("Physics loop error — registers may be stale; retrying")
 
        time.sleep(tick_s)   # outside try so a crash doesn't busy-spin
 
    log.info("Physics loop stopped (stop_event set)")
 
 
# ── Entry point ───────────────────────────────────────────────────────────────
 
def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="PhysicsGuard Modbus TCP Server")
    parser.add_argument(
        "--initial-level",
        type=float,
        default=None,
        metavar="PCT",
        help=(
            "Override the tank's starting level [0-100%%]. "
            "Used by integration tests (e.g. --initial-level 5 for A03). "
            "Defaults to WaterTankController.INITIAL_LEVEL (50%%)."
        ),
    )
    args = parser.parse_args()
 
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(name)s -- %(message)s",
        datefmt="%H:%M:%S",
    )
 
    # ── Instantiate physics controllers ───────────────────────────────────────
    tank_kwargs: dict = {}
    if args.initial_level is not None:
        if not (0.0 <= args.initial_level <= 100.0):
            parser.error(
                f"--initial-level must be in [0, 100], got {args.initial_level}"
            )
        tank_kwargs["INITIAL_LEVEL"] = args.initial_level
        log.info("CLI override: INITIAL_LEVEL=%.1f%%", args.initial_level)
 
    # Only create controllers once — after argument parsing.
    tank = WaterTankController(**tank_kwargs)
    temp = TemperatureController()
 
    # ── Build ValidationEngine ────────────────────────────────────────────────
    _yaml_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "rules.yaml",
    )
    if os.path.exists(_yaml_path):
        log.info("M4: loading rules from %s", _yaml_path)
        engine = load_rules_from_yaml(_yaml_path)
        log.info(
            "M4: YAML engine loaded — %d rules from config file",
            len(engine.get_rules()),
        )
        # Novel-contribution rules that cannot be expressed in flat YAML:
        from src.rules.temporal_rule import TemporalRule
        engine.register_rule(TemporalRule(
            address=1, window_s=300.0, max_cumulative_delta=15.0, label="%",
        ))
        from src.rules.topology_rule import TopologyRule
        from src.plant_topology import build_water_tank_topology
        engine.register_rule(TopologyRule(
            topology=build_water_tank_topology(), default_target="PLC_01",
        ))
        from src.rules.replay_rule import ReplayRule
        engine.register_rule(ReplayRule(address=None, replay_window_s=5.0))
        log.info("M4: R006 TemporalRule, R007 TopologyRule, R008 ReplayRule wired")

        from src.rules.oscillation_rule import OscillationRule
        engine.register_rule(OscillationRule(
            address=1, window_s=120.0, max_reversals=4, min_delta_pct=10.0,
        ))
        log.info("R009 OscillationRule wired")
    else:
        log.warning(
            "M4: config/rules.yaml not found — falling back to hardcoded defaults"
        )
        engine = build_water_tank_engine()
 
    # Wire ConsequenceEngine (novel contribution #1).
    from src.consequence_engine import ConsequenceEngine
    engine.set_consequence_engine(ConsequenceEngine())
 
    # ── Build server ──────────────────────────────────────────────────────────
    flogger           = get_logger("logs/physicsguard.db")
    hr_block, context = build_context(tank, temp, engine, flogger)
 
    stop_event = threading.Event()
    threading.Thread(
        target=physics_loop,
        args=(tank, temp, hr_block, stop_event),
        daemon=True,
        name="physics-loop",
    ).start()
 
    import asyncio
 
    _bind_host: str = os.environ.get("MODBUS_BIND_HOST", "0.0.0.0")
    _bind_port: int = int(os.environ.get("MODBUS_BIND_PORT", "5020"))
 
    _print_banner(engine, tank, temp, flogger, _bind_host, _bind_port)
 
    async def _run_server() -> None:
        server = IPAwareModbusTcpServer(
            context=context, address=(_bind_host, _bind_port)
        )
        log.info("Modbus TCP server listening on %s:%d", _bind_host, _bind_port)
        await server.serve_forever()
 
    try:
        asyncio.run(_run_server())
    except KeyboardInterrupt:
        log.info("Shutdown requested — stopping physics loop")
    finally:
        stop_event.set()
        flogger.stop()
        log.info(
            "PhysicsGuard stopped | session=%s | dropped=%d",
            flogger.session_id, flogger.dropped,
        )
 
 
def _print_banner(
    engine:    ValidationEngine,
    tank:      WaterTankController,
    temp:      TemperatureController,
    flogger:   ForensicLogger,
    bind_host: str = "0.0.0.0",
    bind_port: int = 5020,
) -> None:
    rules      = engine.get_rules()
    tank_state = tank.get_state()
    temp_state = temp.get_state()
    sep        = "=" * 62
 
    bot_token = os.environ.get("PHYSICSGUARD_BOT_TOKEN", "").strip()
    chat_id   = os.environ.get("PHYSICSGUARD_CHAT_ID",   "").strip()
    telegram_status = (
        f"LIVE  (chat_id={chat_id})"
        if bot_token and chat_id
        else "DISABLED  (set PHYSICSGUARD_BOT_TOKEN + PHYSICSGUARD_CHAT_ID)"
    )
 
    print(sep)
    print("  PhysicsGuard  |  ICS Security Gateway  |  Layer 1+4+5+6")
    print(f"  Modbus TCP server  ->  {bind_host}:{bind_port}")
    print()
    print("  PLC_01 — Water Tank:")
    print(f"    Tank Level : {tank_state['tank_level']:.1f}%")
    print(f"    Valve      : {tank_state['valve_position']:.1f}%")
    print(f"    Pump       : {'ON' if tank_state['pump_running'] else 'OFF'}")
    print()
    print("  PLC_02 — Temperature Controller:")
    print(f"    Temperature : {temp_state['temperature']:.1f}°C")
    print(f"    Heater      : {temp_state['heater_power']:.1f}%")
    print()
    print("  Register Map:")
    print("    HR[0]  40001  Tank Level    READ-ONLY  [0-100 %]")
    print("    HR[1]  40002  Valve Pos     READ-WRITE [0-100 %, ≤5 %/s]")
    print("    HR[2]  40003  Pump State    READ-WRITE [0=OFF 1=ON]")
    print("    HR[10] 40011  Temperature   READ-ONLY  [0-200 °C]")
    print("    HR[11] 40012  Heater Power  READ-WRITE [0-100 %]")
    print()
    print(f"  Validation Engine: {len(rules)} rules loaded")
    for r in rules:
        status = "ON " if r["enabled"] else "OFF"
        print(
            f"    [{status}] {r['rule_id']}  {r['severity']:<10} "
            f"priority={r['priority']}  {r['mitre_tag']}"
        )
    print()
    print(
        f"  DoS Rate Limit  ->  "
        f"{ProtectedHoldingRegister._MAX_RATE} cmd / "
        f"{ProtectedHoldingRegister._WINDOW_S:.1f}s per IP  (A06)"
    )
    print(f"  FC Whitelist    ->  FC03 (read) + FC06 (write)  (A07)")
    print(f"  Forensic log    ->  logs/physicsguard.db")
    print(f"  Session ID      ->  {flogger.session_id}")
    print(f"  Telegram        ->  {telegram_status}")
    print("  Physics tick    ->  100 ms  |  Press Ctrl+C to stop.")
    print(sep)
 
 
if __name__ == "__main__":
    main()
