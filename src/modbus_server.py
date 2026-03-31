"""
modbus_server.py  —  Protected Modbus TCP Server
=================================================
Layer 1 + 4 + 5 + 6  |  PhysicsGuard ICS Security Gateway

4-PLC Defence-in-depth pipeline for every external write:
  A07: Function-code whitelist (FC03 read, FC06 write only)
  A06: DoS rate-limit per source IP (10 cmd/s sliding window)
  Read-only guard (HR[0], HR[10], HR[20], HR[31])
  Layer 4: ValidationEngine  — R001–R012 (all 12 rules)
  Layer 5: AlertManager      — Telegram for CRITICAL/EMERGENCY
  Layer 6: ForensicLogger    — non-blocking async SQLite
  Layer 1: Physics controllers — WaterTank, Temperature, Pressure, EmergencyShutdown

Register Map (4 PLCs × 10 registers):
  PLC_01 — Water Tank     HR[0-9]
    HR[0]  40001  Tank Level      READ-ONLY  [0-100 %]
    HR[1]  40002  Valve Position  READ-WRITE [0-100 %, ≤5 %/s]
    HR[2]  40003  Pump State      READ-WRITE [0=OFF, 1=ON]

  PLC_02 — Temperature    HR[10-19]
    HR[10] 40011  Temperature     READ-ONLY  [0-200 °C]
    HR[11] 40012  Heater Power    READ-WRITE [0-100 %]

  PLC_03 — Pressure       HR[20-29]
    HR[20] 40021  Pressure (PSI)  READ-ONLY
    HR[21] 40022  Relief Valve    READ-WRITE [0=CLOSED, 1=OPEN]

  PLC_04 — Emergency      HR[30-39]
    HR[30] 40031  E-Stop Active   READ-WRITE [0=NORMAL, 1=SHUTDOWN]
    HR[31] 40032  Master Pump     READ-ONLY

Rules wired (priority order):
  R004  priority=5   AuthRule         T0817  IP whitelist
  R007  priority=8   TopologyRule     T0888  lateral movement
  R001  priority=10  RangeRule        T0855  value range
  R008  priority=12  ReplayRule       T0856  command replay
  R005  priority=15  TimeRule         T0855  time window
  R002  priority=20  RateRule         T0855  rate-of-change
  R009  priority=22  OscillationRule  T0855  setpoint oscillation
  R006  priority=25  TemporalRule     T0855  slow-drip
  R003  priority=30  InterlockRule    T0813  pump dry-run interlock
  R011  priority=40  CorrelationRule  T0856  cross-sensor correlation
  R012  priority=45  CascadeRule      T0855  cross-PLC cascade failure
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
from src.pressure_controller    import PressureController
from src.emergency_shutdown     import EmergencyShutdownController
from src.validation_engine      import (
    ValidationEngine,
    build_water_tank_engine,
    load_rules_from_yaml,
)
from src.forensic_logger import ForensicLogger, get_logger
from src.alerting        import AlertManager

log = logging.getLogger(__name__)

_physics_thread_local = threading.local()

# C2 Fix: real client IP propagated via ContextVar through asyncio chain
_current_client_ip: contextvars.ContextVar[str] = contextvars.ContextVar(
    "_current_client_ip", default="unknown"
)

# A07: whitelisted Modbus function codes
_ALLOWED_FUNCTION_CODES: frozenset[int] = frozenset({0x03, 0x06})


# ── Request Handler (A07 + C2) ────────────────────────────────────────────────

class IPAwareRequestHandler(ServerRequestHandler):
    async def handle_request(self) -> None:
        # A07: function-code whitelist
        try:
            fc = getattr(self.request, "function_code", None)
            if fc is not None and fc not in _ALLOWED_FUNCTION_CODES:
                peername = (
                    self.transport.get_extra_info("peername", ("?", 0))
                    if self.transport else ("?", 0)
                )
                log.warning(
                    "A07 FC BLOCK | FC=0x%02X not whitelisted | client=%s",
                    fc, peername[0],
                )
                return
        except Exception:
            pass

        # C2: inject real client IP into ContextVar
        peername = None
        try:
            if self.transport is not None:
                peername = self.transport.get_extra_info("peername")
        except Exception:
            pass

        ip    = peername[0] if peername else "unknown"
        token = _current_client_ip.set(ip)
        try:
            await super().handle_request()
        finally:
            _current_client_ip.reset(token)


class IPAwareModbusTcpServer(ModbusTcpServer):
    def callback_new_connection(self) -> IPAwareRequestHandler:
        return IPAwareRequestHandler(
            self,
            self.trace_packet,
            self.trace_pdu,
            self.trace_connect,
        )


# ── Protected Holding Register — 4-PLC ───────────────────────────────────────

class ProtectedHoldingRegister(ModbusSequentialDataBlock):
    """
    40-register block covering all 4 PLCs.

    Write pipeline for every external command:
      1. Read-only guard
      2. A06: DoS rate-limit per source IP
      3. Layer 4: ValidationEngine (R001–R012) with merged global context
      4. Layer 5: AlertManager (Telegram on CRITICAL/EMERGENCY)
      5. Layer 6: ForensicLogger (async SQLite)
      6. Layer 1: Physics controller dispatch
    """

    _READ_ONLY_REGISTERS: frozenset[int] = frozenset({0, 10, 20, 31})
    _MAX_RATE:   int   = 10    # A06: commands per window
    _WINDOW_S:   float = 1.0   # A06: sliding window width

    # Address → PLC routing
    _TANK_REGS:     range = range(0,  10)
    _TEMP_REGS:     range = range(10, 20)
    _PRESS_REGS:    range = range(20, 30)
    _SHUTDOWN_REGS: range = range(30, 40)

    def __init__(
        self,
        tank:     WaterTankController,
        temp:     TemperatureController,
        press:    PressureController,
        shutdown: EmergencyShutdownController,
        engine:   ValidationEngine,
        flogger:  ForensicLogger,
    ) -> None:
        # 40 registers total (4 PLCs × 10)
        initial = [0] * 40
        initial[0]  = round(tank.get_state()["tank_level"])
        initial[10] = round(temp.get_state()["temperature"])
        initial[20] = round(press.get_state()["pressure"])
        initial[31] = press.get_state().get("pressure_int", 0)  # master pump proxy
        super().__init__(address=0, values=initial)

        self._tank     = tank
        self._temp     = temp
        self._press    = press
        self._shutdown = shutdown
        self._engine   = engine
        self._flogger  = flogger

        # A06: per-IP command history for sliding-window rate limit
        self._ip_history: dict[str, deque[float]] = {}

        # Layer 5: AlertManager (Telegram)
        self._alert_manager: AlertManager = AlertManager.from_env()

        log.info(
            "ProtectedHoldingRegister ready | "
            "tank=%.1f%% temp=%.1f°C pressure=%.1f psi | 12 rules active",
            tank.get_state()["tank_level"],
            temp.get_state()["temperature"],
            press.get_state()["pressure"],
        )

    # ── A06: DoS rate limiter ─────────────────────────────────────────────────

    def _is_rate_limited(self, ip: str) -> bool:
        now    = time.monotonic()
        window = self._ip_history.setdefault(ip, deque())
        while window and now - window[0] > self._WINDOW_S:
            window.popleft()
        if len(window) >= self._MAX_RATE:
            return True
        window.append(now)
        return False

    # ── Build merged global context ───────────────────────────────────────────

    def _build_global_context(self, source_ip: str, target_plc: str) -> dict:
        """
        Merge state from all 4 PLCs into a single context dict.

        This is what enables R012 CascadeRule and R011 CorrelationRule to
        read cross-PLC state (e.g., tank_level when validating a heater
        command). Every rule sees the full plant state snapshot.
        """
        ctx = {}
        ctx.update(self._tank.get_state())          # tank_level, valve_position, pump_running, last_cmd_time
        ctx.update(self._temp.get_state())           # temperature, heater_power, is_emergency
        ctx.update(self._press.get_state())          # pressure, relief_valve
        ctx.update(self._shutdown.get_state())       # emergency_stop_active, master_pump_on
        ctx["source_ip"]    = source_ip
        ctx["target_plc_id"] = target_plc
        return ctx

    # ── Main write intercept ──────────────────────────────────────────────────

    def setValues(self, address: int, values: list) -> None:
        # Physics loop: trusted — bypass all guards
        if getattr(_physics_thread_local, "is_physics_loop", False):
            super().setValues(address, values)
            return

        # Read-only guard
        if address in self._READ_ONLY_REGISTERS:
            log.warning("BLOCKED READ-ONLY | reg=%d | external write rejected", address)
            return

        if not values:
            return

        value     = float(values[0])
        source_ip = _current_client_ip.get()

        # A06: DoS rate-limit
        if self._is_rate_limited(source_ip):
            log.warning(
                "A06 DOS BLOCK | ip=%s | exceeded %d cmd/%.1fs window",
                source_ip, self._MAX_RATE, self._WINDOW_S,
            )
            return

        # Route to the target PLC
        if address in self._TANK_REGS:
            target_plc = "PLC_01"
        elif address in self._TEMP_REGS:
            target_plc = "PLC_02"
        elif address in self._PRESS_REGS:
            target_plc = "PLC_03"
        elif address in self._SHUTDOWN_REGS:
            target_plc = "PLC_04"
        else:
            log.warning("BLOCKED UNKNOWN | reg=%d val=%s | not in register map", address, values)
            return

        # Build merged global context (enables cross-PLC rules)
        context = self._build_global_context(source_ip, target_plc)

        # H4 fix: inject cmd_timestamp for R008 ReplayRule
        t_start = time.monotonic()
        context["cmd_timestamp"] = t_start

        # Layer 4: ValidationEngine — all 12 rules
        engine_result = self._engine.validate(
            address=address, value=value, context=context
        )
        latency_us = round((time.monotonic() - t_start) * 1_000_000, 2)

        # Layer 6: ForensicLogger — non-blocking async write
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
            # Layer 5: Telegram alert for CRITICAL/EMERGENCY
            self._alert_manager.send(engine_result)
            return  # register left unchanged

        # Layer 1: dispatch to the correct physics controller
        self._dispatch_physics(address, value, values)

    def _dispatch_physics(self, address: int, value: float, values: list) -> None:
        """Route validated write to the appropriate physics controller."""
        if address == 1:                    # PLC_01: valve position
            phys = self._tank.set_valve_position(value)
            if phys["allowed"]:
                super().setValues(1, [round(value)])
            else:
                log.warning("PHYSICS BLOCK | reg=1 val=%.2f | %s", value, phys.get("reason", ""))

        elif address == 2:                  # PLC_01: pump state
            phys = self._tank.set_pump_state(bool(values[0]))
            if phys["allowed"]:
                super().setValues(2, [int(bool(values[0]))])
            else:
                log.warning("PHYSICS BLOCK | reg=2 val=%.2f | %s", value, phys.get("reason", ""))

        elif address == 11:                 # PLC_02: heater power
            phys = self._temp.set_heater_power(value)
            if phys["allowed"]:
                super().setValues(11, [round(value)])
            else:
                log.warning("PHYSICS BLOCK | reg=11 val=%.2f | %s", value, phys.get("reason", ""))

        elif address == 21:                 # PLC_03: relief valve
            phys = self._press.set_relief_valve(bool(values[0]))
            if phys["allowed"]:
                super().setValues(21, [int(bool(values[0]))])
            else:
                log.warning("PHYSICS BLOCK | reg=21 val=%.2f | %s", value, phys.get("reason", ""))

        elif address == 30:                 # PLC_04: e-stop
            self._shutdown.set_estop(bool(values[0]))
            super().setValues(30, [int(bool(values[0]))])

        else:
            log.warning("BLOCKED UNKNOWN | reg=%d | no physics handler", address)


# ── Factory ───────────────────────────────────────────────────────────────────

def build_context(
    tank:     WaterTankController,
    temp:     TemperatureController,
    press:    PressureController,
    shutdown: EmergencyShutdownController,
    engine:   ValidationEngine,
    flogger:  ForensicLogger,
):
    hr_block = ProtectedHoldingRegister(tank, temp, press, shutdown, engine, flogger)
    slave    = ModbusDeviceContext(hr=hr_block)
    context  = ModbusServerContext(devices=slave, single=True)
    return hr_block, context


# ── Physics loop ──────────────────────────────────────────────────────────────

def physics_loop(
    tank:       WaterTankController,
    temp:       TemperatureController,
    press:      PressureController,
    shutdown:   EmergencyShutdownController,
    hr_block:   ProtectedHoldingRegister,
    stop_event: threading.Event,
    tick_s:     float = 0.1,
) -> None:
    """
    Trusted physics update loop — daemon thread.
    D14: entire tick body in try/except; thread never dies silently.
    """
    _physics_thread_local.is_physics_loop = True
    log.info("Physics loop started (tick=%.0f ms)", tick_s * 1000)

    while not stop_event.is_set():
        try:
            now = time.monotonic()

            # PLC_01 — water tank
            t_state = tank.update_physics(now=now)
            hr_block.setValues(0,  [t_state["tank_level_int"]])
            hr_block.setValues(1,  [t_state["valve_int"]])
            hr_block.setValues(2,  [t_state["pump_int"]])

            # PLC_02 — temperature controller
            h_state = temp.update_physics(now=now)
            hr_block.setValues(10, [h_state["temp_int"]])
            # HR[11] (heater) is operator-commanded — not overwritten by physics

            # PLC_03 — pressure monitor
            p_state = press.update_physics(
                tank_level=t_state["tank_level"], now=now
            )
            hr_block.setValues(20, [p_state["pressure_int"]])
            # HR[21] (relief valve) is operator-commanded

            # PLC_04 — emergency shutdown
            s_state = shutdown.get_state()
            hr_block.setValues(31, [s_state["master_pump_int"]])

        except Exception:
            log.exception("Physics loop error — registers may be stale; retrying")

        time.sleep(tick_s)

    log.info("Physics loop stopped")


# ── Validation Engine factory (all 12 rules) ─────────────────────────────────

def _build_engine(yaml_path: str) -> ValidationEngine:
    """
    Load the validation engine, wiring all rules R001–R012.

    R001–R005 come from rules.yaml.
    R006–R009 are wired in code (stateful / graph objects).
    R011–R012 are wired in code (cross-PLC novel contributions).
    """
    if os.path.exists(yaml_path):
        log.info("Loading rules from %s", yaml_path)
        engine = load_rules_from_yaml(yaml_path)
        log.info("YAML engine loaded — %d rules", len(engine.get_rules()))
    else:
        log.warning("rules.yaml not found at %s — using hardcoded defaults", yaml_path)
        engine = build_water_tank_engine()

    # R006 — TemporalRule (Novel Contribution #3: slow-drip detector)
    from src.rules.temporal_rule import TemporalRule
    _try_register(engine, TemporalRule(
        address=1, window_s=300.0, max_cumulative_delta=15.0, label="%",
    ))

    # R007 — TopologyRule (Novel Contribution #4: lateral movement)
    from src.rules.topology_rule import TopologyRule
    from src.plant_topology import build_water_tank_topology
    _try_register(engine, TopologyRule(
        topology=build_water_tank_topology(), default_target="PLC_01",
    ))

    # R008 — ReplayRule (command replay detector)
    from src.rules.replay_rule import ReplayRule
    _try_register(engine, ReplayRule(address=None, replay_window_s=5.0))

    # R009 — OscillationRule (setpoint oscillation detector)
    from src.rules.oscillation_rule import OscillationRule
    _try_register(engine, OscillationRule(
        address=1, window_s=120.0, max_reversals=4, min_delta_pct=10.0,
    ))

    # R011 — CorrelationRule (cross-sensor false-data-injection detector)
    from src.rules.correlation_rule import CorrelationRule
    _try_register(engine, CorrelationRule(min_expected_rise=0.5))

    # R012 — CascadeRule (cross-PLC cascade failure detector)
    from src.rules.cascade_rule import CascadeRule
    _try_register(engine, CascadeRule(
        cascade_level_threshold=5.0,
        heater_threshold=50.0,
        temp_danger_threshold=150.0,
    ))

    # Novel Contribution #1: ConsequenceEngine (forward damage prediction)
    from src.consequence_engine import ConsequenceEngine
    engine.set_consequence_engine(ConsequenceEngine())

    log.info("Validation engine ready — %d rules wired", len(engine.get_rules()))
    return engine


def _try_register(engine: ValidationEngine, rule) -> None:
    """Register a rule, skipping if already registered (idempotent)."""
    try:
        engine.register_rule(rule)
    except ValueError as exc:
        if "already registered" in str(exc):
            log.debug("Rule %s already registered — skipping", rule.rule_id)
        else:
            raise


# ── Banner ────────────────────────────────────────────────────────────────────

def _print_banner(
    engine:   ValidationEngine,
    tank:     WaterTankController,
    temp:     TemperatureController,
    press:    PressureController,
    flogger:  ForensicLogger,
    host:     str,
    port:     int,
) -> None:
    rules      = engine.get_rules()
    t          = tank.get_state()
    h          = temp.get_state()
    p          = press.get_state()
    bot_token  = os.environ.get("PHYSICSGUARD_BOT_TOKEN", "").strip()
    chat_id    = os.environ.get("PHYSICSGUARD_CHAT_ID",   "").strip()
    telegram   = f"LIVE (chat_id={chat_id})" if (bot_token and chat_id) else "DISABLED"
    sep        = "=" * 66

    print(sep)
    print("  PhysicsGuard  |  ICS Security Gateway  |  4-PLC Full Stack")
    print(f"  Modbus TCP  →  {host}:{port}")
    print()
    print("  PLC_01 — Water Tank:")
    print(f"    Tank Level : {t['tank_level']:.1f}%  |  Valve: {t['valve_position']:.1f}%  |  Pump: {'ON' if t['pump_running'] else 'OFF'}")
    print("  PLC_02 — Temperature Controller:")
    print(f"    Temperature: {h['temperature']:.1f}°C  |  Heater: {h['heater_power']:.1f}%")
    print("  PLC_03 — Pressure Monitor:")
    print(f"    Pressure: {p['pressure']:.1f} PSI")
    print("  PLC_04 — Emergency Shutdown: NORMAL")
    print()
    print("  Register Map:")
    print("    HR[0]  TankLevel    READ-ONLY   HR[1]  ValvePos  READ-WRITE")
    print("    HR[2]  PumpState    READ-WRITE  HR[10] Temp      READ-ONLY")
    print("    HR[11] HeaterPower  READ-WRITE  HR[20] Pressure  READ-ONLY")
    print("    HR[21] ReliefValve  READ-WRITE  HR[30] EStop     READ-WRITE")
    print("    HR[31] MasterPump   READ-ONLY")
    print()
    print(f"  Validation Engine: {len(rules)} rules")
    for r in sorted(rules, key=lambda x: x["priority"]):
        status = "ON " if r["enabled"] else "OFF"
        print(f"    [{status}] {r['rule_id']:<5} priority={r['priority']:<3} "
              f"{r['severity']:<10} {r['mitre_tag']}")
    print()
    print(f"  DoS Rate Limit : {ProtectedHoldingRegister._MAX_RATE} cmd/{ProtectedHoldingRegister._WINDOW_S:.1f}s per IP  (A06)")
    print(f"  FC Whitelist   : FC03 (read) + FC06 (write)  (A07)")
    print(f"  Forensic log   : logs/physicsguard.db")
    print(f"  Session ID     : {flogger.session_id}")
    print(f"  Telegram       : {telegram}")
    print("  Press Ctrl+C to stop.")
    print(sep)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="PhysicsGuard Modbus TCP Server — 4-PLC")
    parser.add_argument(
        "--initial-level", type=float, default=None, metavar="PCT",
        help="Override tank starting level [0-100%] (default: 50%)",
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
            parser.error(f"--initial-level must be in [0, 100], got {args.initial_level}")
        tank_kwargs["INITIAL_LEVEL"] = args.initial_level
        log.info("CLI override: INITIAL_LEVEL=%.1f%%", args.initial_level)

    tank     = WaterTankController(**tank_kwargs)
    temp     = TemperatureController()
    press    = PressureController()
    shutdown = EmergencyShutdownController()

    # ── Build ValidationEngine (all 12 rules) ─────────────────────────────────
    _yaml_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config", "rules.yaml",
    )
    engine = _build_engine(_yaml_path)

    # ── Build server ──────────────────────────────────────────────────────────
    flogger           = get_logger("logs/physicsguard.db")
    hr_block, context = build_context(tank, temp, press, shutdown, engine, flogger)

    stop_event = threading.Event()
    threading.Thread(
        target=physics_loop,
        args=(tank, temp, press, shutdown, hr_block, stop_event),
        daemon=True,
        name="physics-loop",
    ).start()

    import asyncio
    _bind_host: str = os.environ.get("MODBUS_BIND_HOST", "0.0.0.0")
    _bind_port: int = int(os.environ.get("MODBUS_BIND_PORT", "5020"))

    _print_banner(engine, tank, temp, press, flogger, _bind_host, _bind_port)

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


if __name__ == "__main__":
    main()
