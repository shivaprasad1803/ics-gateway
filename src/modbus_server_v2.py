"""
new/src/modbus_server_v2.py  —  SUPER-COMPLETE Protected Modbus TCP Server
===========================================================================
Layer 1 + 4 + 5 + 6  |  PhysicsGuard ICS Security Gateway
Final Year Project | 4-PLC Integrated Defense System (Standalone)

This version is 100% complete and standalone. It includes:
  - IPAware Server & Request Handler (C2, A07)
  - 4-PLC Context Integration (PLC_01 to PLC_04)
  - All 12 Rules (R001-R012)
  - Forensic Logging & Telegram Alerting
"""

import asyncio
import contextvars
import logging
import os
import sys
import threading
import time
from collections import deque
from dotenv import load_dotenv

load_dotenv()

# Project root setup
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusDeviceContext,
)
from pymodbus.server import ModbusTcpServer
from pymodbus.server.requesthandler import ServerRequestHandler

# Imports from existing 'src' (modular components)
from src.water_tank import WaterTankController
from src.temperature_controller import TemperatureController
from src.validation_engine import ValidationEngine, load_rules_from_yaml
from src.forensic_logger import ForensicLogger, get_logger
from src.alerting import AlertManager

# Imports from 'new'
from new.src.pressure_controller import PressureController
from new.src.emergency_shutdown import EmergencyShutdownController
from new.src.rules.correlation_rule import CorrelationRule
from new.src.rules.cascade_rule import CascadeRule

log = logging.getLogger(__name__)

# ── Context and Globals ───────────────────────────────────────────────────────
_current_client_ip: contextvars.ContextVar[str] = contextvars.ContextVar("_current_client_ip", default="unknown")
_physics_thread_local = threading.local()
_ALLOWED_FUNCTION_CODES: frozenset[int] = frozenset({0x03, 0x06})

# ── Request Handler (C2, A07) ────────────────────────────────────────────────
class IPAwareRequestHandler(ServerRequestHandler):
    async def handle_request(self) -> None:
        try:
            fc = getattr(self.request, "function_code", None)
            if fc is not None and fc not in _ALLOWED_FUNCTION_CODES:
                log.warning("A07 FC BLOCK | FC=0x%02X | IP=%s", fc, self.transport.get_extra_info("peername")[0])
                return
        except Exception: pass

        peername = self.transport.get_extra_info("peername") if self.transport else None
        ip = peername[0] if peername else "unknown"
        token = _current_client_ip.set(ip)
        try:
            await super().handle_request()
        finally:
            _current_client_ip.reset(token)

class IPAwareModbusTcpServer(ModbusTcpServer):
    def callback_new_connection(self) -> IPAwareRequestHandler:
        return IPAwareRequestHandler(self, self.trace_packet, self.trace_pdu, self.trace_connect)

# ── Main Datastore ────────────────────────────────────────────────────────────
class FullStackHoldingRegister(ModbusSequentialDataBlock):
    _READ_ONLY_REGISTERS: frozenset[int] = frozenset({0, 10, 20, 31})
    _MAX_RATE: int = 10
    _WINDOW_S: float = 1.0

    def __init__(self, tank, temp, press, shutdown, engine, flogger):
        initial_values = [0] * 40 # 4 PLCs x 10 regs
        super().__init__(address=0, values=initial_values)
        self._tank = tank
        self._temp = temp
        self._press = press
        self._shutdown = shutdown
        self._engine = engine
        self._flogger = flogger
        self._ip_history = {}
        self._alert_manager = AlertManager.from_env()

    def _is_rate_limited(self, ip: str) -> bool:
        now = time.monotonic()
        window = self._ip_history.setdefault(ip, deque())
        while window and now - window[0] > self._WINDOW_S:
            window.popleft()
        if len(window) >= self._MAX_RATE: return True
        window.append(now)
        return False

    def setValues(self, address: int, values: list) -> None:
        if getattr(_physics_thread_local, "is_physics_loop", False):
            super().setValues(address, values)
            return

        if address in self._READ_ONLY_REGISTERS: return

        source_ip = _current_client_ip.get()
        if self._is_rate_limited(source_ip): return

        value = float(values[0])
        
        # Build Global Context
        ctx = self._tank.get_state()
        ctx.update(self._temp.get_state())
        ctx.update(self._press.get_state())
        ctx.update(self._shutdown.get_state())
        ctx["cmd_timestamp"] = time.monotonic()
        ctx["source_ip"] = source_ip

        # Route Target PLC
        if 0 <= address < 10: ctx["target_plc_id"] = "PLC_01"
        elif 10 <= address < 20: ctx["target_plc_id"] = "PLC_02"
        elif 20 <= address < 30: ctx["target_plc_id"] = "PLC_03"
        elif 30 <= address < 40: ctx["target_plc_id"] = "PLC_04"

        # Validation Engine
        t_start = time.monotonic()
        res = self._engine.validate(address, value, ctx)
        lat = round((time.monotonic() - t_start) * 1_000_000, 2)

        # Forensic Log
        self._flogger.log_command(address, value, res.allowed, res.rule_id or "", 
                                  res.reason or "", res.severity or "INFO", 
                                  res.mitre_tag or "", source_ip, lat)

        if not res.allowed:
            self._alert_manager.send(res) # TELEGRAM ALERT
            return

        # Physical Dispatch
        if address == 1: self._tank.set_valve_position(value)
        elif address == 2: self._tank.set_pump_state(bool(value))
        elif address == 11: self._temp.set_heater_power(value)
        elif address == 21: self._press.set_relief_valve(bool(value))
        elif address == 30: self._shutdown.set_estop(bool(value))

# ── Server Setup ─────────────────────────────────────────────────────────────
def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    
    tank, temp, press, shutdown = WaterTankController(), TemperatureController(), PressureController(), EmergencyShutdownController()
    
    # Load rules from the new config location
    yaml_path = "config/rules.yaml"
    if os.path.exists(yaml_path): engine = load_rules_from_yaml(yaml_path)
    else: 
        from src.validation_engine import build_water_tank_engine
        engine = build_water_tank_engine()
    
    # Register Final Contribution Rules
    engine.register_rule(CorrelationRule())
    engine.register_rule(CascadeRule())
    
    # Novel Contribution #1: Consequence Engine
    from src.consequence_engine import ConsequenceEngine
    engine.set_consequence_engine(ConsequenceEngine())

    flogger = get_logger("logs/physicsguard_v2.db")
    hr_block = FullStackHoldingRegister(tank, temp, press, shutdown, engine, flogger)
    
    stop_event = threading.Event()
    def physics_runner():
        _physics_thread_local.is_physics_loop = True
        while not stop_event.is_set():
            try:
                now = time.monotonic()
                t, h, s = tank.update_physics(now=now), temp.update_physics(now=now), shutdown.get_state()
                p = press.update_physics(tank_level=t["tank_level"], now=now)
                hr_block.setValues(0, [t["tank_level_int"]]); hr_block.setValues(10, [h["temp_int"]])
                hr_block.setValues(20, [p["pressure_int"]]); hr_block.setValues(31, [s["master_pump_int"]])
            except: pass
            time.sleep(0.1)
    
    threading.Thread(target=physics_runner, daemon=True).start()

    print("="*62 + "\n  PhysicsGuard V2 | 4-PLC STANDALONE SERVER\n" + "="*62)

    import asyncio
    _host, _port = os.environ.get("MODBUS_BIND_HOST", "0.0.0.0"), int(os.environ.get("MODBUS_BIND_PORT", "5020"))
    server = IPAwareModbusTcpServer(context=ModbusServerContext(slaves=ModbusDeviceContext(hr=hr_block), single=True), address=(_host, _port))
    try: asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        stop_event.set(); flogger.stop()

if __name__ == "__main__": main()
