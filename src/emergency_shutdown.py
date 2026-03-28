"""
emergency_shutdown.py  —  PLC #4 Emergency Shutdown System
==========================================================
Layer 1  |  PhysicsGuard ICS Security Gateway

Register map:
  HR[30] 40031 E-Stop Active      — READ-WRITE (0=NORMAL, 1=SHUTDOWN)
  HR[31] 40032 Master Pump Status — READ-ONLY
"""
import logging
import threading
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass(eq=False)
class EmergencyShutdownController:
    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._estop_active = False
        self._master_pump_on = True

    def get_state(self) -> dict:
        with self._lock:
            return {
                "emergency_stop_active": self._estop_active,
                "master_pump_on": self._master_pump_on,
                "estop_int": 1 if self._estop_active else 0,
                "master_pump_int": 1 if self._master_pump_on else 0
            }

    def set_estop(self, state: bool) -> dict:
        with self._lock:
            self._estop_active = state
            if state:
                self._master_pump_on = False # Force shutdown
                log.warning("!!! EMERGENCY SHUTDOWN ACTIVATED !!!")
            else:
                self._master_pump_on = True
            return self.get_state()
