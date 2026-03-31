"""
emergency_shutdown.py  —  PLC #4 Emergency Shutdown System
==========================================================
Layer 1  |  PhysicsGuard ICS Security Gateway

Register map:
  HR[30] 40031 E-Stop Active      — READ-WRITE (0=NORMAL, 1=SHUTDOWN)
  HR[31] 40032 Master Pump Status — READ-ONLY

Bug fixes applied:
  - set_estop() called self.get_state() while holding self._lock
    → deadlock on the second lock acquisition. Fixed by using _snapshot()
    which builds the dict directly without re-acquiring the lock.
"""
import logging
import threading
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(eq=False)
class EmergencyShutdownController:

    def __post_init__(self) -> None:
        self._lock           = threading.Lock()
        self._estop_active   = False
        self._master_pump_on = True

    # ── Public API ────────────────────────────────────────────────────────────

    def get_state(self) -> dict:
        """Thread-safe snapshot — acquires lock."""
        with self._lock:
            return self._snapshot()

    def set_estop(self, state: bool) -> dict:
        """
        Activate or deactivate the emergency stop.

        Turning ON: forces master_pump_on=False and logs a CRITICAL warning.
        Turning OFF: restores master_pump_on=True (operator reset).
        """
        with self._lock:
            self._estop_active = state
            if state:
                self._master_pump_on = False
                log.critical(
                    "!!! EMERGENCY SHUTDOWN ACTIVATED | "
                    "all pump outputs forced OFF !!!"
                )
            else:
                self._master_pump_on = True
                log.warning("Emergency shutdown DEACTIVATED — system reset by operator")

            # Return snapshot without re-acquiring lock
            return self._snapshot()

    # ── Internal helper (call only while holding _lock) ───────────────────────

    def _snapshot(self) -> dict:
        """
        Build state dict WITHOUT acquiring the lock.
        Must only be called from within a `with self._lock:` block.
        """
        return {
            "emergency_stop_active": self._estop_active,
            "master_pump_on":        self._master_pump_on,
            "estop_int":             1 if self._estop_active   else 0,
            "master_pump_int":       1 if self._master_pump_on else 0,
        }
