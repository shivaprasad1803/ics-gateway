"""
pressure_controller.py  —  PLC #3 Pressure Monitoring Loop
==========================================================
Layer 1  |  PhysicsGuard ICS Security Gateway

Register map:
  HR[20] 40021 Pressure (PSI)  — READ-ONLY
  HR[21] 40022 Relief Valve    — READ-WRITE (0=CLOSED, 1=OPEN)

Bug fixes applied:
  - update_physics() called self.get_state() while holding self._lock
    → deadlock on the second lock acquisition. Fixed by using _snapshot()
    which builds the dict directly without acquiring the lock.
  - set_relief_valve() same pattern fixed the same way.
  - Added master_pump_int key to get_state() so modbus_server.py
    banner lookup works without KeyError.
"""
import logging
import threading
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass(eq=False)
class PressureController:
    INITIAL_PRESSURE: float = 45.0
    MAX_PRESSURE:     float = 300.0

    def __post_init__(self) -> None:
        self._lock         = threading.Lock()
        self._pressure     = self.INITIAL_PRESSURE
        self._relief_valve = False
        self._last_time    = time.monotonic()

    # ── Public API ────────────────────────────────────────────────────────────

    def get_state(self) -> dict:
        """Thread-safe snapshot — acquires lock."""
        with self._lock:
            return self._snapshot()

    def update_physics(self, tank_level: float, now: float | None = None) -> dict:
        """
        Advance pressure physics one tick.
        Called by the physics loop (trusted, no validation).
        Returns the updated state snapshot.
        """
        if now is None:
            now = time.monotonic()

        with self._lock:
            dt = now - self._last_time
            self._last_time = now
            dt = max(0.0, min(dt, 1.0))   # clamp to 1 s for stability

            # Pressure tracks tank level when relief valve is closed.
            # Relief valve open → bleed pressure back to ambient.
            if not self._relief_valve:
                target_pressure = 45.0 + (tank_level * 2.0)   # 45–245 PSI
            else:
                target_pressure = 45.0

            # Smooth exponential approach
            self._pressure += (target_pressure - self._pressure) * min(dt * 0.5, 1.0)
            self._pressure  = max(0.0, min(self.MAX_PRESSURE, self._pressure))

            # Return snapshot without re-acquiring the lock
            return self._snapshot()

    def set_relief_valve(self, state: bool) -> dict:
        """Open or close the relief valve. Always allowed by physics layer."""
        with self._lock:
            self._relief_valve = state
            log.info(
                "PressureController: relief valve %s",
                "OPEN" if state else "CLOSED",
            )
            # Build return dict without re-acquiring lock
            return {"allowed": True, "reason": f"Relief valve {'OPEN' if state else 'CLOSED'}"}

    # ── Internal helper (call only while holding _lock) ───────────────────────

    def _snapshot(self) -> dict:
        """
        Build state dict WITHOUT acquiring the lock.
        Must only be called from within a `with self._lock:` block.
        """
        return {
            "pressure":        self._pressure,
            "relief_valve":    self._relief_valve,
            "pressure_int":    round(self._pressure),
            # master_pump_int is read by modbus_server.py banner + physics loop
            # for HR[31]. Pressure controller proxies this as 1 (pump assumed ON)
            # unless pressure is dangerously high, in which case the EStop PLC
            # would take over. Safe default = 1.
            "master_pump_int": 1,
        }
