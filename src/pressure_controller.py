"""
pressure_controller.py  —  PLC #3 Pressure Monitoring Loop
==========================================================
Layer 1  |  PhysicsGuard ICS Security Gateway

Register map:
  HR[20] 40021 Pressure (PSI)  — READ-ONLY
  HR[21] 40022 Relief Valve    — READ-WRITE (0=CLOSED, 1=OPEN)
"""
import logging
import threading
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)

@dataclass(eq=False)
class PressureController:
    INITIAL_PRESSURE: float = 45.0
    MAX_PRESSURE: float = 300.0
    
    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._pressure = self.INITIAL_PRESSURE
        self._relief_valve = False
        self._last_time = time.monotonic()

    def get_state(self) -> dict:
        with self._lock:
            return {
                "pressure": self._pressure,
                "relief_valve": self._relief_valve,
                "pressure_int": round(self._pressure)
            }

    def update_physics(self, tank_level: float, now: float | None = None) -> dict:
        if now is None:
            now = time.monotonic()
        with self._lock:
            dt = now - self._last_time
            self._last_time = now
            
            # Simple physics: pressure increases with tank level if relief is closed
            if not self._relief_valve:
                target_pressure = 45.0 + (tank_level * 2.0) # 45 to 245 PSI
            else:
                target_pressure = 45.0 # Relief valve drops pressure to ambient
            
            # Smooth transition
            self._pressure += (target_pressure - self._pressure) * min(dt * 0.5, 1.0)
            return self.get_state()

    def set_relief_valve(self, state: bool) -> dict:
        with self._lock:
            self._relief_valve = state
            return {"allowed": True, "reason": f"Relief valve {'OPEN' if state else 'CLOSED'}"}
