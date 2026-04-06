"""
temperature_controller.py — PLC #2 Thermal Process Simulation
Layer 1 | PhysicsGuard ICS Security Gateway

Simulates a heating element with passive cooling.
Register Map:
  HR[0] 40011 Temperature Reading — READ-ONLY (°C)
  HR[1] 40012 Heater Power        — READ-WRITE (0–100%)
"""
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

@dataclass(eq=False)
class TemperatureController:
    # Physical Constraints
    SENSOR_MIN: float = 0.0       # °C
    SENSOR_MAX: float = 200.0     # °C
    EMERGENCY_TEMP: float = 180.0 # °C — triggers hardware-level shutdown
    HEATING_RATE: float = 5.0     # Max °C/min increase at 100% power
    COOLING_RATE: float = 2.0     # Passive °C/min decrease
    AMBIENT_TEMP: float = 25.0    # Baseline temperature
    
    # Security/Safety Constraints
    MAX_HEATER_DELTA: float = 20.0 # Max % change per second (anti-thermal shock)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._temperature: float = self.AMBIENT_TEMP
        self._heater_power: float = 0.0
        self._last_physics_time: float = time.monotonic()
        self._last_cmd_time: float = 0.0
        self._is_emergency_shutdown: bool = False

    def get_state(self) -> dict[str, Any]:
        """Thread-safe snapshot for the ValidationEngine."""
        with self._lock:
            return {
                "temperature": self._temperature,
                "heater_power": self._heater_power,
                "is_emergency": self._is_emergency_shutdown,
                "last_cmd_time": self._last_cmd_time,
                "temp_int": round(self._temperature),
                "heater_int": round(self._heater_power)
            }

    def update_physics(self, now: float | None = None) -> dict[str, Any]:
        """
        Calculates thermal delta based on heater power and passive cooling.
        Called by the modbus_server physics loop.
        """
        now = now or time.monotonic()
        with self._lock:
            dt = min(now - self._last_physics_time, 1.0) # Cap dt at 1s for stability
            self._last_physics_time = now

            if dt <= 0:
                return self._get_snapshot()

            # Calculate net thermal change per second
            heat_gain = (self._heater_power / 100.0) * (self.HEATING_RATE / 60.0)
            cool_loss = (self.COOLING_RATE / 60.0)
            net_change = (heat_gain - cool_loss) * dt

            self._temperature = max(self.SENSOR_MIN, min(self.SENSOR_MAX, self._temperature + net_change))

            # Hardware-level Safety Interlock (L1 Defence)
            if self._temperature >= self.EMERGENCY_TEMP:
                if not self._is_emergency_shutdown:
                    log.critical("THERMAL OVERHEAT | Temp=%.1f°C | Safety Interlock Engaged", self._temperature)
                self._is_emergency_shutdown = True
                self._heater_power = 0.0 # Force heater OFF

            return self._get_snapshot()

    def set_heater_power(self, value: float, now: float | None = None) -> dict:
        """
        Validates and applies heater power setpoints.
        Includes Layer 1 rate-of-change protection.
        """
        now = now or time.monotonic()
        with self._lock:
            if self._is_emergency_shutdown:
                return {"allowed": False, "reason": "Hardware safety lockout active"}

            if not (0.0 <= value <= 100.0):
                return {"allowed": False, "reason": f"Power {value}% outside [0, 100]"}

            # Local Physics Guard: Thermal Shock Protection
            if self._last_cmd_time > 0:
                dt = now - self._last_cmd_time
                delta = abs(value - self._heater_power)
                if dt > 0 and (delta / dt) > self.MAX_HEATER_DELTA:
                    return {"allowed": False, "reason": "Heater ramp rate exceeds safety limits"}

            self._heater_power = value
            self._last_cmd_time = now
            return {"allowed": True, "reason": "Heater power updated"}

    def _get_snapshot(self) -> dict[str, Any]:
        return {
            "temperature":    self._temperature,
            "heater_power":   self._heater_power,
            "is_emergency":   self._is_emergency_shutdown,
            "last_cmd_time":  self._last_cmd_time,
            "temp_int":       round(self._temperature),
            "heater_int":     round(self._heater_power),
        }
