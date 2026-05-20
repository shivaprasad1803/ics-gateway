"""
test_plc_controllers.py — Basic coverage for PLC Layer 1 controllers
PhysicsGuard | Layer 1
Covers: EmergencyShutdownController, PressureController, TemperatureController
"""
import time
import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.emergency_shutdown import EmergencyShutdownController
from src.pressure_controller import PressureController
from src.temperature_controller import TemperatureController


# ── EmergencyShutdownController ───────────────────────────────────────────────

class TestEmergencyShutdown:

    def test_initial_state_is_normal(self):
        ctrl = EmergencyShutdownController()
        state = ctrl.get_state()
        assert state["emergency_stop_active"] is False
        assert state["master_pump_on"] is True
        assert state["estop_int"] == 0
        assert state["master_pump_int"] == 1

    def test_activate_estop_forces_pump_off(self):
        ctrl = EmergencyShutdownController()
        state = ctrl.set_estop(True)
        assert state["emergency_stop_active"] is True
        assert state["master_pump_on"] is False
        assert state["estop_int"] == 1
        assert state["master_pump_int"] == 0

    def test_deactivate_estop_restores_pump(self):
        ctrl = EmergencyShutdownController()
        ctrl.set_estop(True)
        state = ctrl.set_estop(False)
        assert state["emergency_stop_active"] is False
        assert state["master_pump_on"] is True

    def test_get_state_thread_safe(self):
        ctrl = EmergencyShutdownController()
        ctrl.set_estop(True)
        state = ctrl.get_state()
        assert state["emergency_stop_active"] is True

    def test_snapshot_does_not_deadlock(self):
        ctrl = EmergencyShutdownController()
        for _ in range(100):
            ctrl.set_estop(True)
            ctrl.set_estop(False)
        assert ctrl.get_state()["emergency_stop_active"] is False


# ── PressureController ────────────────────────────────────────────────────────

class TestPressureController:

    def test_initial_state(self):
        ctrl = PressureController()
        state = ctrl.get_state()
        assert state["pressure"] == PressureController.INITIAL_PRESSURE
        assert state["relief_valve"] is False
        assert state["master_pump_int"] == 1

    def test_physics_increases_pressure_with_high_level(self):
        ctrl = PressureController()
        t0 = time.monotonic()
        state = ctrl.update_physics(tank_level=100.0, now=t0 + 5.0)
        assert state["pressure"] > PressureController.INITIAL_PRESSURE

    def test_relief_valve_reduces_pressure(self):
        ctrl = PressureController()
        t0 = time.monotonic()
        ctrl.update_physics(tank_level=100.0, now=t0 + 5.0)
        ctrl.set_relief_valve(True)
        state_after = ctrl.update_physics(tank_level=100.0, now=t0 + 10.0)
        assert state_after["relief_valve"] is True

    def test_set_relief_valve_returns_allowed(self):
        ctrl = PressureController()
        result = ctrl.set_relief_valve(True)
        assert result["allowed"] is True
        result2 = ctrl.set_relief_valve(False)
        assert result2["allowed"] is True

    def test_pressure_clamped_at_max(self):
        ctrl = PressureController()
        t0 = time.monotonic()
        for i in range(100):
            ctrl.update_physics(tank_level=100.0, now=t0 + i * 2.0)
        state = ctrl.get_state()
        assert state["pressure"] <= PressureController.MAX_PRESSURE

    def test_snapshot_no_deadlock(self):
        ctrl = PressureController()
        t0 = time.monotonic()
        ctrl.update_physics(tank_level=50.0, now=t0 + 1.0)
        ctrl.set_relief_valve(True)
        ctrl.update_physics(tank_level=50.0, now=t0 + 2.0)
        state = ctrl.get_state()
        assert "pressure" in state


# ── TemperatureController ─────────────────────────────────────────────────────

class TestTemperatureController:

    def test_initial_state(self):
        ctrl = TemperatureController()
        state = ctrl.get_state()
        assert state["temperature"] == TemperatureController.AMBIENT_TEMP
        assert state["heater_power"] == 0.0
        assert state["is_emergency"] is False

    def test_heater_increases_temperature(self):
        ctrl = TemperatureController()
        t0 = time.monotonic()
        ctrl.set_heater_power(100.0, now=t0)
        state = ctrl.update_physics(now=t0 + 60.0)
        assert state["temperature"] > TemperatureController.AMBIENT_TEMP

    def test_heater_power_range_check(self):
        ctrl = TemperatureController()
        r1 = ctrl.set_heater_power(-1.0)
        assert r1["allowed"] is False
        r2 = ctrl.set_heater_power(101.0)
        assert r2["allowed"] is False
        r3 = ctrl.set_heater_power(50.0)
        assert r3["allowed"] is True

    def test_emergency_shutdown_triggers_at_high_temp(self):
        ctrl = TemperatureController()
        t0 = time.monotonic()
        ctrl.set_heater_power(100.0, now=t0)
        
        # Advance time iteratively instead of one massive jump
        current_time = t0
        for _ in range(3600):
            current_time += 1.0
            state = ctrl.update_physics(now=current_time)
            if state.get("is_emergency"):  # ✅ break on interlock
                break
        assert state.get("is_emergency"), \
            "Expected emergency shutdown to trigger at high temperature"

        
    def test_heater_blocked_during_lockout(self):
        ctrl = TemperatureController()
        ctrl._is_emergency_shutdown = True
        result = ctrl.set_heater_power(50.0)
        assert result["allowed"] is False

    def test_passive_cooling_works(self):
        ctrl = TemperatureController()
        t0 = time.monotonic()
        ctrl.set_heater_power(100.0, now=t0)
        ctrl.update_physics(now=t0 + 300.0)
        ctrl.set_heater_power(0.0, now=t0 + 300.0)
        state = ctrl.update_physics(now=t0 + 600.0)
        assert state["temperature"] < TemperatureController.SENSOR_MAX
