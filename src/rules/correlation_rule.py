"""
correlation_rule.py  —  Cross-Sensor Correlation Rule (A11)
==========================================================
Layer 4  |  PhysicsGuard ICS Security Gateway
Novel contribution: detects False Data Injection (A11) by correlating
sensor readings that must move together physically.

Example: If valve is 100% open and pump is OFF, tank level MUST increase.
If tank level stays flat or decreases, a sensor is being spoofed.
"""

from typing import Any
from src.rules.base_rule import BaseRule, RuleResult, pass_result, block_result, SEVERITY_CRITICAL

class CorrelationRule(BaseRule):
    """
    Correlates Valve Position, Pump State, and Tank Level Rate-of-Change.
    Detects T0856 / A11 False Data Injection.
    """

    def __init__(
        self,
        rule_id: str = "R011",
        priority: int = 40,
        min_expected_rise: float = 0.5, # % per second when valve open
    ) -> None:
        super().__init__(rule_id, priority, SEVERITY_CRITICAL, "T0856")
        self.min_expected_rise = min_expected_rise
        self._last_level: float | None = None
        self._last_time: float | None = None

    def evaluate(
        self,
        address: int,
        value: float,
        context: dict[str, Any],
        now: float | None = None,
    ) -> RuleResult:
        if not self.enabled:
            return pass_result(self.rule_id, "disabled")

        import time
        t = now if now is not None else time.monotonic()
        
        current_level = float(context.get("tank_level", 50.0))
        valve_pos = float(context.get("valve_position", 0.0))
        pump_on = bool(context.get("pump_running", False))

        # We only correlate when the valve is significantly open and pump is off
        # to ensure the tank SHOULD be filling up.
        if valve_pos > 80.0 and not pump_on:
            if self._last_level is not None and self._last_time is not None:
                dt = t - self._last_time
                if dt > 1.0: # Check every second
                    actual_rise = current_level - self._last_level
                    # If it's not rising despite valve being 80%+, something is wrong
                    if actual_rise < (self.min_expected_rise * dt):
                        return block_result(
                            self.rule_id,
                            f"Sensor Mismatch: Tank level not rising despite Valve={valve_pos}%",
                            self.severity,
                            self.mitre_tag
                        )
            
            self._last_level = current_level
            self._last_time = t
        else:
            # Reset history if conditions not met to avoid stale correlation
            self._last_level = None
            self._last_time = None

        return pass_result(self.rule_id, "correlation within bounds")
