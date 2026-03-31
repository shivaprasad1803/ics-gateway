"""
correlation_rule.py  —  R011 Cross-Sensor Correlation Rule (A11)
Layer 4  |  PhysicsGuard ICS Security Gateway
Place in: src/rules/correlation_rule.py
"""
import logging
import time
from typing import Any
from src.rules.base_rule import (
    BaseRule, RuleResult, pass_result, block_result, SEVERITY_CRITICAL,
)

log = logging.getLogger(__name__)


class CorrelationRule(BaseRule):
    """R011 — Cross-Sensor Correlation Rule  (MITRE T0856)"""

    rule_id:   str = "R011"
    priority:  int = 40
    severity:  str = SEVERITY_CRITICAL
    mitre_tag: str = "T0856"

    def __init__(self, min_expected_rise: float = 0.5) -> None:
        self.min_expected_rise = min_expected_rise
        self._last_level: float | None = None
        self._last_time:  float | None = None

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,
    ) -> RuleResult:
        t = now if now is not None else time.monotonic()
        current_level = float(context.get("tank_level", 50.0))
        valve_pos     = float(context.get("valve_position", 0.0))
        pump_on       = bool(context.get("pump_running", False))

        # Only check when valve is wide open and pump is off (tank MUST fill)
        if valve_pos > 80.0 and not pump_on:
            if self._last_level is not None and self._last_time is not None:
                dt = t - self._last_time
                if dt > 1.0:
                    actual_rise = current_level - self._last_level
                    expected    = self.min_expected_rise * dt
                    if actual_rise < expected:
                        reason = (
                            f"R011 SENSOR MISMATCH | tank not rising despite "
                            f"valve={valve_pos:.0f}% — actual_rise={actual_rise:.2f}% "
                            f"expected ≥ {expected:.2f}% in {dt:.1f}s | "
                            f"MITRE {self.mitre_tag}"
                        )
                        log.warning(
                            "CorrelationRule R011: BLOCKED | valve=%.0f%% rise=%.2f%% expected=%.2f%%",
                            valve_pos, actual_rise, expected,
                        )
                        # Reset after detection to avoid repeated blocks
                        self._last_level = None
                        self._last_time  = None
                        return block_result(
                            rule_id=self.rule_id, reason=reason,
                            severity=self.severity, mitre_tag=self.mitre_tag,
                            metadata={
                                "valve_pos":   valve_pos,
                                "actual_rise": actual_rise,
                                "expected":    expected,
                                "dt":          dt,
                            },
                        )
            self._last_level = current_level
            self._last_time  = t
        else:
            self._last_level = None
            self._last_time  = None

        return pass_result(self.rule_id, "R011 PASS | correlation within bounds")
