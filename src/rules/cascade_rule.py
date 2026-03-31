"""
cascade_rule.py  —  R012 Multi-PLC Cascade Failure Detector
Layer 4  |  PhysicsGuard ICS Security Gateway
Place in: src/rules/cascade_rule.py
"""
import logging
from typing import Any
from src.rules.base_rule import (
    BaseRule, RuleResult, pass_result, block_result, SEVERITY_EMERGENCY,
)

log = logging.getLogger(__name__)


class CascadeRule(BaseRule):
    """R012 — Multi-PLC Cascade Failure Detector  (MITRE T0855)"""

    rule_id:   str = "R012"
    priority:  int = 45
    severity:  str = SEVERITY_EMERGENCY
    mitre_tag: str = "T0855"

    def __init__(
        self,
        cascade_level_threshold: float = 5.0,
        heater_threshold:        float = 50.0,
        temp_danger_threshold:   float = 150.0,
    ) -> None:
        self.cascade_level_threshold = cascade_level_threshold
        self.heater_threshold        = heater_threshold
        self.temp_danger_threshold   = temp_danger_threshold

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,
    ) -> RuleResult:
        # Heater guard (HR[11])
        if address == 11:
            tank_level = float(context.get("tank_level", 50.0))
            if value > self.heater_threshold and tank_level < self.cascade_level_threshold:
                reason = (
                    f"R012 CASCADE HAZARD | Heater={value:.0f}% blocked — "
                    f"tank_level={tank_level:.1f}% < {self.cascade_level_threshold:.0f}% | "
                    f"MITRE {self.mitre_tag}"
                )
                log.warning("CascadeRule R012: heater BLOCKED | heater=%.0f%% tank=%.1f%%", value, tank_level)
                return block_result(
                    rule_id=self.rule_id, reason=reason,
                    severity=self.severity, mitre_tag=self.mitre_tag,
                    metadata={"address": address, "value": value, "tank_level": tank_level},
                )

        # Pump guard (HR[2]) — block pump-ON during thermal emergency
        if address == 2 and value > 0:
            temperature = float(context.get("temperature", 25.0))
            if temperature > self.temp_danger_threshold:
                reason = (
                    f"R012 CASCADE HAZARD | Pump-ON blocked — "
                    f"temperature={temperature:.1f}°C > {self.temp_danger_threshold:.0f}°C | "
                    f"MITRE {self.mitre_tag}"
                )
                log.warning("CascadeRule R012: pump-ON BLOCKED | temperature=%.1f°C", temperature)
                return block_result(
                    rule_id=self.rule_id, reason=reason,
                    severity=self.severity, mitre_tag=self.mitre_tag,
                    metadata={"address": address, "value": value, "temperature": temperature},
                )

        return pass_result(self.rule_id, "R012 PASS | no cascade condition detected")
