"""
cascade_rule.py  —  Multi-PLC Cascade Failure Detector (A12)
==========================================================
Layer 4  |  PhysicsGuard ICS Security Gateway
Novel contribution: detects Cascade Failure Triggers (A12) by monitoring
logical dependencies across different PLCs in the plant topology.

Example: If PLC_01 (Water Tank) is at 1% level, PLC_02 (Heater) MUST NOT
be set to 100% power, as it would cause a thermal runaway/damage.
"""

from typing import Any
from src.rules.base_rule import BaseRule, RuleResult, pass_result, block_result, SEVERITY_EMERGENCY

class CascadeRule(BaseRule):
    """
    Monitors inter-PLC safety constraints.
    Detects T0855 / A12 Cascade Failure Trigger.
    """

    def __init__(
        self,
        rule_id: str = "R012",
        priority: int = 45,
    ) -> None:
        super().__init__(rule_id, priority, SEVERITY_EMERGENCY, "T0855")

    def evaluate(
        self,
        address: int,
        value: float,
        context: dict[str, Any],
        now: float | None = None,
    ) -> RuleResult:
        if not self.enabled:
            return pass_result(self.rule_id, "disabled")

        # Context keys must reflect the global plant state.
        # This requires the modbus_server.py to populate multi-PLC context.
        tank_level = float(context.get("tank_level", 50.0))
        heater_power = float(context.get("heater_power", 0.0))

        # Check Cascade Failure Condition:
        # If writing to Heater (PLC_02 address 11) or Tank registers:
        if address == 11 and value > 50.0 and tank_level < 5.0:
            return block_result(
                self.rule_id,
                f"Cascade Danger: Cannot set Heater={value}% while TankLevel={tank_level}% is critical",
                self.severity,
                self.mitre_tag
            )

        return pass_result(self.rule_id, "no cascade condition detected")
