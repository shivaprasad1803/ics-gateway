"""
range_rule.py  —  R001 Range Validation Rule
=============================================
Layer 4  |  PhysicsGuard ICS Security Gateway
Week 3 deliverable: block any write whose value falls outside [min, max].

Detects attacks:
  A01 — Out-of-Range Setpoint  (MITRE T0855)

Physical justification for valve [0, 100]%:
  A valve cannot physically open beyond 100% or below 0%. Any command
  outside this range either indicates a sensor miscalibration, a
  protocol error, or an active setpoint manipulation attack (T0855).
  IEC 61511 requires range checking at every process input boundary.
"""

import logging
from typing import Any

from src.rules.base_rule import (
    BaseRule,
    RuleResult,
    pass_result,
    block_result,
    SEVERITY_CRITICAL,
)

log = logging.getLogger(__name__)


class RangeRule(BaseRule):
    """
    R001 — Range Validation Rule  (MITRE T0855)

    Blocks any write to target_address where value < min_value or
    value > max_value.  Boundary values (== min or == max) are allowed.

    Usage::

        rule = RangeRule(address=1, min_value=0.0, max_value=100.0,
                         label="valve %")
        result = rule.evaluate(address=1, value=150.0, context={})
        assert result.allowed is False   # 150 > 100 → blocked

        result = rule.evaluate(address=1, value=100.0, context={})
        assert result.allowed is True    # exactly at boundary → allowed
    """

    rule_id:   str = "R001"
    priority:  int = 10       # Runs first — fast, no context needed
    severity:  str = SEVERITY_CRITICAL
    mitre_tag: str = "T0855"  # Manipulation of Control — Setpoint

    def __init__(
        self,
        address:   int,
        min_value: float,
        max_value: float,
        label:     str = "value",
    ) -> None:
        """
        Args:
            address   : 0-based register address this rule guards
            min_value : inclusive lower bound
            max_value : inclusive upper bound
            label     : unit label used in log/reason strings
        """
        if min_value > max_value:
            raise ValueError(
                f"RangeRule: min_value {min_value} > max_value {max_value} "
                f"— range is empty"
            )
        self.address   = address
        self.min_value = min_value
        self.max_value = max_value
        self.label     = label

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,   # unused — present to satisfy BaseRule contract
    ) -> RuleResult:
        """
        Block if value is outside [min_value, max_value].

        Complexity: O(1) — no context required, fastest rule in the chain.
        """
        # Not our register — pass immediately without inspecting value
        if address != self.address:
            return pass_result(
                self.rule_id,
                f"R001 skipped (reg {address} ≠ {self.address})",
            )

        if self.min_value <= value <= self.max_value:
            return pass_result(
                self.rule_id,
                f"R001 PASS | {self.label}={value:.2f} "
                f"in [{self.min_value}, {self.max_value}]",
            )

        reason = (
            f"R001 RANGE VIOLATION | {self.label}={value:.2f} "
            f"outside [{self.min_value}, {self.max_value}] | "
            f"MITRE {self.mitre_tag}"
        )
        return block_result(
            rule_id=self.rule_id,
            reason=reason,
            severity=self.severity,
            mitre_tag=self.mitre_tag,
            metadata={
                "address":   address,
                "value":     value,
                "min_value": self.min_value,
                "max_value": self.max_value,
            },
        )
