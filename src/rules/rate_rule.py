"""
rate_rule.py  —  R002 Rate-of-Change Validation Rule
=====================================================
Layer 4  |  PhysicsGuard ICS Security Gateway
Week 3 deliverable: block writes where |Δvalue| / dt > max_rate.

Detects attacks:
  A02 — Rapid Setpoint Change    (MITRE T0855)
  A09 — Setpoint Oscillation     (MITRE T0855)

Critical design notes:
  D03 alignment: dt <= 0 is treated as infinite rate and BLOCKED.
    The physics layer (water_tank.py D03) does the same — if two
    commands share a monotonic tick, rate = |Δ| / 0 = ∞ → blocked.
    Previously this layer SKIPPED on dt <= 0, creating an inconsistency:
    an attacker sending two commands fast enough to share a tick would
    bypass Layer 4 (skipped) but be caught by Layer 1 (blocked).
    Now both layers are consistent — defence-in-depth is symmetric.

  dt < 0 specifically indicates a clock anomaly (monotonic clock
  went backwards, which should never happen) or possible timestamp
  manipulation. This is escalated to EMERGENCY severity.

  now= parameter is injectable for deterministic testing without sleep().
  time.monotonic() ONLY — never time.time() for dt calculations (B02 fix).
"""

import logging
import time
from typing import Any

from src.rules.base_rule import (
    BaseRule,
    RuleResult,
    pass_result,
    block_result,
    SEVERITY_CRITICAL,
    SEVERITY_EMERGENCY,
)

log = logging.getLogger(__name__)


class RateRule(BaseRule):
    """
    R002 — Rate-of-Change Rule  (MITRE T0855)

    Blocks any write where:
        rate = |proposed_value - current_value| / dt  >  max_rate

    Where:
        current_value = context[context_key]   (e.g. context["valve_position"])
        dt            = now - context["last_cmd_time"]

    First-command skip:
        If last_cmd_time is 0.0 (never set) the rate check is skipped.
        This applies only to the very first command ever issued — R001
        range check still runs, so there is no security gap.

    dt <= 0 blocking (D03):
        dt == 0  → rate = ∞ → CRITICAL (instant/same-tick command)
        dt < 0   → clock anomaly → EMERGENCY (potential time manipulation)

    Usage::

        rule = RateRule(address=1, max_rate=5.0, context_key="valve_position")
        t0  = time.monotonic()
        ctx = {"valve_position": 0.0, "last_cmd_time": t0}

        # 50 %/s — blocked
        result = rule.evaluate(address=1, value=50.0, context=ctx, now=t0 + 1.0)
        assert result.allowed is False

        # 2.5 %/s — allowed
        result = rule.evaluate(address=1, value=5.0, context=ctx, now=t0 + 2.0)
        assert result.allowed is True
    """

    rule_id:   str = "R002"
    priority:  int = 20       # Runs after R001 — requires context["last_cmd_time"]
    severity:  str = SEVERITY_CRITICAL
    mitre_tag: str = "T0855"  # Manipulation of Control — Setpoint

    def __init__(
        self,
        address:     int,
        max_rate:    float,
        context_key: str,
        label:       str = "value/s",
    ) -> None:
        """
        Args:
            address     : 0-based register address this rule guards
            max_rate    : maximum allowed rate of change (units/second)
            context_key : key in context snapshot for the current value,
                          e.g. "valve_position"
            label       : unit label for log/reason strings, e.g. "%/s"
        """
        if max_rate <= 0:
            raise ValueError(
                f"RateRule: max_rate must be > 0, got {max_rate}"
            )
        self.address     = address
        self.max_rate    = max_rate
        self.context_key = context_key
        self.label       = label

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,   # injectable for testing (B02 fix)
    ) -> RuleResult:
        """
        Block if the rate of change exceeds max_rate.

        Thread safety: stateless — reads only from context and now.
        Complexity: O(1).

        Args:
            address : register being written
            value   : proposed new value
            context : must contain context_key (current value) and
                      last_cmd_time (monotonic timestamp of last accepted write)
            now     : time.monotonic() override for deterministic tests
        """
        # Not our register — pass immediately
        if address != self.address:
            return pass_result(
                self.rule_id,
                f"R002 skipped (reg {address} ≠ {self.address})",
            )

        # B02 fix: ONLY time.monotonic() — immune to NTP jumps
        if now is None:
            now = time.monotonic()

        last_cmd_time: float = float(context.get("last_cmd_time", 0.0))
        current_value: float = float(context.get(self.context_key, 0.0))

        # First-command-ever: no prior timestamp — skip rate check
        # (R001 range check already ran; attacker cannot exploit this)
        if last_cmd_time <= 0.0:
            return pass_result(
                self.rule_id,
                "R002 skipped (no prior command — first command only)",
            )

        dt: float = now - last_cmd_time

        # ── D03 alignment: dt <= 0 → block ───────────────────────────────────
        # dt == 0: two commands on the same monotonic tick → infinite rate
        # dt < 0:  clock anomaly or timestamp manipulation → EMERGENCY
        if dt < 0.0:
            reason = (
                f"R002 CLOCK ANOMALY | dt={dt:.9f}s < 0 — "
                f"monotonic clock went backwards; "
                f"possible timestamp manipulation | "
                f"MITRE {self.mitre_tag}"
            )
            log.error("RateRule: clock anomaly dt=%.9f — escalating to EMERGENCY", dt)
            return block_result(
                rule_id=self.rule_id,
                reason=reason,
                severity=SEVERITY_EMERGENCY,
                mitre_tag=self.mitre_tag,
                metadata={
                    "address":        address,
                    "value":          value,
                    "current_value":  current_value,
                    "dt":             dt,
                    "last_cmd_time":  last_cmd_time,
                    "now":            now,
                },
            )

        if dt == 0.0:
            reason = (
                f"R002 INSTANT CHANGE | dt=0 — same monotonic tick; "
                f"treating as infinite rate | "
                f"MITRE {self.mitre_tag}"
            )
            return block_result(
                rule_id=self.rule_id,
                reason=reason,
                severity=SEVERITY_CRITICAL,
                mitre_tag=self.mitre_tag,
                metadata={
                    "address":       address,
                    "value":         value,
                    "current_value": current_value,
                    "dt":            dt,
                },
            )

        # ── Normal rate check ─────────────────────────────────────────────────
        rate: float = abs(value - current_value) / dt

        if rate <= self.max_rate:
            return pass_result(
                self.rule_id,
                f"R002 PASS | rate={rate:.3f} {self.label} "
                f"≤ limit {self.max_rate}",
            )

        reason = (
            f"R002 RATE VIOLATION | rate={rate:.2f} {self.label} "
            f"exceeds limit {self.max_rate} | "
            f"Δ={value - current_value:+.2f} in {dt:.3f}s | "
            f"MITRE {self.mitre_tag}"
        )
        return block_result(
            rule_id=self.rule_id,
            reason=reason,
            severity=self.severity,
            mitre_tag=self.mitre_tag,
            metadata={
                "address":       address,
                "value":         value,
                "current_value": current_value,
                "rate":          rate,
                "max_rate":      self.max_rate,
                "dt":            dt,
            },
        )
