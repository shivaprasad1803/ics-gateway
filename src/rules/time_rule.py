"""
time_rule.py  —  R005 Time-Based Access Control Rule
=====================================================
Layer 4  |  PhysicsGuard ICS Security Gateway
Week 3 deliverable: warn or block commands outside permitted operating hours.

Detects attacks:
  A12 — After-Hours Command Injection  (MITRE T0855)

Priority design:
  R005 runs at priority=15 — between R001 (range check, priority=10) and
  R002 (rate check, priority=20).
  Rationale: a time-window violation is less severe than an out-of-range
  value (R001 always physical damage) but should be flagged before the
  rate check which requires full context.

Severity model:
  Default severity is WARNING — outside hours is suspicious but not
  necessarily destructive. Set block_outside_hours=True to escalate
  to CRITICAL blocking, e.g. for a facility with strict no-write windows
  (maintenance period, night shutdown, etc.).

  This two-mode design follows ICS security practice:
    - Detection mode (WARNING): alerts operator, allows command through
    - Enforcement mode (CRITICAL, block_outside_hours=True): hard block

Time injection for testing:
  The 'now' parameter accepts a float (time.time()-compatible epoch
  seconds). Tests inject specific timestamps to simulate inside/outside
  the allowed window without waiting for the system clock. When now is
  None, time.time() is used (wall-clock, NOT monotonic — time-of-day
  checks require civil time, not monotonic uptime).

Example allowed_hours:
  (8, 18)  → 08:00–17:59 (business hours)
  (0, 24)  → all hours (effectively disable the rule)
  (22, 6)  → 22:00–05:59 (overnight allowed window, wraps midnight)
"""

import logging
import time
import datetime
from typing import Any

from src.rules.base_rule import (
    BaseRule,
    RuleResult,
    pass_result,
    block_result,
    SEVERITY_WARNING,
    SEVERITY_CRITICAL,
)

log = logging.getLogger(__name__)


class TimeRule(BaseRule):
    """
    R005 — Time-Based Access Control Rule  (MITRE T0855)

    Warns (or blocks) write commands that arrive outside the configured
    allowed operating hours.

    Hours are specified as integers in [0, 23] (inclusive).
    The window is inclusive on both ends: allowed_hours=(8, 18) permits
    writes from 08:00:00 through 18:59:59.

    Midnight-wrapping windows are supported:
        allowed_hours=(22, 6) → 22:00–05:59 (crosses midnight)

    Usage::

        # Detection mode: WARNING outside 08:00–17:59 (does not block)
        rule = TimeRule(allowed_hours=(8, 18), label="business hours")
        # 14:30 → inside window
        ts = datetime.datetime(2024, 1, 15, 14, 30).timestamp()
        result = rule.evaluate(address=1, value=50.0, context={}, now=ts)
        assert result.allowed is True

        # 02:00 → outside window, WARNING (still allowed)
        ts2 = datetime.datetime(2024, 1, 15, 2, 0).timestamp()
        result2 = rule.evaluate(address=1, value=50.0, context={}, now=ts2)
        assert result2.allowed is True     # allowed but severity=WARNING

        # Enforcement mode: CRITICAL block outside window
        rule2 = TimeRule(allowed_hours=(8, 18), block_outside_hours=True)
        result3 = rule2.evaluate(address=1, value=50.0, context={}, now=ts2)
        assert result3.allowed is False    # blocked
    """

    rule_id:   str = "R005"
    priority:  int = 15        # Between R001 (10) and R002 (20)
    severity:  str = SEVERITY_WARNING   # Default: warn, don't block
    mitre_tag: str = "T0855"   # Manipulation of Control

    def __init__(
        self,
        allowed_hours:       tuple[int, int],
        address:             int | None = None,
        label:               str = "operating hours",
        block_outside_hours: bool = False,
    ) -> None:
        """
        Args:
            allowed_hours       : (start_hour, end_hour) inclusive, [0, 23].
                                  Wrapping supported: (22, 6) crosses midnight.
                                  (0, 23) means all hours permitted.
            address             : register to guard, or None for all registers.
            label               : description for log/reason strings.
            block_outside_hours : if True, outside-hours result is CRITICAL
                                  and is_blocking() returns True (hard block).
                                  if False (default), result is WARNING and
                                  allowed=True (detection/audit mode).
        """
        start_h, end_h = allowed_hours
        if not (0 <= start_h <= 23):
            raise ValueError(
                f"TimeRule: start_hour must be in [0, 23], got {start_h}"
            )
        if not (0 <= end_h <= 23):
            raise ValueError(
                f"TimeRule: end_hour must be in [0, 23], got {end_h}"
            )
        self.allowed_hours       = (start_h, end_h)
        self.address             = address
        self.label               = label
        self.block_outside_hours = block_outside_hours

    def _is_within_hours(self, hour: int) -> bool:
        """
        Return True if hour falls within the allowed window.

        Handles midnight-wrapping: start=22, end=6 means
        22,23,0,1,2,3,4,5,6 are all allowed.
        """
        start_h, end_h = self.allowed_hours
        if start_h <= end_h:
            # Normal window, e.g. 8 → 18: no wrap
            return start_h <= hour <= end_h
        else:
            # Wrapping window, e.g. 22 → 6: crosses midnight
            return hour >= start_h or hour <= end_h

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,   # time.time()-compatible epoch seconds
    ) -> RuleResult:
        """
        Warn or block if the current hour is outside the allowed window.

        'now' is a float (time.time() epoch seconds), NOT time.monotonic().
        Time-of-day checks require civil wall-clock time. Tests inject
        specific epoch timestamps — use datetime(...).timestamp() for clarity.

        Complexity: O(1).
        """
        # Optional address filter
        if self.address is not None and address != self.address:
            return pass_result(
                self.rule_id,
                f"R005 skipped (reg {address} ≠ {self.address})",
            )

        # Resolve wall-clock time — NOT monotonic (B02: monotonic for rate
        # only; time-of-day always uses civil time)
        wall_time: float = now if (now is not None and now > 1_000_000_000) else time.time()
        current_hour: int = datetime.datetime.fromtimestamp(wall_time).hour

        if self._is_within_hours(current_hour):
            start_h, end_h = self.allowed_hours
            return pass_result(
                self.rule_id,
                f"R005 PASS | {self.label} | "
                f"hour={current_hour:02d}:xx within [{start_h:02d}:00, "
                f"{end_h:02d}:59]",
            )

        # Outside allowed hours
        start_h, end_h = self.allowed_hours
        description = (
            f"R005 TIME VIOLATION | {self.label} | "
            f"hour={current_hour:02d}:xx outside allowed window "
            f"[{start_h:02d}:00–{end_h:02d}:59] | "
            f"MITRE {self.mitre_tag}"
        )

        if self.block_outside_hours:
            # Enforcement mode: hard block
            log.warning(
                "TimeRule: BLOCKING command outside hours | "
                "hour=%02d | window=[%02d:00-%02d:59] | addr=%d val=%.2f",
                current_hour, start_h, end_h, address, value,
            )
            return block_result(
                rule_id=self.rule_id,
                reason=description,
                severity=SEVERITY_CRITICAL,
                mitre_tag=self.mitre_tag,
                metadata={
                    "current_hour":  current_hour,
                    "allowed_hours": self.allowed_hours,
                    "address":       address,
                    "value":         value,
                    "mode":          "enforcement",
                },
            )
        else:
            # Detection mode: WARNING — log and allow through
            log.warning(
                "TimeRule: after-hours command (audit) | "
                "hour=%02d | window=[%02d:00-%02d:59] | addr=%d val=%.2f",
                current_hour, start_h, end_h, address, value,
            )
            # allowed=True with severity=WARNING — is_blocking() returns False
            # (WARNING not in BLOCKING_SEVERITIES) — command proceeds but is
            # logged for forensic audit and Layer 7 dashboard alerting.
            from src.rules.base_rule import RuleResult
            return RuleResult(
                allowed=True,
                reason=description,
                rule_id=self.rule_id,
                severity=SEVERITY_WARNING,
                mitre_tag=self.mitre_tag,
                metadata={
                    "current_hour":  current_hour,
                    "allowed_hours": self.allowed_hours,
                    "address":       address,
                    "value":         value,
                    "mode":          "detection",
                },
            )
