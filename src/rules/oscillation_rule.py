"""
oscillation_rule.py  —  R009 Setpoint Oscillation Detector
===========================================================
Layer 4  |  PhysicsGuard ICS Security Gateway

Novel Contribution (A09)  |  MITRE T0855

Detects attacks:
  A09 — Setpoint Oscillation Attack  (MITRE T0855)

The gap this closes
───────────────────
Both R002 (RateRule) and R006 (TemporalRule) check magnitude of change
but neither catches DIRECTION REVERSAL PATTERNS.  An attacker can send:

    t=0s   valve=80%   (rate=OK, cumulative=OK)
    t=3s   valve=20%   (rate=20%/3s=6.7%/s → blocked by R002)

They adapt:
    t=0s   valve=80%   (rate=OK)
    t=15s  valve=20%   (rate=4%/s → slips under R002)
    t=30s  valve=80%   (rate=4%/s → slips under R002, cumulative=60% → blocked by R006 eventually)

But with shorter windows they might still cause mechanical stress before
R006 fires.  Rapid oscillation stresses valve actuators even when each
individual step looks legitimate.

R009 closes this by tracking DIRECTION REVERSALS in a sliding window.
A legitimate operator smoothly adjusts a setpoint in one direction.
An attacker (or malfunctioning controller) repeatedly reverses direction.

Detection design
────────────────
  - History: deque of (monotonic_timestamp, value) pairs.
  - On each evaluate(): evict entries older than window_s.
  - Compute deltas between consecutive history entries.
  - Count sign-changes in those deltas (direction reversals).
  - If reversals >= max_reversals → BLOCK as oscillation.
  - Only deltas >= min_delta_pct count — filters out noise from tiny
    adjustments that are not genuine oscillation (e.g. 50%→51%→50%).

Example attack scenario:
  valve: 20% → 80% → 20% → 80% → 20%  (4 reversals in 60s)
  Each step: 60%/20s = 3 %/s → under R002 limit.
  R006 cumulative delta = 60% but direction alternates so net drift ≈ 0 —
  TemporalRule measures |proposed - oldest|, which stays at ~60%, but
  the SUSTAINED OSCILLATION stress on the physical actuator is not captured.
  R009 fires at the 4th reversal and blocks the pattern.

Priority
────────
  R009 priority=22 — after R002 (20, per-command rate) and before R006 (25,
  cumulative window).  Oscillation check runs at the rate layer.

Thread safety
─────────────
  R009 is STATEFUL — history deque mutated per accepted command.
  A threading.Lock guards all reads and writes.

Configuration
─────────────
  address       : register to guard (1 = valve position)
  window_s      : sliding window width in seconds (default 120 s)
  max_reversals : direction changes before blocking (default 4)
  min_delta_pct : minimum value change to count as a reversal (default 10.0)

Example::

    rule = OscillationRule(address=1, window_s=60.0, max_reversals=4)
    t0 = 1000.0

    # Build oscillation history: 20→80→20→80→20
    for i, val in enumerate([20.0, 80.0, 20.0, 80.0]):
        rule.evaluate(address=1, value=val, context={}, now=t0 + i * 15)

    # 5th command hits max_reversals (4) → BLOCKED
    result = rule.evaluate(address=1, value=20.0, context={}, now=t0 + 60)
    assert not result.allowed

Dissertation defence note
─────────────────────────
  "How does PhysicsGuard detect setpoint oscillation attacks?"

  Answer: "R009 OscillationRule tracks direction reversals in a 120-second
  sliding window.  A legitimate operator adjusts setpoints smoothly; an
  attacker driving rapid back-and-forth produces multiple direction changes
  within the window.  When reversal count reaches the threshold (default 4),
  the command is blocked as a T0855 oscillation attack.  The min_delta_pct
  parameter (default 10%) filters normal fine-tuning from genuine oscillation.
  This is distinct from R002 (per-command rate) and R006 (cumulative drift) —
  oscillation can evade both while still stressing the physical actuator."
"""

from __future__ import annotations

import logging
import threading

import time
from collections import deque
from typing import Any

from src.rules.base_rule import (
    BaseRule,
    RuleResult,
    pass_result,
    block_result,
    SEVERITY_CRITICAL,
)

log = logging.getLogger(__name__)


class OscillationRule(BaseRule):
    """
    R009 — Setpoint Oscillation Detector  (MITRE T0855)

    Blocks commands when the number of direction reversals in the
    sliding window reaches max_reversals.

    Attributes (class-level):
        rule_id   : "R009"
        priority  : 22  (after R002=20, before R006=25)
        severity  : CRITICAL
        mitre_tag : "T0855"

    Args:
        address       : 0-based register address to guard (typically 1 for valve).
        window_s      : sliding window width in seconds (default 120.0).
        max_reversals : number of direction changes that triggers a block
                        (default 4 — i.e., five alternating commands).
        min_delta_pct : minimum absolute value change to count as a directional
                        move.  Changes smaller than this are ignored (noise filter).
                        Default 10.0 (%).
    """

    rule_id:   str = "R009"
    priority:  int = 22        # after R002 (20), before R006 (25)
    severity:  str = SEVERITY_CRITICAL
    mitre_tag: str = "T0855"   # Manipulation of Control — Setpoint

    def __init__(
        self,
        address:       int,
        window_s:      float = 120.0,
        max_reversals: int   = 4,
        min_delta_pct: float = 10.0,
    ) -> None:
        if window_s <= 0:
            raise ValueError(f"OscillationRule: window_s must be > 0, got {window_s}")
        if max_reversals < 1:
            raise ValueError(
                f"OscillationRule: max_reversals must be >= 1, got {max_reversals}"
            )
        if min_delta_pct < 0:
            raise ValueError(
                f"OscillationRule: min_delta_pct must be >= 0, got {min_delta_pct}"
            )

        self.address       = address
        self.window_s      = window_s
        self.max_reversals = max_reversals
        self.min_delta_pct = min_delta_pct

        # Sliding window: deque of (monotonic_timestamp, value) pairs.
        # Only ACCEPTED commands are recorded (same pattern as TemporalRule).
        self._history: deque[tuple[float, float]] = deque()
        self._lock = threading.Lock()

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,
    ) -> RuleResult:
        """
        Block if the direction-reversal count in the sliding window
        meets or exceeds max_reversals.

        Algorithm:
          1. Skip if not our register.
          2. Evict entries older than window_s.
          3. Build a delta series: [v1-v0, v2-v1, ...] filtering deltas
             with |Δ| < min_delta_pct (noise).
          4. Count sign changes in the filtered delta series.
          5. Check proposed delta against last accepted value:
             if adding it would create >= max_reversals reversals → BLOCK.
          6. Pass and record (now, value) in history.

        Thread safety: all history reads/writes inside self._lock.
        """
        if address != self.address:
            return pass_result(
                self.rule_id,
                f"R009 skipped (reg {address} ≠ {self.address})",
            )

        import time as _time
        if now is None:
            now = time.monotonic()

        value = float(value)

        with self._lock:
            # Step 1: evict expired entries
            cutoff = now - self.window_s
            while self._history and self._history[0][0] < cutoff:
                self._history.popleft()

            # Step 2: count reversals in current window + proposed command.
            # Build list of significant values (filter noise with min_delta_pct).
            all_values: list[float] = [v for _, v in self._history] + [value]

            if len(all_values) < 3:
                # Need at least 3 points for one reversal — always pass
                self._history.append((now, value))
                return pass_result(
                    self.rule_id,
                    f"R009 PASS | insufficient history ({len(all_values)} pts) "
                    f"for oscillation detection",
                )

            # Compute significant deltas (filter small noise movements)
            significant_deltas: list[float] = []
            ref = all_values[0]
            for v in all_values[1:]:
                delta = v - ref
                if abs(delta) >= self.min_delta_pct:
                    significant_deltas.append(delta)
                    ref = v

            # Count direction reversals (sign changes) in significant deltas
            reversals = 0
            for i in range(1, len(significant_deltas)):
                prev_sign = 1 if significant_deltas[i - 1] > 0 else -1
                curr_sign = 1 if significant_deltas[i]     > 0 else -1
                if prev_sign != curr_sign:
                    reversals += 1

            if reversals >= self.max_reversals:
                reason = (
                    f"R009 OSCILLATION DETECTED | "
                    f"{reversals} direction reversals in "
                    f"{self.window_s:.0f}s window "
                    f"(limit={self.max_reversals}) | "
                    f"proposed={value:.1f} | "
                    f"MITRE {self.mitre_tag}"
                )
                log.warning(
                    "OscillationRule R009: oscillation BLOCKED | "
                    "addr=%d val=%.1f reversals=%d limit=%d window=%.0fs",
                    address, value, reversals, self.max_reversals, self.window_s,
                )
                # Blocked command NOT recorded — attacker cannot reset baseline
                return block_result(
                    rule_id=self.rule_id,
                    reason=reason,
                    severity=self.severity,
                    mitre_tag=self.mitre_tag,
                    metadata={
                        "address":       address,
                        "value":         value,
                        "reversals":     reversals,
                        "max_reversals": self.max_reversals,
                        "window_s":      self.window_s,
                        "history_len":   len(self._history),
                    },
                )

            # Pass — record in history
            self._history.append((now, value))

        return pass_result(
            self.rule_id,
            f"R009 PASS | {reversals} reversal(s) in {self.window_s:.0f}s window "
            f"(limit={self.max_reversals})",
        )

    def reset(self) -> None:
        """Clear oscillation history. Use between test scenarios."""
        with self._lock:
            self._history.clear()

    def snapshot(self) -> list[tuple[float, float]]:
        """Return (timestamp, value) history copy for tests/diagnostics."""
        with self._lock:
            return list(self._history)
