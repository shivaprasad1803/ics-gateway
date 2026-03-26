"""
temporal_rule.py  —  R006 Temporal Slow-Drip Anomaly Detector
==============================================================
Layer 4  |  PhysicsGuard ICS Security Gateway

Novel Contribution #3  |  H2 fix

Detects attacks:
  A10 — Temporal Slow-Drip Attack  (MITRE T0855)

The gap this closes
───────────────────
R002 (RateRule) checks only the INSTANTANEOUS rate of change between
consecutive commands:

    rate = |Δvalue| / dt_between_commands

An attacker who keeps each per-command delta below the R002 threshold
(5 %/s) can still accumulate a large cumulative shift over time:

    Attacker sends valve: 46%, 47%, 48% ... each 10 s apart.
    Per-command rate = 1 % / 10 s = 0.1 %/s  →  R002 passes every time.
    After 500 s the valve has moved from 46% → 96%.  Tank overflows.
    Zero R002 detections.

R006 closes this by tracking the CUMULATIVE absolute delta within a
configurable sliding time window:

    cumulative_delta = |value_now - oldest_value_in_window|

If cumulative_delta exceeds max_cumulative_delta the command is blocked,
regardless of whether any single step exceeded the per-command limit.

Sliding-window design
─────────────────────
  - History is a collections.deque of (monotonic_timestamp, value) pairs.
  - On every evaluate() call, entries older than window_s are evicted.
  - The cumulative delta is measured from the OLDEST surviving entry to
    the PROPOSED new value (not yet committed).
  - window_s=300, max_cumulative_delta=15.0 by default: a legitimate
    operator cannot move the valve more than 15% in any 300-second window.
  - The window and threshold are constructor-configurable for YAML loading.

Thread safety
─────────────
  Unlike R001/R002 which are stateless, R006 is STATEFUL — history is
  mutated on every evaluate() call.  A threading.Lock guards all reads
  and writes to _history.

  This matters because ValidationEngine may be called from the Modbus
  server thread AND (after C1 fix) from the asyncua event loop.  Both
  paths must see a consistent history deque.

now= injection
──────────────
  time.monotonic() only — never time.time().  The 'now' parameter is
  injectable for deterministic tests: pass now=<float> to simulate
  arbitrary inter-command timing without sleep().

Priority
────────
  R006 priority=25 — runs after R002 (20) because R002 eliminates
  instant-rate attacks before the sliding window is consulted.  Runs
  before R003 (30) interlock because temporal anomalies should be caught
  at the rate layer, not the state layer.

Example::

    rule = TemporalRule(address=1, window_s=300, max_cumulative_delta=15.0)
    t0 = time.monotonic()

    # Slow-drip: +1% every 10 s — each step passes R002 (0.1 %/s)
    ctx = {"valve_position": 46.0, "last_cmd_time": t0}
    for i, pct in enumerate(range(47, 68)):       # 47 … 67
        now = t0 + i * 10.0
        ctx = {**ctx, "valve_position": float(pct - 1), "last_cmd_time": now - 10}
        result = rule.evaluate(address=1, value=float(pct), context=ctx, now=now)
        # First 20 steps pass; step 21 (cumulative Δ = 21%) is blocked

Dissertation defence note
─────────────────────────
  "How does PhysicsGuard detect slow-drip attacks that stay below the
  per-command rate limit?"

  Answer: "R006 TemporalRule maintains a sliding window of accepted
  commands. The cumulative valve movement within any 300-second window is
  bounded to 15%. An attacker sending +1%/10 s passes R002 every time
  but is blocked by R006 after accumulating 16% of drift (160 s in,
  340 s before overflow).  This is Novel Contribution #3 — no
  open-source ICS gateway does this today."
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


class TemporalRule(BaseRule):
    """
    R006 — Temporal Slow-Drip Anomaly Detector  (MITRE T0855)

    Blocks commands where the cumulative absolute value change within a
    sliding time window exceeds max_cumulative_delta.

    Complements R002 (per-command rate check) by catching attacks that
    deliberately stay below the per-command threshold while accumulating
    a large total shift over time.

    Attributes (class-level, overrideable):
        rule_id   : "R006"
        priority  : 25  (after R002=20, before R003=30)
        severity  : CRITICAL
        mitre_tag : "T0855"

    Args:
        address              : 0-based register address this rule guards.
                               Typically 1 (valve position).
        window_s             : sliding window duration in seconds.
                               Default 300 s (5-minute window).
        max_cumulative_delta : maximum allowed cumulative |Δvalue| within
                               window_s.  Default 15.0 (percent for valve).
        label                : unit label for log/reason strings.
    """

    rule_id:   str = "R006"
    priority:  int = 25        # After R002 (20), before R003 (30)
    severity:  str = SEVERITY_CRITICAL
    mitre_tag: str = "T0855"   # Manipulation of Control — Setpoint

    def __init__(
        self,
        address:              int,
        window_s:             float = 300.0,
        max_cumulative_delta: float = 15.0,
        label:                str   = "%",
    ) -> None:
        """
        Args:
            address              : register address to guard (e.g. 1 for valve)
            window_s             : sliding window width in seconds (default 300 s).
                                   A 5-minute window catches slow-drip attacks
                                   that complete in under 500 s (A10 scenario).
            max_cumulative_delta : max cumulative |Δ| within the window
                                   (default 15.0 — i.e. 15% for valve position).
                                   With +1%/10s attack this fires at step 16
                                   (160 s into the attack, 340 s before overflow).
            label                : unit string for human-readable reasons
        """
        if window_s <= 0:
            raise ValueError(f"TemporalRule: window_s must be > 0, got {window_s}")
        if max_cumulative_delta <= 0:
            raise ValueError(
                f"TemporalRule: max_cumulative_delta must be > 0, "
                f"got {max_cumulative_delta}"
            )

        self.address              = address
        self.window_s             = window_s
        self.max_cumulative_delta = max_cumulative_delta
        self.label                = label

        # Sliding window: deque of (monotonic_timestamp, accepted_value) tuples.
        # Only ALLOWED commands are recorded — blocked commands do not advance
        # the baseline, preventing an attacker from "resetting" the window by
        # interleaving blocked commands with allowed ones.
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
        Block if cumulative |Δ| within the sliding window exceeds the limit.

        Algorithm:
          1. Evict history entries older than (now - window_s).
          2. Compute cumulative delta = |proposed_value - oldest_in_window|.
             If window is empty, delta = 0 (first command is always allowed).
          3. If cumulative_delta > max_cumulative_delta → BLOCK.
          4. Otherwise → PASS; record (now, value) in history for future calls.

        Note: The proposed value is recorded ONLY on a PASS result.  Blocked
        values are not recorded so the attacker cannot poison the window
        baseline by repeatedly sending just-below-threshold commands followed
        by a large blocked step.

        Thread safety: all history reads/writes are inside self._lock.

        Args:
            address : register being written
            value   : proposed new value
            context : current plant state (used only for address skip check)
            now     : time.monotonic() override for deterministic tests
        """
        # Not our register — skip immediately (O(1), no lock needed)
        if address != self.address:
            return pass_result(
                self.rule_id,
                f"R006 skipped (reg {address} ≠ {self.address})",
            )

        if now is None:
            now = time.monotonic()

        value = float(value)

        with self._lock:
            # ── Step 1: evict expired entries ─────────────────────────────
            cutoff = now - self.window_s
            while self._history and self._history[0][0] < cutoff:
                self._history.popleft()

            # ── Step 2: compute cumulative delta ──────────────────────────
            if self._history:
                # Oldest value still inside the window
                oldest_value = self._history[0][1]
                cumulative_delta = abs(value - oldest_value)
            else:
                # Empty window — first command in this window, always allowed
                cumulative_delta = 0.0

            # ── Step 3: check against threshold ───────────────────────────
            if cumulative_delta > self.max_cumulative_delta:
                reason = (
                    f"R006 SLOW-DRIP DETECTED | "
                    f"cumulative Δ={cumulative_delta:.2f}{self.label} "
                    f"in {self.window_s:.0f}s window "
                    f"exceeds limit {self.max_cumulative_delta}{self.label} | "
                    f"proposed={value:.2f} oldest_in_window={oldest_value:.2f} | "
                    f"MITRE {self.mitre_tag}"
                )
                log.warning(
                    "TemporalRule R006: slow-drip blocked | "
                    "addr=%d val=%.2f cumulative_delta=%.2f limit=%.2f "
                    "window=%.0fs",
                    address, value, cumulative_delta,
                    self.max_cumulative_delta, self.window_s,
                )
                # Do NOT record blocked value — attacker cannot reset baseline
                return block_result(
                    rule_id=self.rule_id,
                    reason=reason,
                    severity=self.severity,
                    mitre_tag=self.mitre_tag,
                    metadata={
                        "address":              address,
                        "value":                value,
                        "oldest_value":         oldest_value,
                        "cumulative_delta":     cumulative_delta,
                        "max_cumulative_delta": self.max_cumulative_delta,
                        "window_s":             self.window_s,
                        "history_len":          len(self._history),
                        "now":                  now,
                    },
                )

            # ── Step 4: pass — record accepted value in history ───────────
            self._history.append((now, value))

        return pass_result(
            self.rule_id,
            f"R006 PASS | "
            f"cumulative Δ={cumulative_delta:.2f}{self.label} "
            f"≤ limit {self.max_cumulative_delta}{self.label} "
            f"in {self.window_s:.0f}s window",
        )

    def reset(self) -> None:
        """
        Clear the sliding window history.

        Useful in tests between scenarios to prevent history from one
        test bleeding into the next.  Not needed in production — the
        window expires naturally.
        """
        with self._lock:
            self._history.clear()

    def snapshot(self) -> list[tuple[float, float]]:
        """
        Return a copy of the current history window as a list of
        (timestamp, value) tuples, oldest first.

        Intended for testing and dashboard inspection only.
        """
        with self._lock:
            return list(self._history)
