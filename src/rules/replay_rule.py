"""
replay_rule.py  —  R008 Command Replay Attack Detector
=======================================================
Layer 4  |  PhysicsGuard ICS Security Gateway

H4 fix

Detects attacks:
  A08 — Command Replay Attack  (MITRE T0856)

The gap this closes
───────────────────
An attacker who can observe the Modbus TCP wire captures a legitimate
command frame:

    Time 10:00:00 — operator writes valve=50  (allowed, logged)

Five seconds later they replay the exact same payload:

    Time 10:00:05 — attacker replays valve=50 frame

All five existing rules pass:
  R001 range check  — 50% is in [0, 100]          ✅ passes
  R002 rate check   — only 0%/s change (50→50)    ✅ passes
  R003 interlock    — not a pump command           ✅ passes
  R004 auth         — same IP as operator          ✅ passes
  R005 time window  — still business hours         ✅ passes

The replay is accepted.  Replaying a pump-START command after the tank
has drained below 10% is a particularly dangerous variant: R003 normally
catches the interlock, but if the attacker captured the command from a
time when level was high, R003 runs against the CURRENT (low) level and
will block it — but R008 catches it before R003 even runs, making the
detection earlier and independent.

Detection design
────────────────
R008 maintains a bounded deque of recently-accepted commands as
(address, quantised_value, monotonic_timestamp) triples.  A new command
is a replay if the exact same (address, quantised_value) was accepted
within the last replay_window_s seconds.

Quantisation: value is rounded to one decimal place before comparison
so that floating-point noise (50.0 vs 50.00001) does not produce false
negatives.  Operators legitimately sending 50.0% twice in quick succession
is extremely rare in ICS; the window default of 5 s keeps the detection
window tight.

context["cmd_timestamp"] injection
────────────────────────────────────
setValues() in ProtectedHoldingRegister already captures time.monotonic()
for latency measurement (t_start, reused as cmd_timestamp).  The rule reads
context.get("cmd_timestamp") — if absent it calls time.monotonic() itself,
keeping the rule usable in unit tests that don't populate the context.

Priority
────────
R008 priority=12 — after R001 range (10) and before R005 time (15).
Rationale: range check eliminates nonsensical values first (fastest gate
for out-of-range replays).  Replay check runs before rate/time/interlock
so a replayed command is blocked as A08, not misclassified as A02/A05.

Thread safety
─────────────
R008 is STATEFUL — the history deque is mutated on every accepted command.
A threading.Lock guards all reads and writes, matching TemporalRule's
pattern.  The Modbus path and OPC UA path (after C1 fix) both call
ValidationEngine from asyncio, but the lock is cheap and contention rare.

Capacity limit
──────────────
The history deque is bounded by max_history (default 1000) so memory
consumption is O(1) regardless of command volume.  1000 entries at 5 s
window implies the rule is designed for ≤200 cmd/s sustained rate — well
above any realistic ICS workload.

Example::

    rule = ReplayRule(address=1, replay_window_s=5.0)
    t0   = 1000.0

    # Legitimate command — accepted and recorded
    ctx = {"cmd_timestamp": t0, "valve_position": 0.0, "tank_level": 50.0}
    r = rule.evaluate(address=1, value=50.0, context=ctx, now=t0)
    assert r.allowed                           # first time — allowed

    # Replay within window — blocked
    r2 = rule.evaluate(address=1, value=50.0, context=ctx, now=t0 + 3.0)
    assert not r2.allowed                      # replay within 5 s — blocked

    # Same value after window expires — allowed again
    r3 = rule.evaluate(address=1, value=50.0, context=ctx, now=t0 + 6.0)
    assert r3.allowed                          # window expired — allowed

Dissertation defence note
─────────────────────────
  "How does PhysicsGuard detect command replay attacks?"

  Answer: "R008 ReplayRule tracks every accepted command in a bounded
  sliding window.  If the exact same (address, value) appears again within
  5 seconds, it is flagged as a replay (MITRE T0856) and blocked before
  any physics rule runs.  The rule is stateful and thread-safe, and the
  window is configurable via the constructor — allowing operators to tune
  the detection sensitivity without code changes."
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

# Quantisation precision: values rounded to this many decimal places before
# comparison so floating-point noise does not cause false negatives.
_VALUE_ROUND_DP: int = 1


class ReplayRule(BaseRule):
    """
    R008 — Command Replay Attack Detector  (MITRE T0856)

    Blocks commands where the exact same (address, value) was accepted
    within the last replay_window_s seconds.

    Complements R001–R007 by catching attacks that replay a previously
    legitimate command verbatim — all physics/identity rules pass because
    the content was valid when originally issued.

    Attributes (class-level):
        rule_id   : "R008"
        priority  : 12  (after R001 range=10, before R005 time=15)
        severity  : CRITICAL
        mitre_tag : "T0856"

    Args:
        address         : 0-based register address to guard.
                          Typically 1 (valve) or 2 (pump).
                          Pass None to guard ALL addresses.
        replay_window_s : time window in seconds within which a duplicate
                          (address, value) is considered a replay.
                          Default 5.0 s.
        max_history     : maximum number of recent commands to track.
                          Older entries are evicted when this limit is
                          reached, regardless of timestamp.
                          Default 1000.
    """

    rule_id:   str = "R008"
    priority:  int = 12        # After R001 (10), before R005 (15)
    severity:  str = SEVERITY_CRITICAL
    mitre_tag: str = "T0856"   # Theft of Operational Information / Replay

    def __init__(
        self,
        address:         int | None = None,
        replay_window_s: float      = 5.0,
        max_history:     int        = 1000,
    ) -> None:
        """
        Args:
            address         : register to guard, or None for all registers.
            replay_window_s : how long (seconds) to remember a command.
                              A duplicate within this window = replay.
                              Default 5.0 s.
            max_history     : capacity cap on the history deque.
                              Default 1000 entries.
        """
        if replay_window_s <= 0:
            raise ValueError(
                f"ReplayRule: replay_window_s must be > 0, got {replay_window_s}"
            )
        if max_history < 1:
            raise ValueError(
                f"ReplayRule: max_history must be >= 1, got {max_history}"
            )

        self.address         = address
        self.replay_window_s = replay_window_s
        self.max_history     = max_history

        # History: deque of (address, quantised_value, monotonic_timestamp).
        # maxlen enforces the capacity cap automatically.
        self._history: deque[tuple[int, float, float]] = deque(maxlen=max_history)
        self._lock = threading.Lock()

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,
    ) -> RuleResult:
        """
        Block if the same (address, value) was accepted within replay_window_s.

        Algorithm:
          1. Address filter: if self.address is set and differs, skip.
          2. Resolve timestamp: context["cmd_timestamp"] or time.monotonic().
          3. Evict history entries older than (now - replay_window_s).
          4. Check: is (address, quantised_value) in remaining history?
             Yes → BLOCK as replay.
          5. No → PASS; record (address, quantised_value, now) for future.

        Like TemporalRule, blocked commands are NOT recorded — an attacker
        cannot flood the history with blocked replays to push out the
        original entry and then send the replay again.

        Thread safety: all history reads/writes inside self._lock.

        Args:
            address : register being written
            value   : proposed new value
            context : may contain "cmd_timestamp" (monotonic float) set by
                      ProtectedHoldingRegister.setValues() before validate()
            now     : time.monotonic() override for deterministic tests
        """
        # Address filter
        if self.address is not None and address != self.address:
            return pass_result(
                self.rule_id,
                f"R008 skipped (reg {address} ≠ {self.address})",
            )

        # Resolve timestamp — prefer context injection, fall back to live clock
        if now is None:
            now = float(context.get("cmd_timestamp", time.monotonic()))

        qval = round(float(value), _VALUE_ROUND_DP)

        with self._lock:
            # ── Step 1: evict expired entries ─────────────────────────────
            cutoff = now - self.replay_window_s
            # Deque is ordered oldest-first; popleft until fresh entry found
            while self._history and self._history[0][2] < cutoff:
                self._history.popleft()

            # ── Step 2: check for duplicate in window ──────────────────────
            for hist_addr, hist_val, _ in self._history:
                if hist_addr == address and hist_val == qval:
                    reason = (
                        f"R008 REPLAY DETECTED | "
                        f"(addr={address}, val={qval}) seen within "
                        f"last {self.replay_window_s:.1f}s replay window | "
                        f"MITRE {self.mitre_tag}"
                    )
                    log.warning(
                        "ReplayRule R008: replay BLOCKED | "
                        "addr=%d val=%.1f window=%.1fs | MITRE %s",
                        address, qval, self.replay_window_s, self.mitre_tag,
                    )
                    # Do NOT record blocked command — prevents history flooding
                    return block_result(
                        rule_id=self.rule_id,
                        reason=reason,
                        severity=self.severity,
                        mitre_tag=self.mitre_tag,
                        metadata={
                            "address":         address,
                            "value":           qval,
                            "replay_window_s": self.replay_window_s,
                            "now":             now,
                        },
                    )

            # ── Step 3: pass — record command ──────────────────────────────
            self._history.append((address, qval, now))

        return pass_result(
            self.rule_id,
            f"R008 PASS | (addr={address}, val={qval}) "
            f"not seen in last {self.replay_window_s:.1f}s",
        )

    def reset(self) -> None:
        """
        Clear replay history.

        Useful between test scenarios to prevent cross-contamination.
        Not needed in production — the window expires naturally.
        """
        with self._lock:
            self._history.clear()

    def snapshot(self) -> list[tuple[int, float, float]]:
        """
        Return a copy of history as (address, value, timestamp) triples.

        Intended for testing and diagnostics only.
        """
        with self._lock:
            return list(self._history)
