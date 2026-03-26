"""
test_A09_oscillation.py  —  Unit + Integration Tests for A09 OscillationRule
==============================================================================
PhysicsGuard ICS Security Gateway  |  Layer 4
Tests for R009 OscillationRule — Setpoint Oscillation Attack (MITRE T0855).

Can be run standalone or appended into test_missing_attacks.py.

Coverage:
  - Core detection: 4 reversals in window → BLOCK
  - False-positive guard: smooth ramp never triggers
  - min_delta_pct noise filter: tiny moves ignored
  - Window expiry resets detection
  - Blocked commands do NOT advance history
  - Integration: R009 in full ValidationEngine pipeline
  - Boundary: exactly max_reversals fires, max_reversals-1 passes

Run:
  pytest tests/test_A09_oscillation.py -v
"""

from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from src.rules.oscillation_rule import OscillationRule
from src.rules.base_rule import SEVERITY_CRITICAL
from src.validation_engine import build_water_tank_engine


# ── Helpers ───────────────────────────────────────────────────────────────────

def _feed(rule: OscillationRule, values: list[float], step_s: float = 20.0) -> list:
    """Feed a sequence of values into the rule with equal time steps."""
    results = []
    t = 1000.0
    for v in values:
        results.append(rule.evaluate(address=1, value=v, context={}, now=t))
        t += step_s
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# A09 — Setpoint Oscillation (MITRE T0855 → R009 OscillationRule)
# ═══════════════════════════════════════════════════════════════════════════════

class TestA09_SetpointOscillation:
    """
    Attack: adversary (or malfunctioning SCADA controller) drives the valve
    back-and-forth repeatedly, each step below R002's per-command rate limit
    but mechanically stressing the actuator.

    Pattern: 20% → 80% → 20% → 80% → 20%  (4 direction reversals)
    Each step: 60%/20s = 3%/s — under R002 5%/s limit
    Net cumulative drift ≈ 0 — R006 is slow to respond
    R009 fires at the 5th command (4 reversals counted)
    """

    def _fresh_rule(self, **kw) -> OscillationRule:
        return OscillationRule(
            address=1,
            window_s=120.0,
            max_reversals=4,
            min_delta_pct=10.0,
            **kw,
        )

    # ── Core detection ────────────────────────────────────────────────────────

    def test_A09_oscillation_blocked_at_max_reversals(self) -> None:
        """
        A09 core: 4 direction reversals must trigger a BLOCK on the
        5th command (20→80→20→80→20).
        """
        # Arrange
        rule = self._fresh_rule()
        # Act — feed 4 alternating commands (builds up 3 reversals)
        for v in [20.0, 80.0, 20.0, 80.0]:
            r = rule.evaluate(address=1, value=v, context={}, now=1000.0 + v)
            assert r.allowed, f"Setup step val={v} must be allowed"

        # 5th command creates the 4th reversal → BLOCK
        result = rule.evaluate(address=1, value=20.0, context={}, now=1100.0)

        # Assert
        assert not result.allowed, (
            "R009: 4th direction reversal must BLOCK the oscillation attack"
        )
        assert result.rule_id  == "R009"
        assert result.severity == SEVERITY_CRITICAL
        assert result.mitre_tag == "T0855"
        assert result.metadata.get("reversals") == 4

    def test_A09_smooth_ramp_never_triggers(self) -> None:
        """
        A legitimate operator ramp (10→20→30→40→50→60→70) has 0 reversals
        and must never be blocked by R009.
        """
        # Arrange
        rule = self._fresh_rule()
        # Act
        results = _feed(rule, [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0])
        # Assert
        assert all(r.allowed for r in results), (
            "R009 must not block a smooth monotonic ramp (0 reversals)"
        )

    def test_A09_one_reversal_allowed(self) -> None:
        """
        A single direction change (normal setpoint adjustment) must be allowed.
        Example: operator ramps up then back down once — not oscillation.
        """
        # Arrange
        rule = self._fresh_rule(max_reversals=4)
        # Act — up then down (1 reversal)
        results = _feed(rule, [20.0, 50.0, 80.0, 50.0, 20.0])
        # Assert — 1 reversal is well under max_reversals=4
        assert all(r.allowed for r in results), (
            "Single direction change must be allowed (not oscillation)"
        )

    def test_A09_boundary_exactly_max_reversals_blocks(self) -> None:
        """
        Exactly max_reversals reversals must trigger a BLOCK.
        max_reversals=2: 20→80→20→80 creates 3 entries after first two,
        but the third reversal on the 4th entry triggers the block.
        """
        # Arrange — lower threshold to 2 reversals for faster test
        rule = OscillationRule(
            address=1, window_s=120.0, max_reversals=2, min_delta_pct=10.0
        )
        # Act
        rule.evaluate(address=1, value=20.0, context={}, now=1000.0)
        rule.evaluate(address=1, value=80.0, context={}, now=1020.0)
        rule.evaluate(address=1, value=20.0, context={}, now=1040.0)
        result = rule.evaluate(address=1, value=80.0, context={}, now=1060.0)
        # Assert
        assert not result.allowed, (
            "R009: max_reversals=2 must block at the 2nd reversal"
        )
        assert result.metadata.get("reversals") >= 2

    def test_A09_below_max_reversals_passes(self) -> None:
        """
        max_reversals-1 reversals must still pass.
        """
        # Arrange — max_reversals=4, feed 3 reversals
        rule = self._fresh_rule(max_reversals=4)
        # 20→80→20→80 = 3 reversals — should still pass
        for t_off, v in enumerate([20.0, 80.0, 20.0, 80.0]):
            result = rule.evaluate(
                address=1, value=v, context={}, now=1000.0 + t_off * 20
            )
            assert result.allowed, (
                f"R009: 3 reversals is under max_reversals=4 — must be ALLOWED"
                f" (step val={v})"
            )

    # ── Noise filter ──────────────────────────────────────────────────────────

    def test_A09_small_moves_below_min_delta_ignored(self) -> None:
        """
        Small adjustments below min_delta_pct must not count as direction changes.
        Operator fine-tuning (50→51→50→51→50) should not trigger R009.
        """
        # Arrange — min_delta_pct=10%, small moves = 1%
        rule = self._fresh_rule(min_delta_pct=10.0, max_reversals=2)
        # Act — 5 tiny alternating adjustments (each Δ=1%, below threshold)
        results = _feed(rule, [50.0, 51.0, 50.0, 51.0, 50.0], step_s=5.0)
        # Assert — noise filtered out → 0 significant reversals → all pass
        assert all(r.allowed for r in results), (
            "R009: small moves below min_delta_pct must not trigger oscillation"
        )

    def test_A09_moves_at_min_delta_boundary_count(self) -> None:
        """
        Moves exactly at min_delta_pct must count as direction changes.
        """
        # Arrange — min_delta_pct=10, moves of exactly 10
        rule = OscillationRule(
            address=1, window_s=120.0, max_reversals=2, min_delta_pct=10.0
        )
        # Act — 20→30→20→30 = 10% steps, 2 reversals
        rule.evaluate(address=1, value=20.0, context={}, now=1000.0)
        rule.evaluate(address=1, value=30.0, context={}, now=1020.0)
        rule.evaluate(address=1, value=20.0, context={}, now=1040.0)
        result = rule.evaluate(address=1, value=30.0, context={}, now=1060.0)
        # Assert
        assert not result.allowed, (
            "R009: moves >= min_delta_pct must count; 2 reversals at boundary must block"
        )

    # ── Window expiry ─────────────────────────────────────────────────────────

    def test_A09_window_expiry_resets_detection(self) -> None:
        """
        After window_s expires, old history is evicted and detection resets.
        Operator can legitimately return to a previous setpoint in a new window.
        """
        # Arrange — small window of 30s, feed 4 reversals inside it
        rule = OscillationRule(
            address=1, window_s=30.0, max_reversals=4, min_delta_pct=10.0
        )
        for t_off, v in enumerate([20.0, 80.0, 20.0, 80.0]):
            rule.evaluate(address=1, value=v, context={}, now=float(t_off * 5))

        # History is at t=0..15s. Jump to t=50s — all entries expired.
        result = rule.evaluate(address=1, value=20.0, context={}, now=50.0)

        # Assert — fresh window, 0 reversals, must pass
        assert result.allowed, (
            "R009: after window expiry history resets — command must be ALLOWED"
        )

    # ── History pollution prevention ──────────────────────────────────────────

    def test_A09_blocked_command_not_recorded(self) -> None:
        """
        Security property: blocked oscillation commands must NOT be added
        to history.  An attacker cannot use blocked commands to age out
        old history entries and restart the oscillation window.
        """
        # Arrange
        rule = OscillationRule(
            address=1, window_s=120.0, max_reversals=2, min_delta_pct=10.0
        )
        # Build up to max_reversals
        rule.evaluate(address=1, value=20.0, context={}, now=1000.0)
        rule.evaluate(address=1, value=80.0, context={}, now=1020.0)
        rule.evaluate(address=1, value=20.0, context={}, now=1040.0)

        history_before = rule.snapshot()

        # Act — trigger a block
        blocked = rule.evaluate(address=1, value=80.0, context={}, now=1060.0)
        assert not blocked.allowed, "Must be blocked to test history invariant"

        history_after = rule.snapshot()

        # Assert — history unchanged after block
        assert len(history_after) == len(history_before), (
            "R009: blocked command must NOT be added to sliding window history"
        )

    # ── Address filter ────────────────────────────────────────────────────────

    def test_A09_skips_different_address(self) -> None:
        """R009 guarding addr=1 must not affect writes to addr=2."""
        # Arrange
        rule = self._fresh_rule()
        # Act — many oscillating writes to addr=2
        results = [
            rule.evaluate(address=2, value=float(v), context={}, now=1000.0 + i * 20)
            for i, v in enumerate([20, 80, 20, 80, 20])
        ]
        # Assert — all pass (wrong address)
        assert all(r.allowed for r in results), (
            "R009 for addr=1 must not block writes to addr=2"
        )

    # ── Constructor validation ────────────────────────────────────────────────

    def test_A09_invalid_window_raises(self) -> None:
        with pytest.raises(ValueError, match="window_s"):
            OscillationRule(address=1, window_s=0.0)

    def test_A09_invalid_max_reversals_raises(self) -> None:
        with pytest.raises(ValueError, match="max_reversals"):
            OscillationRule(address=1, max_reversals=0)

    def test_A09_invalid_min_delta_raises(self) -> None:
        with pytest.raises(ValueError, match="min_delta_pct"):
            OscillationRule(address=1, min_delta_pct=-1.0)

    # ── Integration: R009 in full ValidationEngine ────────────────────────────

    def test_A09_oscillation_caught_in_full_engine(self) -> None:
        """
        Integration: full engine with R009 detects oscillation that evades
        R002 (per-command rate) on every individual step.
        """
        # Arrange
        engine = build_water_tank_engine()
        # Wire R009
        engine.register_rule(
            OscillationRule(address=1, window_s=120.0, max_reversals=4, min_delta_pct=10.0)
        )
        t0 = time.monotonic()

        # Feed 4 oscillating commands — each should pass R002 (3%/s < 5%/s)
        for i, val in enumerate([20.0, 80.0, 20.0, 80.0]):
            ctx = {
                "valve_position": val,
                "tank_level":     50.0,
                "last_cmd_time":  t0 + i * 20,
            }
            r = engine.validate(
                address=1, value=val, context=ctx, now=t0 + i * 20 + 20
            )
            # Each step passes R002 (rate = 60%/20s = 3%/s < 5%/s)
            # R009 accumulates reversals but doesn't fire until 4th reversal
            if not r.allowed and r.rule_id == "R009":
                break  # engine may fire earlier — that's fine, it's still caught

        # 5th command — must be caught by R009
        ctx5 = {
            "valve_position": 80.0,
            "tank_level":     50.0,
            "last_cmd_time":  t0 + 80,
        }
        result = engine.validate(
            address=1, value=20.0, context=ctx5, now=t0 + 100
        )

        # Assert — oscillation caught (either R009 or an earlier rule is fine,
        # but if it's allowed then R009 failed to detect the pattern)
        assert not result.allowed, (
            "Full engine must detect oscillation attack — "
            f"got allowed=True (rule_id={result.rule_id})"
        )
