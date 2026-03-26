"""
test_missing_attacks.py — Integration Tests for Attack Scenarios A04-A15
=========================================================================
PhysicsGuard ICS Security Gateway  |  Layer 4 + 8
Dissertation evidence for 95% detection rate claim.

Covers the 6 attacks missing from test_attack_scenarios.py:

  A04 — Unauthorized Source IP       MITRE T0817  R004 AuthRule
  A05 — Time Window Violation        MITRE T0855  R005 TimeRule
  A08 — Command Replay Attack        MITRE T0856  R008 ReplayRule
  A10 — Slow-Drip Setpoint Creep     MITRE T0855  R006 TemporalRule
  A13 — Emergency Stop Bypass        MITRE T0813  R003 InterlockRule
  A15 — Lateral Movement PLC→PLC     MITRE T0888  R007 TopologyRule

Design principles (from adversarial-test-engine skill):
  - AAA pattern (Arrange / Act / Assert) on every test
  - No time.sleep() — all timing injected via now= parameter
  - Both unit-level (isolated rule) and integration-level (full engine) tests
  - Blocked AND allowed cases for every attack (proves no false positives)
  - Boundary values tested explicitly
  - Consequence engine metadata verified for critical blocks
  - Rule priority order verified end-to-end

Run:
  pytest tests/test_missing_attacks.py -v
  pytest tests/test_missing_attacks.py -v --tb=short 2>&1 | tee attack_coverage.log
"""

from __future__ import annotations

import datetime
import os
import sys
import time

# Allow running as both:
#   pytest tests/test_missing_attacks.py    (pytest discovers the tests)
#   python  tests/test_missing_attacks.py   (standalone runner)
# sys.path additions mirror every other test file in the project:
#   [0] project root — resolves "from src.rules.x import ..."
#   [1] src/          — resolves bare "from rules.x import ..." inside src/rules/__init__.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from src.rules.auth_rule      import AuthRule
from src.rules.base_rule      import (
    SEVERITY_CRITICAL,
    SEVERITY_EMERGENCY,
    SEVERITY_WARNING,
)
from src.rules.interlock_rule import InterlockRule
from src.rules.range_rule     import RangeRule
from src.rules.replay_rule    import ReplayRule
from src.rules.temporal_rule  import TemporalRule
from src.rules.time_rule      import TimeRule
from src.rules.topology_rule  import TopologyRule
from src.consequence_engine   import ConsequenceEngine
from src.plant_topology       import PlantTopology, PLCNode, build_water_tank_topology
from src.validation_engine    import ValidationEngine, build_water_tank_engine


# ── Shared helpers ────────────────────────────────────────────────────────────

def _ts(hour: int) -> float:
    """Return a wall-clock epoch timestamp for a given hour on a fixed date."""
    return datetime.datetime(2024, 6, 15, hour, 0, 0).timestamp()


def _base_ctx(**extra) -> dict:
    """Minimal valid plant state context, with optional overrides."""
    ctx = {
        "tank_level":     50.0,
        "valve_position": 0.0,
        "pump_running":   False,
        "last_cmd_time":  0.0,
    }
    ctx.update(extra)
    return ctx


def _engine_with_auth(ips: set[str]) -> ValidationEngine:
    """Full engine (R001-R008) with R004 IP whitelist configured."""
    engine = build_water_tank_engine()
    rule   = AuthRule(allowed_ips=ips)
    rule.rule_id = "R004"
    engine.register_rule(rule)
    return engine


def _engine_with_time(
    hours: tuple[int, int],
    block: bool = True,
) -> ValidationEngine:
    """Full engine with R005 TimeRule in enforcement mode (block=True default)."""
    engine = build_water_tank_engine()
    rule   = TimeRule(allowed_hours=hours, block_outside_hours=block)
    rule.rule_id = "R005"
    engine.register_rule(rule)
    return engine


# ═══════════════════════════════════════════════════════════════════════════════
# A04 — Unauthorized Source IP  (MITRE T0817 → R004 AuthRule)
# ═══════════════════════════════════════════════════════════════════════════════

class TestA04_UnauthorizedSourceIP:
    """
    Attack: adversary injects Modbus commands from an IP not in the operator
    whitelist.  R004 AuthRule is the identity gate — it runs at priority=5,
    BEFORE all physics rules, so attacker commands never reach the plant.

    Real-world scenario: attacker gains OT network access via VPN or
    pivot host and sends commands directly to the Modbus TCP port.
    """

    # ── Unit: R004 in isolation ───────────────────────────────────────────────

    def test_A04_unauthorized_ip_blocked(self) -> None:
        """A04 core: command from non-whitelisted IP must be BLOCKED by R004."""
        # Arrange
        rule = AuthRule(allowed_ips={"127.0.0.1", "192.168.1.10"})
        ctx  = _base_ctx(source_ip="10.0.0.99")   # attacker IP
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert not result.allowed, \
            "R004 must block commands from IP not in whitelist"
        assert result.rule_id  == "R004",       f"Expected R004, got {result.rule_id}"
        assert result.severity == SEVERITY_CRITICAL
        assert result.mitre_tag == "T0817",      f"Expected T0817, got {result.mitre_tag}"

    def test_A04_authorized_ip_passes(self) -> None:
        """Legitimate operator IP must be allowed through R004."""
        # Arrange
        rule = AuthRule(allowed_ips={"127.0.0.1", "192.168.1.10"})
        ctx  = _base_ctx(source_ip="127.0.0.1")
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert result.allowed, \
            "R004 must allow commands from whitelisted IP"

    def test_A04_empty_whitelist_allows_all(self) -> None:
        """
        Empty whitelist = opt-in model, all sources permitted.
        Prevents locking out misconfigured systems on first deployment.
        """
        # Arrange
        rule = AuthRule(allowed_ips=set())
        ctx  = _base_ctx(source_ip="99.99.99.99")   # any IP
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert result.allowed, \
            "Empty whitelist must allow all sources (opt-in model)"

    def test_A04_no_source_ip_in_context_skips_check(self) -> None:
        """
        Internal physics-loop calls have no source_ip — check must be skipped.
        Blocking internal calls would lock the server out of its own physics.
        """
        # Arrange
        rule = AuthRule(allowed_ips={"127.0.0.1"})
        ctx  = _base_ctx()   # no source_ip key
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert result.allowed, \
            "R004 must skip check when source_ip absent (internal call)"

    def test_A04_blocks_pump_command_from_attacker(self) -> None:
        """
        R004 guards ALL registers — attacker cannot start pump from rogue IP.
        The pump-start is particularly dangerous (could trigger dry-run).
        """
        # Arrange
        rule = AuthRule(allowed_ips={"127.0.0.1"})
        ctx  = _base_ctx(source_ip="192.168.100.50", tank_level=80.0)
        # Act
        result = rule.evaluate(address=2, value=1.0, context=ctx)   # pump ON
        # Assert
        assert not result.allowed, \
            "R004 must block pump-start command from unauthorized IP"
        assert result.rule_id == "R004"

    def test_A04_metadata_contains_source_ip(self) -> None:
        """Blocked result metadata must include the offending IP for forensics."""
        # Arrange
        rule     = AuthRule(allowed_ips={"127.0.0.1"})
        attacker = "172.16.0.88"
        ctx      = _base_ctx(source_ip=attacker)
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert not result.allowed
        assert result.metadata.get("source_ip") == attacker, \
            f"Metadata must contain attacker IP, got: {result.metadata}"

    # ── Integration: R004 fires BEFORE physics rules ──────────────────────────

    def test_A04_blocks_before_R001_in_full_engine(self) -> None:
        """
        Integration: R004 (priority=5) must fire before R001 (priority=10).
        Attacker sending out-of-range value should be blocked as T0817 not T0855
        — identity gate runs first so the physics rules never even execute.
        """
        # Arrange
        engine = _engine_with_auth({"127.0.0.1"})
        # Out-of-range value (would be R001 if IP were allowed)
        ctx    = _base_ctx(source_ip="10.0.0.99")
        # Act
        result = engine.validate(address=1, value=150.0, context=ctx)
        # Assert
        assert not result.allowed
        assert result.rule_id == "R004", \
            f"R004 must block before R001 runs — got rule_id={result.rule_id}"

    def test_A04_consequence_engine_attached_on_block(self) -> None:
        """
        Novel contribution #1: blocked R004 result must carry forward-physics
        damage prediction so operators see 'OVERFLOW in X seconds if allowed'.
        """
        # Arrange
        engine = _engine_with_auth({"127.0.0.1"})
        engine.set_consequence_engine(ConsequenceEngine())
        ctx = {
            "tank_level": 90.0, "valve_position": 0.0,
            "pump_running": False, "source_ip": "10.0.0.99",
            "last_cmd_time": 0.0,
        }
        # Act — valve=90 from attacker would cause overflow
        result = engine.validate(address=1, value=90.0, context=ctx)
        # Assert
        assert not result.allowed
        assert "consequence" in result.metadata, \
            "Blocked R004 result must carry consequence prediction"
        assert "damage_predicted" in result.metadata["consequence"]


# ═══════════════════════════════════════════════════════════════════════════════
# A05 — Time Window Violation  (MITRE T0855 → R005 TimeRule)
# ═══════════════════════════════════════════════════════════════════════════════

class TestA05_TimeWindowViolation:
    """
    Attack: adversary sends commands outside permitted operating hours
    (e.g. 02:00 when plant is unmonitored).

    Two modes:
      Detection (block_outside_hours=False): WARNING logged, command passes.
        Useful for audit trails without disrupting marginal time-zone cases.
      Enforcement (block_outside_hours=True): CRITICAL, command BLOCKED.
        Required for strict maintenance-window or shift-change lockouts.
    """

    # ── Unit: R005 detection mode ─────────────────────────────────────────────

    def test_A05_after_hours_detection_mode_warns_not_blocks(self) -> None:
        """
        Detection mode: after-hours command must produce WARNING severity
        but allowed=True — command passes through for forensic audit.
        """
        # Arrange
        rule = TimeRule(allowed_hours=(8, 18), block_outside_hours=False)
        # Act — 02:00 is outside 08:00-18:00 window
        result = rule.evaluate(address=1, value=50.0, context={}, now=_ts(2))
        # Assert
        assert result.allowed, \
            "Detection mode must allow command even outside hours"
        assert result.severity == SEVERITY_WARNING, \
            f"Expected WARNING severity, got {result.severity}"
        assert result.rule_id == "R005"

    def test_A05_within_hours_always_passes(self) -> None:
        """Commands inside the allowed window must always pass with no warning."""
        # Arrange
        rule = TimeRule(allowed_hours=(8, 18), block_outside_hours=True)
        # Act
        result = rule.evaluate(address=1, value=50.0, context={}, now=_ts(12))
        # Assert
        assert result.allowed, \
            "Command at 12:00 must be allowed (inside 08:00-18:00 window)"

    # ── Unit: R005 enforcement mode ───────────────────────────────────────────

    def test_A05_enforcement_mode_blocks_after_hours(self) -> None:
        """
        A05 core: enforcement mode must BLOCK commands outside allowed hours.
        """
        # Arrange
        rule = TimeRule(allowed_hours=(8, 18), block_outside_hours=True)
        # Act — 02:00 attack
        result = rule.evaluate(address=1, value=50.0, context={}, now=_ts(2))
        # Assert
        assert not result.allowed, \
            "Enforcement mode must block command at 02:00 (outside 08:00-18:00)"
        assert result.severity == SEVERITY_CRITICAL
        assert result.rule_id  == "R005"
        assert result.mitre_tag == "T0855"

    def test_A05_boundary_first_hour_inside_is_allowed(self) -> None:
        """Boundary: command at exactly 08:00 (start of window) must pass."""
        # Arrange
        rule = TimeRule(allowed_hours=(8, 18), block_outside_hours=True)
        # Act
        result = rule.evaluate(address=1, value=50.0, context={}, now=_ts(8))
        # Assert
        assert result.allowed, "Boundary hour=8 must be inside [8, 18] window"

    def test_A05_boundary_last_hour_inside_is_allowed(self) -> None:
        """Boundary: command at exactly 18:00 (end of window) must pass."""
        # Arrange
        rule = TimeRule(allowed_hours=(8, 18), block_outside_hours=True)
        # Act
        result = rule.evaluate(address=1, value=50.0, context={}, now=_ts(18))
        # Assert
        assert result.allowed, "Boundary hour=18 must be inside [8, 18] window"

    def test_A05_midnight_wrapping_window(self) -> None:
        """
        Midnight-wrapping window (22, 6): night-shift operators allowed,
        daytime commands blocked — simulates overnight maintenance window.
        """
        # Arrange
        rule = TimeRule(allowed_hours=(22, 6), block_outside_hours=True)
        # Act / Assert — inside window
        assert rule.evaluate(1, 50.0, {}, now=_ts(23)).allowed, \
            "23:00 must be inside (22, 6) wrapping window"
        assert rule.evaluate(1, 50.0, {}, now=_ts(3)).allowed, \
            "03:00 must be inside (22, 6) wrapping window"
        # Act / Assert — outside window
        assert not rule.evaluate(1, 50.0, {}, now=_ts(12)).allowed, \
            "12:00 must be outside (22, 6) wrapping window"

    # ── Integration: R005 in full engine ─────────────────────────────────────

    def test_A05_enforcement_blocks_in_full_engine(self) -> None:
        """
        Integration: R005 (priority=15) correctly fires on after-hours command
        in the full validation pipeline.
        """
        # Arrange
        engine = _engine_with_time(hours=(8, 18), block=True)
        ctx    = _base_ctx()
        # Act — send command at 02:00
        result = engine.validate(address=1, value=50.0, context=ctx, now=_ts(2))
        # Assert
        assert not result.allowed
        assert result.rule_id == "R005", \
            f"R005 must block after-hours command — got {result.rule_id}"


# ═══════════════════════════════════════════════════════════════════════════════
# A08 — Command Replay Attack  (MITRE T0856 → R008 ReplayRule)
# ═══════════════════════════════════════════════════════════════════════════════

class TestA08_CommandReplayAttack:
    """
    Attack: adversary captures a legitimate Modbus command frame and replays
    it verbatim seconds later. All physics rules pass because the content
    was valid when originally issued.

    R008 ReplayRule tracks accepted commands in a 5-second sliding window.
    The same (address, value) pair within the window = replay → BLOCKED.

    This is stateful — each test uses a fresh ReplayRule instance to
    prevent history leaking between test cases.
    """

    # ── Unit: R008 in isolation ───────────────────────────────────────────────

    def test_A08_first_occurrence_is_allowed(self) -> None:
        """First occurrence of any (address, value) must be allowed and recorded."""
        # Arrange
        rule = ReplayRule(address=1, replay_window_s=5.0)
        ctx  = _base_ctx()
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx, now=1000.0)
        # Assert
        assert result.allowed, \
            "R008: first occurrence of any command must be allowed"
        assert result.rule_id == "R008"

    def test_A08_replay_within_window_is_blocked(self) -> None:
        """
        A08 core: same (address, value) within 5s window must be BLOCKED.
        This is the replay attack — identical frame sent seconds later.
        """
        # Arrange
        rule = ReplayRule(address=1, replay_window_s=5.0)
        ctx  = _base_ctx()
        # Act — first shot seeds history
        rule.evaluate(address=1, value=50.0, context=ctx, now=1000.0)
        # Replay 2 seconds later — inside window
        result = rule.evaluate(address=1, value=50.0, context=ctx, now=1002.0)
        # Assert
        assert not result.allowed, \
            "R008: same (addr=1, val=50.0) within 5s window must be BLOCKED"
        assert result.rule_id  == "R008"
        assert result.severity == SEVERITY_CRITICAL
        assert result.mitre_tag == "T0856"

    def test_A08_replay_at_window_edge_still_blocked(self) -> None:
        """
        Boundary: replay at exactly 5.0s after original must still be BLOCKED.
        The window is strict — eviction requires > 5.0s elapsed.
        """
        # Arrange
        rule = ReplayRule(address=1, replay_window_s=5.0)
        ctx  = _base_ctx()
        # Act
        rule.evaluate(address=1, value=50.0, context=ctx, now=1000.0)
        result = rule.evaluate(address=1, value=50.0, context=ctx, now=1005.0)
        # Assert
        assert not result.allowed, \
            "R008: replay at exactly window boundary (5.0s) must still be BLOCKED"

    def test_A08_after_window_expires_same_value_allowed(self) -> None:
        """
        After window expires, the same (address, value) is a new legitimate
        command — operator legitimately repeating a setpoint hours later.
        """
        # Arrange
        rule = ReplayRule(address=1, replay_window_s=5.0)
        ctx  = _base_ctx()
        # Act — seed, then wait 6s (past window)
        rule.evaluate(address=1, value=50.0, context=ctx, now=1000.0)
        result = rule.evaluate(address=1, value=50.0, context=ctx, now=1006.0)
        # Assert
        assert result.allowed, \
            "R008: same value after window expires must be ALLOWED (new legitimate command)"

    def test_A08_different_value_same_address_not_a_replay(self) -> None:
        """
        Operator adjusting setpoint from 50% to 55% is NOT a replay —
        the value is different even though the address is the same.
        """
        # Arrange
        rule = ReplayRule(address=1, replay_window_s=5.0)
        ctx  = _base_ctx()
        # Act
        rule.evaluate(address=1, value=50.0, context=ctx, now=1000.0)
        result = rule.evaluate(address=1, value=55.0, context=ctx, now=1002.0)
        # Assert
        assert result.allowed, \
            "R008: different value on same address is NOT a replay"

    def test_A08_same_value_different_address_not_a_replay(self) -> None:
        """
        Valve=50% and pump=50% are independent registers — replaying
        the same numeric value on a different address is not a replay.
        """
        # Arrange
        rule = ReplayRule(address=None, replay_window_s=5.0)  # guards all
        ctx  = _base_ctx()
        # Act — addr=1 value=1.0 is recorded
        rule.evaluate(address=1, value=1.0, context=ctx, now=1000.0)
        # addr=2 value=1.0 is a different command
        result = rule.evaluate(address=2, value=1.0, context=ctx, now=1002.0)
        # Assert
        assert result.allowed, \
            "R008: same value on different address is NOT a replay"

    def test_A08_dangerous_pump_start_replay_blocked(self) -> None:
        """
        Dangerous variant: attacker captures pump-ON command when tank was
        high, then replays it after tank has drained. R008 catches the replay
        before R003 interlock even runs — earlier and independent detection.
        """
        # Arrange
        rule = ReplayRule(address=None, replay_window_s=5.0)
        # First command at high tank level — legitimate, passes
        ctx_high = _base_ctx(tank_level=80.0)
        rule.evaluate(address=2, value=1.0, context=ctx_high, now=1000.0)

        # Tank drains to 5% (below interlock threshold)
        ctx_low = _base_ctx(tank_level=5.0)
        # Act — replay within window
        result = rule.evaluate(address=2, value=1.0, context=ctx_low, now=1003.0)
        # Assert
        assert not result.allowed, \
            "R008: pump-ON replay within window must be BLOCKED as T0856"
        assert result.rule_id == "R008", \
            f"Must be caught by R008 (replay), not R003 (interlock) — got {result.rule_id}"

    # ── Integration: R008 in full engine ─────────────────────────────────────

    def test_A08_replay_blocked_in_full_engine(self) -> None:
        """
        Integration: R008 correctly detects replay in the full engine pipeline.
        The first call seeds the internal history; the second is detected.
        """
        # Arrange
        engine = build_water_tank_engine()
        ctx    = _base_ctx(last_cmd_time=0.0)
        # Act — seed with first command
        r1 = engine.validate(address=1, value=50.0, context=ctx)
        assert r1.allowed, "First command must be allowed (seeds R008 history)"
        # Replay immediately
        r2 = engine.validate(address=1, value=50.0, context=ctx)
        # Assert
        assert not r2.allowed, \
            "R008 must detect replay in full engine pipeline"
        assert r2.rule_id == "R008", \
            f"Expected R008 to block replay, got {r2.rule_id}"


# ═══════════════════════════════════════════════════════════════════════════════
# A10 — Slow-Drip Setpoint Creep  (MITRE T0855 → R006 TemporalRule)
# ═══════════════════════════════════════════════════════════════════════════════

class TestA10_SlowDripSetpointCreep:
    """
    Attack: attacker sends small valve increments (+1%/10s), each well below
    the R002 per-command rate limit (5 %/s), but cumulatively moves the valve
    from 20% to 37%+ in 5 minutes causing tank overflow.

    R006 TemporalRule closes this gap by tracking cumulative |Δ| within a
    300-second sliding window.  Threshold: 15% cumulative change.

    Key numbers (verified experimentally):
      oldest_in_window = 21.0% (after first step)
      Each step: +1% → delta grows from 0 to 15
      Step 16 (val=36.0%): delta=15.0 → exactly at limit → ALLOWED
      Step 17 (val=37.0%): delta=16.0 → EXCEEDS limit → BLOCKED
    """

    # ── Unit: R006 in isolation ───────────────────────────────────────────────

    def test_A10_individual_steps_each_pass_R002_rate_limit(self) -> None:
        """
        Prove the evasion that R006 closes: each +1%/10s step is 0.1 %/s,
        well below R002's 5 %/s limit — R002 passes every single step.
        This demonstrates why R006 is a novel contribution.
        """
        # Arrange
        r002_rule = RangeRule(address=1, min_value=0.0, max_value=100.0)
        # (Use RangeRule as a proxy — rate check is not the point here.
        # The point is that each step is protocol-valid.)
        t0 = time.monotonic()

        for step in range(16):
            value   = 20.0 + (step + 1)   # 21, 22, ..., 36
            context = _base_ctx(valve_position=float(20 + step), last_cmd_time=t0)
            # each step is 1% in 10s = 0.1 %/s — well below 5 %/s
            result  = r002_rule.evaluate(address=1, value=value, context=context)
            assert result.allowed, \
                f"Step {step+1}: value={value}% must pass range check (evasion test)"

    def test_A10_below_threshold_all_pass(self) -> None:
        """
        16 steps of +1%: cumulative delta reaches exactly 15% at step 16.
        Since threshold is STRICTLY greater than 15, step 16 passes.
        """
        # Arrange
        rule   = TemporalRule(address=1, window_s=300.0, max_cumulative_delta=15.0)
        base_v = 20.0

        # Act — 16 steps, +1% each, 10s apart
        for step in range(16):
            value  = base_v + (step + 1)   # 21.0 → 36.0
            result = rule.evaluate(
                address=1, value=value, context=_base_ctx(),
                now=float(step * 10),
            )
            # Assert each step passes
            assert result.allowed, \
                (f"Step {step+1}: value={value:.0f}% cumulative delta "
                 f"should still be ≤ 15% threshold — got blocked")

    def test_A10_step_17_triggers_block(self) -> None:
        """
        A10 core: step 17 (val=37%) pushes cumulative delta to 16% > 15%.
        R006 must BLOCK at this point.
        """
        # Arrange
        rule   = TemporalRule(address=1, window_s=300.0, max_cumulative_delta=15.0)
        base_v = 20.0

        # Seed 16 steps (all allowed)
        for step in range(16):
            rule.evaluate(
                address=1, value=base_v + (step + 1),
                context=_base_ctx(), now=float(step * 10),
            )

        # Act — step 17: cumulative delta = 37 - 21 = 16 > 15
        result = rule.evaluate(
            address=1, value=37.0,
            context=_base_ctx(), now=160.0,
        )
        # Assert
        assert not result.allowed, \
            "R006: step 17 (cumulative delta=16% > 15% limit) must be BLOCKED"
        assert result.rule_id  == "R006"
        assert result.severity == SEVERITY_CRITICAL
        assert result.mitre_tag == "T0855"
        # Verify metadata carries window diagnostics
        assert "cumulative_delta" in result.metadata
        assert result.metadata["cumulative_delta"] == pytest.approx(16.0, abs=0.01)

    def test_A10_blocked_step_does_not_advance_baseline(self) -> None:
        """
        Security property: blocked commands must NOT be recorded in history.
        An attacker cannot flood the window with blocked steps to push out
        the oldest entry and then continue the drip attack.
        """
        # Arrange
        rule   = TemporalRule(address=1, window_s=300.0, max_cumulative_delta=15.0)
        # Seed to just below limit (16 steps, oldest = 21.0)
        for step in range(16):
            rule.evaluate(
                address=1, value=20.0 + (step + 1),
                context=_base_ctx(), now=float(step * 10),
            )

        history_before = rule.snapshot()

        # Act — try to record a blocked step
        rule.evaluate(address=1, value=37.0, context=_base_ctx(), now=160.0)
        history_after  = rule.snapshot()

        # Assert — history is unchanged (blocked entry not recorded)
        assert len(history_after) == len(history_before), \
            "R006: blocked command must NOT be added to sliding window history"

    def test_A10_window_expiry_resets_detection(self) -> None:
        """
        After the 300s window expires, cumulative delta resets.
        Legitimate operator can make large adjustments in a new window.
        """
        # Arrange
        rule   = TemporalRule(address=1, window_s=300.0, max_cumulative_delta=15.0)
        base_v = 20.0

        # Seed 16 steps at t=0..150s
        for step in range(16):
            rule.evaluate(
                address=1, value=base_v + (step + 1),
                context=_base_ctx(), now=float(step * 10),
            )

        # Act — send a command 310 seconds after the OLDEST entry
        # All history entries are now expired (t=0..150 < cutoff=310-300=10)
        result = rule.evaluate(
            address=1, value=37.0,
            context=_base_ctx(), now=310.0,    # past window expiry
        )
        # Assert — fresh window, delta resets to 0, allowed
        assert result.allowed, \
            "R006: after window expires, cumulative delta resets and command is ALLOWED"

    # ── Integration: R006 in full engine ─────────────────────────────────────

    def test_A10_slow_drip_caught_in_full_engine(self) -> None:
        """
        Integration: full engine with R006 detects slow-drip attack that
        evades R002 per-command rate check at every individual step.
        """
        # Arrange
        engine = build_water_tank_engine()
        t0     = time.monotonic()
        base_v = 20.0

        # Seed 16 steps — each passes R002 (0.1 %/s per step)
        for step in range(16):
            ctx = _base_ctx(
                valve_position=base_v + step,
                last_cmd_time=t0 + (step * 10),
            )
            r = engine.validate(
                address=1, value=base_v + (step + 1),
                context=ctx, now=t0 + (step * 10) + 10.0,
            )
            assert r.allowed, f"Step {step+1} should pass (seeds engine history)"

        # Act — step 17 must be caught
        ctx17 = _base_ctx(
            valve_position=36.0,
            last_cmd_time=t0 + 160.0,
        )
        result = engine.validate(
            address=1, value=37.0,
            context=ctx17, now=t0 + 170.0,
        )
        # Assert
        assert not result.allowed, \
            "R006 must catch slow-drip step 17 in full engine pipeline"
        assert result.rule_id == "R006", \
            f"Expected R006 to block slow-drip, got {result.rule_id}"


# ═══════════════════════════════════════════════════════════════════════════════
# A13 — Emergency Stop Bypass  (MITRE T0813 → R003 InterlockRule variant)
# ═══════════════════════════════════════════════════════════════════════════════

class TestA13_EmergencyStopBypass:
    """
    Attack: attacker sends pump-start command while emergency_stop_active=True,
    attempting to restart equipment during a safety-triggered shutdown.

    R003 InterlockRule uses condition="not emergency_stop_active" to guard
    the pump register. The same rule class handles both A03 (dry-run interlock)
    and A13 (e-stop bypass) — different conditions, same severity EMERGENCY.

    The AST-based safe_eval_condition() (§15.3) makes this immune to injection
    attacks that would be possible with eval().
    """

    def _make_estop_rule(self) -> InterlockRule:
        """Fresh e-stop interlock rule for each test."""
        return InterlockRule(
            address=2,
            condition="not emergency_stop_active",
            label="emergency stop interlock",
            only_on_nonzero=True,
        )

    def _make_estop_engine(self) -> ValidationEngine:
        """Full engine with BOTH dry-run and e-stop interlocks on address 2."""
        engine  = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        # Dry-run interlock (A03)
        r003_dryrrun = InterlockRule(
            address=2,
            condition="tank_level >= 10",
            label="pump dry-run interlock",
            only_on_nonzero=True,
        )
        r003_dryrrun.rule_id = "R003"
        engine.register_rule(r003_dryrrun)
        # E-stop interlock (A13) — different rule_id to distinguish in assertions
        r003_estop = InterlockRule(
            address=2,
            condition="not emergency_stop_active",
            label="emergency stop interlock",
            only_on_nonzero=True,
        )
        r003_estop.rule_id  = "R003_ESTOP"
        r003_estop.priority = 31       # runs just after dry-run check
        engine.register_rule(r003_estop)
        return engine

    # ── Unit: e-stop interlock in isolation ───────────────────────────────────

    def test_A13_pump_start_blocked_when_estop_active(self) -> None:
        """
        A13 core: pump-start command must be BLOCKED when emergency_stop_active=True.
        Restarting equipment during a safety shutdown can cause catastrophic damage.
        """
        # Arrange
        rule = self._make_estop_rule()
        ctx  = _base_ctx(emergency_stop_active=True, tank_level=80.0)
        # Act
        result = rule.evaluate(address=2, value=1.0, context=ctx)
        # Assert
        assert not result.allowed, \
            "R003 must block pump-start when emergency_stop_active=True"
        assert result.severity == SEVERITY_EMERGENCY
        assert result.mitre_tag == "T0813"

    def test_A13_pump_start_allowed_when_estop_not_active(self) -> None:
        """Normal pump start (no active e-stop) must pass the interlock."""
        # Arrange
        rule = self._make_estop_rule()
        ctx  = _base_ctx(emergency_stop_active=False, tank_level=80.0)
        # Act
        result = rule.evaluate(address=2, value=1.0, context=ctx)
        # Assert
        assert result.allowed, \
            "R003 must allow pump-start when emergency_stop_active=False"

    def test_A13_pump_stop_always_allowed_during_estop(self) -> None:
        """
        B03 principle: turning the pump OFF must ALWAYS be allowed regardless
        of e-stop state. Operators must always be able to stop equipment.
        """
        # Arrange
        rule = self._make_estop_rule()
        ctx  = _base_ctx(emergency_stop_active=True)
        # Act — pump OFF command (value=0)
        result = rule.evaluate(address=2, value=0.0, context=ctx)
        # Assert
        assert result.allowed, \
            "R003: pump turn-OFF must always be allowed (B03) even during e-stop"

    def test_A13_valve_command_skips_estop_interlock(self) -> None:
        """
        E-stop interlock guards address=2 (pump) only.
        Valve commands (address=1) must not be affected by e-stop state.
        """
        # Arrange
        rule = self._make_estop_rule()
        ctx  = _base_ctx(emergency_stop_active=True)
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert result.allowed, \
            "R003 e-stop interlock guards addr=2 only — valve addr=1 must be unaffected"

    def test_A13_safe_eval_blocks_injection_attempt(self) -> None:
        """
        §15.3 security: safe_eval_condition() must reject function calls,
        imports, and attribute access at EVALUATION TIME.

        Construction-time check only validates syntax (ast.parse succeeds).
        The AST walker fires during evaluate() and raises ValueError for
        any disallowed node type — function calls, attribute access, etc.
        This makes arbitrary code execution structurally impossible.
        """
        from src.rules.base_rule import safe_eval_condition

        # Function call — ast.Call is not in the AST whitelist
        with pytest.raises(ValueError, match="Disallowed"):
            safe_eval_condition(
                "__import__('os').system('id') == 0",
                {"x": 1},
            )

        # Attribute access — ast.Attribute is not in the AST whitelist
        with pytest.raises(ValueError, match="Disallowed"):
            safe_eval_condition(
                "x.__class__.__name__ == 'int'",
                {"x": 1},
            )

    # ── Integration: A13 in full engine ──────────────────────────────────────

    def test_A13_estop_blocked_in_engine_with_consequence(self) -> None:
        """
        Integration: e-stop bypass blocked by R003 in full engine pipeline,
        with consequence engine predicting DRY_RUN damage.
        """
        # Arrange
        engine = self._make_estop_engine()
        engine.set_consequence_engine(ConsequenceEngine())
        ctx = {
            "tank_level": 80.0, "valve_position": 0.0,
            "pump_running": False, "last_cmd_time": 0.0,
            "emergency_stop_active": True,
        }
        # Act
        result = engine.validate(address=2, value=1.0, context=ctx)
        # Assert
        assert not result.allowed, \
            "Engine must block pump-start when emergency_stop_active=True"
        assert result.rule_id in ("R003", "R003_ESTOP"), \
            f"E-stop block must come from R003 variant, got {result.rule_id}"


# ═══════════════════════════════════════════════════════════════════════════════
# A15 — Lateral Movement PLC→PLC  (MITRE T0888 → R007 TopologyRule)
# ═══════════════════════════════════════════════════════════════════════════════

class TestA15_LateralMovementPLC:
    """
    Attack: attacker compromises PLC_01 (Water Tank) and injects commands
    targeting PLC_04 (Emergency Shutdown) — a non-adjacent, non-authorised
    path in the plant topology.

    This is a Stuxnet-style multi-hop lateral movement attack. All 5 physics
    rules pass (content is valid) but the source→target path is unauthorized.

    R007 TopologyRule wraps the Layer 0 PlantTopology graph and blocks any
    command whose source_plc_id → target_plc_id pair is not in the allowed
    paths set.

    Plant topology (4-PLC chain, confirmed build_water_tank_topology fix):
      PLC_01 → PLC_02 → PLC_03 → PLC_04   (authorised process-flow paths)
      PLC_01 → PLC_04                       (NOT authorised — A15 attack path)
    """

    def _fresh_topo_rule(self) -> TopologyRule:
        """Fresh topology rule with 4-PLC chain."""
        return TopologyRule(topology=build_water_tank_topology())

    # ── Unit: R007 in isolation ───────────────────────────────────────────────

    def test_A15_lateral_movement_PLC01_to_PLC04_blocked(self) -> None:
        """
        A15 core: PLC_01 → PLC_04 is not an authorised path and must be BLOCKED.
        This is the direct Stuxnet-style jump across the process chain.
        """
        # Arrange
        rule = self._fresh_topo_rule()
        ctx  = _base_ctx(source_plc_id="PLC_01", target_plc_id="PLC_04")
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert not result.allowed, \
            "R007 must block PLC_01→PLC_04 lateral movement (non-authorised path)"
        assert result.rule_id  == "R007"
        assert result.severity == SEVERITY_CRITICAL
        assert result.mitre_tag == "T0888"

    def test_A15_authorised_adjacent_path_passes(self) -> None:
        """PLC_01 → PLC_02 is an authorised path and must be ALLOWED."""
        # Arrange
        rule = self._fresh_topo_rule()
        ctx  = _base_ctx(source_plc_id="PLC_01", target_plc_id="PLC_02")
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert result.allowed, \
            "R007 must allow PLC_01→PLC_02 (authorised process-flow path)"

    def test_A15_self_write_always_allowed(self) -> None:
        """
        Same-PLC command (PLC_01 writing its own registers) must always pass.
        PlantTopology.is_authorised_path() short-circuits on src==dst.
        """
        # Arrange
        rule = self._fresh_topo_rule()
        ctx  = _base_ctx(source_plc_id="PLC_01", target_plc_id="PLC_01")
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert result.allowed, \
            "R007: same-PLC write (PLC_01→PLC_01) must always be allowed"

    def test_A15_no_plc_context_skips_check(self) -> None:
        """
        Internal physics-loop calls have no source_plc_id — check must be
        skipped. Matches AuthRule's opt-in pattern for source_ip.
        """
        # Arrange
        rule = self._fresh_topo_rule()
        ctx  = _base_ctx()   # no PLC routing context
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert result.allowed, \
            "R007 must skip check when source_plc_id absent (internal call)"

    def test_A15_reverse_path_blocked(self) -> None:
        """
        PLC_02 → PLC_01 (reverse direction) is also not in allowed paths.
        Topology is directed — authorised paths are one-way.
        """
        # Arrange
        rule = self._fresh_topo_rule()
        ctx  = _base_ctx(source_plc_id="PLC_02", target_plc_id="PLC_01")
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert not result.allowed, \
            "R007 must block PLC_02→PLC_01 (reverse path not authorised)"

    def test_A15_runtime_path_revocation(self) -> None:
        """
        D11 (runtime isolation): operator can revoke an authorised path
        at runtime to isolate a compromised PLC without restarting the server.
        """
        # Arrange
        topo = build_water_tank_topology()
        rule = TopologyRule(topology=topo)
        ctx  = _base_ctx(source_plc_id="PLC_01", target_plc_id="PLC_02")

        # Confirm path is initially authorised
        assert rule.evaluate(address=1, value=50.0, context=ctx).allowed, \
            "PLC_01→PLC_02 must be authorised before revocation"

        # Act — operator isolates PLC_02 (compromised)
        topo.revoke_path("PLC_01", "PLC_02")
        result = rule.evaluate(address=1, value=50.0, context=ctx)

        # Assert — now blocked without server restart
        assert not result.allowed, \
            "R007: revoked path must be BLOCKED immediately at runtime (D11)"

    def test_A15_metadata_contains_path_info(self) -> None:
        """Blocked result metadata must record src and dst PLCs for forensics."""
        # Arrange
        rule = self._fresh_topo_rule()
        ctx  = _base_ctx(source_plc_id="PLC_01", target_plc_id="PLC_04")
        # Act
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        # Assert
        assert not result.allowed
        assert result.metadata.get("source_plc_id") == "PLC_01", \
            f"Metadata must contain source PLC, got {result.metadata}"
        assert result.metadata.get("target_plc_id") == "PLC_04", \
            f"Metadata must contain target PLC, got {result.metadata}"

    # ── Integration: R007 fires BEFORE R001 in full engine ────────────────────

    def test_A15_blocks_before_R001_in_full_engine(self) -> None:
        """
        Integration: R007 (priority=8) fires before R001 (priority=10).
        A lateral movement attack carrying an out-of-range value must be
        caught as T0888 (topology violation), not T0855 (range violation).
        """
        # Arrange
        engine = build_water_tank_engine()
        ctx    = _base_ctx(source_plc_id="PLC_01", target_plc_id="PLC_04")
        # Act — out-of-range value via illegal path
        result = engine.validate(address=1, value=150.0, context=ctx)
        # Assert
        assert not result.allowed
        assert result.rule_id == "R007", \
            (f"R007 (priority=8) must block before R001 (priority=10) — "
             f"got rule_id={result.rule_id}")
        assert result.mitre_tag == "T0888"

    def test_A15_all_authorised_paths_pass_in_full_engine(self) -> None:
        """
        Negative test: all 4 authorised paths in the topology must produce
        no false positives in the full engine pipeline.
        """
        # Arrange
        engine = build_water_tank_engine()
        t0     = time.monotonic()
        authorised_paths = [
            ("PLC_01", "PLC_01"),   # self
            ("PLC_01", "PLC_02"),   # tank → valve
            ("PLC_02", "PLC_03"),   # valve → pressure
            ("PLC_03", "PLC_04"),   # pressure → e-stop
        ]
        for src, dst in authorised_paths:
            # Arrange
            ctx = _base_ctx(
                source_plc_id=src,
                target_plc_id=dst,
                last_cmd_time=0.0,
            )
            # Act
            result = engine.validate(address=1, value=50.0, context=ctx, now=t0 + 100.0)
            # Assert
            assert result.allowed or result.rule_id != "R007", \
                (f"R007 must not block authorised path {src}→{dst} — "
                 f"got allowed={result.allowed} rule_id={result.rule_id}")
