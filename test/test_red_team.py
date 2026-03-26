"""
test_red_team.py  —  Unit tests for the Adversarial Red-Team Engine
Layer 8  |  PhysicsGuard ICS Security Gateway
Week 8 deliverable: ≥ 20 tests covering all five strategies, public API,
                    bypass detection, and MagicMock validator contract.
"""
import logging
from unittest.mock import MagicMock, patch

import pytest

from src.red_team import (
    BUILT_IN_STRATEGIES,
    SLOW_DRIP_STEPS,
    AttackResult,
    AttackVector,
    RedTeamEngine,
)

log = logging.getLogger(__name__)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_validator(allowed: bool = False) -> MagicMock:
    """
    Build a MagicMock ValidationEngine that returns a fixed ValidationResult.

    Args:
        allowed: Whether the mock result reports the command as allowed.

    Returns:
        Configured MagicMock with a ``validate`` method.
    """
    validator = MagicMock()
    result = MagicMock()
    result.allowed   = allowed
    result.rule_id   = "R001"
    result.severity  = "CRITICAL"
    result.reason    = "R001 RANGE VIOLATION | valve %=101.00 outside [0.0, 100.0]"
    result.mitre_tag = "T0855"
    validator.validate.return_value = result
    return validator


def _make_engine(allowed: bool = False, **kwargs) -> RedTeamEngine:
    """Convenience factory: validator + engine in one call."""
    return RedTeamEngine(validator=_make_validator(allowed), **kwargs)


# ── Category 1: Each strategy produces at least one vector ────────────────────

class TestStrategyGenerators:
    """Verify each mutation strategy generates ≥ 1 AttackVector."""

    def test_boundary_value_generates_at_least_one_vector(self) -> None:
        """boundary_value strategy must produce at least one probe."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run_strategy("boundary_value")

        # Assert
        assert len(results) >= 1, (
            "boundary_value must generate at least one AttackVector"
        )

    def test_rate_spike_generates_at_least_one_vector(self) -> None:
        """rate_spike strategy must produce at least one probe."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run_strategy("rate_spike")

        # Assert
        assert len(results) >= 1, (
            "rate_spike must generate at least one AttackVector"
        )

    def test_replay_generates_at_least_one_vector(self) -> None:
        """replay strategy must produce at least one probe."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run_strategy("replay")

        # Assert
        assert len(results) >= 1, (
            "replay must generate at least one AttackVector"
        )

    def test_slow_drip_generates_at_least_one_vector(self) -> None:
        """slow_drip strategy must produce at least one probe."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run_strategy("slow_drip")

        # Assert
        assert len(results) >= 1, (
            "slow_drip must generate at least one AttackVector"
        )

    def test_lateral_generates_at_least_one_vector(self) -> None:
        """lateral strategy must produce at least one probe."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run_strategy("lateral")

        # Assert
        assert len(results) >= 1, (
            "lateral must generate at least one AttackVector"
        )

    def test_slow_drip_generates_correct_step_count(self) -> None:
        """slow_drip must generate exactly SLOW_DRIP_STEPS probes."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run_strategy("slow_drip")

        # Assert
        assert len(results) == SLOW_DRIP_STEPS, (
            f"slow_drip must generate exactly {SLOW_DRIP_STEPS} steps, "
            f"got {len(results)}"
        )


# ── Category 2: bypass detection ──────────────────────────────────────────────

class TestBypassDetection:
    """found_bypass reflects whether the validator allowed the command."""

    def test_found_bypass_false_when_validator_blocks(self) -> None:
        """found_bypass must be False when the validator blocks the command."""
        # Arrange — validator blocks (allowed=False)
        engine = _make_engine(allowed=False)

        # Act
        results = engine.run_strategy("boundary_value")

        # Assert
        for r in results:
            assert r.found_bypass is False, (
                f"found_bypass must be False when validator blocks "
                f"(strategy={r.strategy}, addr={r.address}, val={r.value})"
            )

    def test_found_bypass_true_when_validator_allows(self) -> None:
        """
        found_bypass must be True when the validator allows attack probes.

        Design note — positive-control probes are excluded:
        _gen_boundary_value() includes two probes with "boundary probe" in
        their description (val=100.0, val=0.0). These are positive controls
        that verify the validator does NOT over-block at the safe boundary.
        Being allowed at val=100 or val=0 is CORRECT behaviour — not a bypass.
        The real attack probes (val=101, val=-1, val=150) are the ones that
        must be blocked, and if a defective validator allows them, those SHOULD
        show found_bypass=True.
        """
        # Arrange — validator allows (allowed=True → bypass for attack probes)
        engine = _make_engine(allowed=True)

        # Act
        results = engine.run_strategy("boundary_value")

        # Assert — attack probes must be found_bypass=True when allowed
        #          positive-control probes ("boundary probe") are exempt
        for r in results:
            is_positive_control = "boundary probe" in r.description
            if is_positive_control:
                # val=100.0 and val=0.0 — being allowed is correct; not a bypass
                assert r.found_bypass is False, (
                    f"Positive-control probe (val={r.value}) being allowed "
                    f"is CORRECT behaviour — must NOT be found_bypass=True"
                )
            else:
                # val=101, val=-1, val=150 — being allowed = validator is broken
                assert r.found_bypass is True, (
                    f"Attack probe (val={r.value}) allowed by defective validator "
                    f"must be found_bypass=True "
                    f"(strategy={r.strategy}, addr={r.address})"
                )


# ── Category 3: run() contract ────────────────────────────────────────────────

class TestRunContract:
    """Tests for the run() public method."""

    def test_run_returns_list_of_attack_results(self) -> None:
        """run(rounds=1) must return a non-empty list of AttackResult."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run(rounds=1)

        # Assert
        assert isinstance(results, list), (
            "run() must return a list"
        )
        assert len(results) > 0, (
            "run(rounds=1) must return at least one AttackResult"
        )
        assert all(isinstance(r, AttackResult) for r in results), (
            "Every element returned by run() must be an AttackResult"
        )

    def test_run_rounds_zero_raises_value_error(self) -> None:
        """run(rounds=0) must raise ValueError."""
        # Arrange
        engine = _make_engine()

        # Act / Assert
        with pytest.raises(ValueError, match="rounds must be >= 1"):
            engine.run(rounds=0)

    def test_run_rounds_negative_raises_value_error(self) -> None:
        """run(rounds=-1) must raise ValueError."""
        # Arrange
        engine = _make_engine()

        # Act / Assert
        with pytest.raises(ValueError, match="rounds must be >= 1"):
            engine.run(rounds=-1)

    def test_run_rounds_two_returns_exactly_double(self) -> None:
        """run(rounds=2) must return exactly 2× the results of run(rounds=1)."""
        # Arrange
        validator = _make_validator(allowed=False)
        engine = RedTeamEngine(validator=validator)

        # Act
        single = engine.run(rounds=1)
        double = engine.run(rounds=2)

        # Assert
        assert len(double) == 2 * len(single), (
            f"run(rounds=2) expected {2 * len(single)} results, "
            f"got {len(double)}"
        )

    def test_all_built_in_strategies_present_in_run(self) -> None:
        """run(rounds=1) must include results from every built-in strategy."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run(rounds=1)
        strategies_seen = {r.strategy for r in results}

        # Assert
        for strategy in BUILT_IN_STRATEGIES:
            assert strategy in strategies_seen, (
                f"Strategy '{strategy}' produced no results in run(rounds=1)"
            )


# ── Category 4: run_strategy() contract ───────────────────────────────────────

class TestRunStrategyContract:
    """Tests for the run_strategy() public method."""

    def test_run_strategy_returns_only_named_strategy_results(self) -> None:
        """run_strategy('boundary_value') must return only boundary_value results."""
        # Arrange
        engine = _make_engine()

        # Act
        results = engine.run_strategy("boundary_value")

        # Assert
        assert len(results) > 0, (
            "run_strategy('boundary_value') must return at least one result"
        )
        for r in results:
            assert r.strategy == "boundary_value", (
                f"Expected strategy='boundary_value', got '{r.strategy}'"
            )

    def test_run_strategy_nonexistent_raises_value_error(self) -> None:
        """run_strategy with an unknown name must raise ValueError."""
        # Arrange
        engine = _make_engine()

        # Act / Assert
        with pytest.raises(ValueError, match="Unknown strategy"):
            engine.run_strategy("nonexistent_strategy")

    def test_run_strategy_each_strategy_only_its_own_results(self) -> None:
        """run_strategy(s) results must all have strategy == s."""
        # Arrange
        engine = _make_engine()

        # Act / Assert
        for strategy in BUILT_IN_STRATEGIES:
            results = engine.run_strategy(strategy)
            for r in results:
                assert r.strategy == strategy, (
                    f"run_strategy('{strategy}') returned a result "
                    f"with strategy='{r.strategy}'"
                )


# ── Category 5: bypass_summary() contract ─────────────────────────────────────

class TestBypassSummary:
    """Tests for the bypass_summary() public method."""

    def test_bypass_summary_empty_when_no_bypasses(self) -> None:
        """bypass_summary must return {} when the validator blocks everything."""
        # Arrange
        engine = _make_engine(allowed=False)
        results = engine.run(rounds=1)

        # Act
        summary = engine.bypass_summary(results)

        # Assert
        assert summary == {}, (
            f"bypass_summary must be empty when validator blocks all, "
            f"got {summary}"
        )

    def test_bypass_summary_counts_bypasses_per_strategy(self) -> None:
        """bypass_summary must count found_bypass=True per strategy correctly."""
        # Arrange — build results manually with known bypass flags
        results = [
            AttackResult(
                strategy="boundary_value", address=1, value=101.0,
                context={}, description="over-range",
                allowed=True,  rule_id="R001", severity="CRITICAL",
                reason="range violation", mitre_tag="T0855",
                found_bypass=True,
            ),
            AttackResult(
                strategy="boundary_value", address=1, value=100.0,
                context={}, description="at-boundary",
                allowed=False, rule_id="R001", severity="CRITICAL",
                reason="range violation", mitre_tag="T0855",
                found_bypass=False,
            ),
            AttackResult(
                strategy="rate_spike", address=1, value=90.0,
                context={}, description="spike",
                allowed=True,  rule_id="R002", severity="HIGH",
                reason="rate violation", mitre_tag="T0855",
                found_bypass=True,
            ),
        ]
        engine = _make_engine()

        # Act
        summary = engine.bypass_summary(results)

        # Assert
        assert summary.get("boundary_value") == 1, (
            f"Expected boundary_value bypass count 1, "
            f"got {summary.get('boundary_value')}"
        )
        assert summary.get("rate_spike") == 1, (
            f"Expected rate_spike bypass count 1, "
            f"got {summary.get('rate_spike')}"
        )
        assert "slow_drip" not in summary, (
            "slow_drip had no bypasses and must not appear in summary"
        )

    def test_bypass_summary_multiple_strategies_all_bypass(self) -> None:
        """bypass_summary counts correctly when every probe bypasses."""
        # Arrange — validator allows everything
        engine = _make_engine(allowed=True)
        results = engine.run(rounds=1)

        # Act
        summary = engine.bypass_summary(results)

        # Assert
        for strategy in BUILT_IN_STRATEGIES:
            assert strategy in summary, (
                f"Strategy '{strategy}' should appear in summary when "
                "all probes bypass"
            )
            assert summary[strategy] > 0, (
                f"Strategy '{strategy}' bypass count should be > 0 "
                "when validator allows all"
            )


# ── Category 6: validator call contract ───────────────────────────────────────

class TestValidatorCallContract:
    """Verify the validator is called correctly per AttackVector."""

    def test_validator_called_exactly_once_per_attack_vector(self) -> None:
        """validate() must be called exactly once for each AttackVector."""
        # Arrange
        validator = _make_validator(allowed=False)
        engine = RedTeamEngine(validator=validator)

        # Count vectors by running each strategy independently
        total_vectors = sum(
            len(engine.run_strategy(s)) for s in BUILT_IN_STRATEGIES
        )
        call_count_after_strategies = validator.validate.call_count

        # Reset and run via run() to count again
        validator.validate.reset_mock()

        # Act
        engine.run(rounds=1)

        # Assert
        assert validator.validate.call_count == call_count_after_strategies, (
            f"run(rounds=1) should call validate() "
            f"{call_count_after_strategies} times (once per AttackVector), "
            f"got {validator.validate.call_count}"
        )

    def test_validate_called_with_correct_signature(self) -> None:
        """validate() must be called with (address=, value=, context=) kwargs."""
        # Arrange
        validator = _make_validator(allowed=False)
        engine = RedTeamEngine(validator=validator)

        # Act
        engine.run_strategy("boundary_value")

        # Assert — every call used keyword arguments
        for call_args in validator.validate.call_args_list:
            kwargs = call_args.kwargs
            assert "address" in kwargs, (
                "validate() must be called with keyword arg 'address'"
            )
            assert "value" in kwargs, (
                "validate() must be called with keyword arg 'value'"
            )
            assert "context" in kwargs, (
                "validate() must be called with keyword arg 'context'"
            )


# ── Category 7: AttackResult field completeness ───────────────────────────────

class TestAttackResultFields:
    """All AttackResult fields must be populated from the validator response."""

    def test_all_attack_result_fields_populated(self) -> None:
        """Every AttackResult field must be non-None after firing a probe."""
        # Arrange
        engine = _make_engine(allowed=False)

        # Act
        results = engine.run_strategy("boundary_value")

        # Assert
        required_fields = [
            "strategy", "address", "value", "context", "description",
            "allowed", "rule_id", "severity", "reason", "mitre_tag",
            "found_bypass",
        ]
        for r in results:
            for field in required_fields:
                assert getattr(r, field) is not None, (
                    f"AttackResult.{field} must not be None "
                    f"(addr={r.address}, val={r.value})"
                )

    def test_attack_result_fields_match_validator_response(self) -> None:
        """rule_id, severity, reason, mitre_tag must come from validator."""
        # Arrange
        validator = _make_validator(allowed=False)
        engine = RedTeamEngine(validator=validator)

        # Act
        results = engine.run_strategy("boundary_value")

        # Assert — fields must match what the mock returns
        for r in results:
            assert r.rule_id   == "R001",    f"rule_id mismatch for val={r.value}"
            assert r.severity  == "CRITICAL", f"severity mismatch for val={r.value}"
            assert r.mitre_tag == "T0855",   f"mitre_tag mismatch for val={r.value}"


# ── Category 8: custom strategies override ────────────────────────────────────

class TestCustomStrategies:
    """Passing a custom strategies list to __init__ overrides the defaults."""

    def test_custom_strategies_override_built_in_defaults(self) -> None:
        """Only the supplied strategies should run when overriding defaults."""
        # Arrange
        engine = _make_engine(strategies=["boundary_value", "rate_spike"])

        # Act
        results = engine.run(rounds=1)
        strategies_seen = {r.strategy for r in results}

        # Assert
        assert "boundary_value" in strategies_seen, (
            "boundary_value should be present when included in custom list"
        )
        assert "rate_spike" in strategies_seen, (
            "rate_spike should be present when included in custom list"
        )
        for excluded in ("replay", "slow_drip", "lateral"):
            assert excluded not in strategies_seen, (
                f"'{excluded}' must not run when excluded from custom list"
            )

    def test_unknown_custom_strategy_raises_value_error(self) -> None:
        """Passing an unknown strategy name to __init__ must raise ValueError."""
        # Arrange / Act / Assert
        with pytest.raises(ValueError, match="Unknown strategy names"):
            RedTeamEngine(
                validator=_make_validator(),
                strategies=["boundary_value", "does_not_exist"],
            )

    def test_single_strategy_in_custom_list(self) -> None:
        """A single-element custom strategies list must work correctly."""
        # Arrange
        engine = _make_engine(strategies=["lateral"])

        # Act
        results = engine.run(rounds=1)

        # Assert
        assert all(r.strategy == "lateral" for r in results), (
            "With strategies=['lateral'], every result must have strategy='lateral'"
        )
