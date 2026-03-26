"""
test_validation.py  —  Layer 4 Validation Engine Unit Tests
============================================================
Layer 4  |  PhysicsGuard ICS Security Gateway
Week 3 deliverable: pure unit tests — no server, no network, no sleep().

Coverage:
  safe_eval_condition — AST evaluator: valid/invalid expressions
  RangeRule     (R001) — boundaries, wrong address, invalid config
  RateRule      (R002) — fast/slow, exact limit, dt<=0 blocking (D03),
                         clock anomaly escalation, no-baseline skip
  InterlockRule (R003) — condition met/unmet, turn-OFF always allowed,
                         eval-error fail-safe, chained comparison,
                         compound condition, bad syntax at construction
  ValidationEngine     — priority order, short-circuit, toggle, metrics,
                         consequence engine wiring, exception fail-safe
  Integration          — full engine A01/A02/A03 + normal operations
"""

from __future__ import annotations

import sys
import os
import time
import tempfile
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── pytest bridge ─────────────────────────────────────────────────────────────
# Makes the file runnable two ways:
#   pytest tests/test_validation.py   — normal pytest session
#   python tests/test_validation.py   — standalone, no pytest session needed
#
# Two problems solved:
#   1. pytest.raises() crashes outside a pytest session — replaced with our
#      own _StandaloneRaises that works as a plain context manager anywhere.
#   2. @pytest.mark.parametrize stores cases in fn.pytestmark (pytest internal
#      format) which varies by version — we intercept it and also store cases
#      in fn._standalone_params so _run_all() can always find them directly.

class _StandaloneRaises:
    """
    pytest.raises replacement that works when running standalone
    (python tests/test_validation.py) with OR without pytest installed.
    Real pytest's raises() requires an active pytest session — it breaks
    when called directly from a plain Python __main__ runner.
    """
    def __init__(self, exc_type, match: str = ""):
        self._exc_type = exc_type
        self._match    = match

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, tb):
        if exc_type is None:
            raise AssertionError(
                f"Expected {self._exc_type.__name__} — no exception raised"
            )
        if not issubclass(exc_type, self._exc_type):
            return False   # let unexpected exception propagate
        if self._match:
            import re as _re
            if not _re.search(self._match, str(exc_val)):
                raise AssertionError(
                    f"Exception {str(exc_val)!r} "
                    f"did not match pattern {self._match!r}"
                )
        return True        # suppress the expected exception


try:
    import pytest as _real_pytest

    class _PytestBridge:                        # type: ignore[no-redef]
        """
        Wraps real pytest so that:
          - pytest.raises      → our standalone-safe implementation
          - pytest.mark.parametrize → real pytest decorator PLUS sets
            fn._standalone_params so _run_all() can expand cases directly
        This means the file works correctly both as:
          pytest tests/test_validation.py   (full pytest session)
          python tests/test_validation.py   (standalone runner)
        """
        raises = _StandaloneRaises   # always use our safe implementation

        class mark:
            @staticmethod
            def parametrize(argnames, argvalues):
                real_deco = _real_pytest.mark.parametrize(argnames, argvalues)
                def decorator(fn):
                    fn = real_deco(fn)
                    fn._standalone_args   = argnames
                    fn._standalone_params = list(argvalues)
                    return fn
                return decorator

    pytest = _PytestBridge()                    # type: ignore[assignment]

except ModuleNotFoundError:
    class _FakePytest:                          # type: ignore[no-redef]
        """Full shim when pytest is not installed at all."""
        raises = _StandaloneRaises

        class mark:
            @staticmethod
            def parametrize(argnames, argvalues):
                def decorator(fn):
                    fn._standalone_args   = argnames
                    fn._standalone_params = list(argvalues)
                    return fn
                return decorator

    pytest = _FakePytest()                      # type: ignore[assignment]

from src.rules.base_rule import (
    RuleResult,
    safe_eval_condition,
    SEVERITY_CRITICAL,
    SEVERITY_EMERGENCY,
)
from src.rules.range_rule     import RangeRule
from src.rules.rate_rule      import RateRule
from src.rules.interlock_rule import InterlockRule
from src.validation_engine    import ValidationEngine, build_water_tank_engine


# ── safe_eval_condition ────────────────────────────────────────────────────────

class TestSafeEvalCondition:
    """§15.3: AST-based evaluator — no eval(), no __builtins__ bypass."""

    def test_simple_gte_true(self) -> None:
        # Arrange
        ctx = {"tank_level": 50.0}
        # Act
        result = safe_eval_condition("tank_level >= 10", ctx)
        # Assert
        assert result is True, "50 >= 10 must be True"

    def test_simple_gte_false(self) -> None:
        ctx = {"tank_level": 5.0}
        assert safe_eval_condition("tank_level >= 10", ctx) is False

    def test_exact_boundary(self) -> None:
        ctx = {"tank_level": 10.0}
        assert safe_eval_condition("tank_level >= 10", ctx) is True, \
            "Exactly 10 must satisfy >= 10"

    def test_bool_name_lookup(self) -> None:
        # Bare variable name used as bool condition
        ctx = {"pump_running": False}
        assert safe_eval_condition("pump_running", ctx) is False

    def test_not_operator(self) -> None:
        ctx = {"pump_running": False}
        assert safe_eval_condition("not pump_running", ctx) is True

    def test_and_compound(self) -> None:
        ctx = {"tank_level": 50.0, "valve_position": 30.0}
        assert safe_eval_condition(
            "tank_level >= 10 and valve_position < 50", ctx
        ) is True

    def test_or_compound_first_true(self) -> None:
        ctx = {"tank_level": 50.0, "valve_position": 80.0}
        # First branch true → whole condition true
        assert safe_eval_condition(
            "tank_level >= 10 or valve_position < 50", ctx
        ) is True

    def test_chained_comparison(self) -> None:
        # 5 < 50.0 < 95 — chained comparison
        ctx = {"tank_level": 50.0}
        assert safe_eval_condition("5 < tank_level < 95", ctx) is True

    def test_chained_comparison_fails_upper(self) -> None:
        ctx = {"tank_level": 96.0}
        assert safe_eval_condition("5 < tank_level < 95", ctx) is False

    def test_unknown_variable_raises_key_error(self) -> None:
        ctx = {"tank_level": 50.0}
        with pytest.raises(KeyError, match="undefined_var"):
            safe_eval_condition("undefined_var >= 10", ctx)

    def test_invalid_syntax_raises_value_error(self) -> None:
        ctx = {"tank_level": 50.0}
        with pytest.raises(ValueError):
            safe_eval_condition("tank_level >=", ctx)

    def test_disallowed_function_call_raises(self) -> None:
        # AST walker must reject ast.Call nodes
        ctx = {"tank_level": 50.0}
        with pytest.raises(ValueError, match="Disallowed"):
            safe_eval_condition("len(tank_level) > 0", ctx)

    def test_disallowed_string_literal_raises(self) -> None:
        ctx = {"x": 1.0}
        with pytest.raises(ValueError, match="numeric"):
            safe_eval_condition("x == 'hello'", ctx)


# ── RangeRule (R001) ──────────────────────────────────────────────────────────

class TestRangeRule:

    @pytest.mark.parametrize("value,should_block", [
        (150.0,    True),    # above max
        (100.001,  True),    # just above max (float)
        (-1.0,     True),    # below min
        (-0.001,   True),    # just below min (float)
        (100.0,    False),   # at max boundary — allowed
        (0.0,      False),   # at min boundary — allowed
        (50.0,     False),   # middle — allowed
    ])
    def test_boundaries(self, value: float, should_block: bool) -> None:
        # Arrange
        rule = RangeRule(address=1, min_value=0.0, max_value=100.0, label="valve %")
        # Act
        result = rule.evaluate(address=1, value=value, context={})
        # Assert
        assert result.allowed == (not should_block), (
            f"RangeRule expected {'block' if should_block else 'allow'} "
            f"for value={value}, got allowed={result.allowed}"
        )
        if should_block:
            assert result.rule_id == "R001", f"Expected R001, got {result.rule_id}"
            assert result.severity == SEVERITY_CRITICAL

    def test_skips_different_address(self) -> None:
        # Arrange
        rule = RangeRule(address=1, min_value=0.0, max_value=100.0)
        # Act — value 999 at wrong address
        result = rule.evaluate(address=2, value=999.0, context={})
        # Assert — rule for addr=1 must not affect addr=2
        assert result.allowed, \
            "Rule guarding addr=1 must not block writes to addr=2"

    def test_invalid_config_raises(self) -> None:
        # Arrange / Act / Assert
        with pytest.raises(ValueError, match="min_value.*max_value"):
            RangeRule(address=1, min_value=100.0, max_value=0.0)

    def test_metadata_contains_bounds_on_block(self) -> None:
        rule   = RangeRule(address=1, min_value=0.0, max_value=100.0)
        result = rule.evaluate(address=1, value=150.0, context={})
        assert "min_value" in result.metadata
        assert "max_value" in result.metadata
        assert result.metadata["value"] == 150.0


# ── RateRule (R002) ───────────────────────────────────────────────────────────

class TestRateRule:

    def _make_rule(self) -> RateRule:
        return RateRule(address=1, max_rate=5.0, context_key="valve_position")

    @pytest.mark.parametrize("delta,dt,should_block", [
        # rate = delta/dt vs limit 5.0 %/s
        (50.0,  1.0,   True),   # 50 %/s >> 5 %/s
        (100.0, 0.001, True),   # ~100000 %/s
        (5.0,   2.0,   False),  # 2.5 %/s — within limit
        (5.0,   1.0,   False),  # exactly 5.0 %/s — at limit, allowed
        (5.001, 1.0,   True),   # 5.001 %/s — just over limit
    ])
    def test_rate_boundaries(
        self,
        delta: float,
        dt: float,
        should_block: bool,
    ) -> None:
        # Arrange
        rule = self._make_rule()
        t0   = time.monotonic()
        ctx  = {"valve_position": 0.0, "last_cmd_time": t0}
        # Act
        result = rule.evaluate(address=1, value=delta, context=ctx, now=t0 + dt)
        # Assert
        assert result.allowed == (not should_block), (
            f"RateRule: delta={delta} dt={dt} → rate={delta/dt:.2f} %/s, "
            f"expected {'block' if should_block else 'allow'}, "
            f"got allowed={result.allowed}"
        )

    def test_skips_when_no_prior_timestamp(self) -> None:
        # Arrange — last_cmd_time=0.0 means first command ever
        rule   = self._make_rule()
        ctx    = {"valve_position": 0.0, "last_cmd_time": 0.0}
        # Act — 100 %/s jump; skipped because no baseline
        result = rule.evaluate(address=1, value=100.0, context=ctx)
        # Assert — first command: skip rate check
        assert result.allowed, \
            "First command (last_cmd_time=0) must skip rate check"

    def test_skips_different_address(self) -> None:
        rule = self._make_rule()
        t0   = time.monotonic()
        ctx  = {"valve_position": 0.0, "last_cmd_time": t0}
        result = rule.evaluate(address=2, value=999.0, context=ctx, now=t0 + 0.001)
        assert result.allowed, "Rule for addr=1 must skip addr=2"

    def test_dt_zero_blocks_critical(self) -> None:
        """D03: same monotonic tick → infinite rate → CRITICAL block."""
        # Arrange
        rule = self._make_rule()
        t0   = time.monotonic()
        ctx  = {"valve_position": 0.0, "last_cmd_time": t0}
        # Act — same tick (dt=0)
        result = rule.evaluate(address=1, value=5.0, context=ctx, now=t0)
        # Assert — must block, not skip
        assert not result.allowed, \
            "dt=0 (same tick) must be BLOCKED, not skipped (D03)"
        assert result.severity == SEVERITY_CRITICAL

    def test_dt_negative_escalates_to_emergency(self) -> None:
        """Clock anomaly (dt < 0) → EMERGENCY block."""
        # Arrange
        rule = self._make_rule()
        t0   = time.monotonic()
        ctx  = {"valve_position": 0.0, "last_cmd_time": t0}
        # Act — clock went backwards
        result = rule.evaluate(address=1, value=5.0, context=ctx, now=t0 - 1.0)
        # Assert
        assert not result.allowed, "Negative dt must be BLOCKED"
        assert result.severity == SEVERITY_EMERGENCY, \
            f"Clock anomaly must escalate to EMERGENCY, got {result.severity}"

    def test_invalid_max_rate_raises(self) -> None:
        with pytest.raises(ValueError, match="max_rate"):
            RateRule(address=1, max_rate=0.0, context_key="valve_position")

    def test_metadata_contains_rate_on_block(self) -> None:
        rule = self._make_rule()
        t0   = time.monotonic()
        ctx  = {"valve_position": 0.0, "last_cmd_time": t0}
        result = rule.evaluate(address=1, value=50.0, context=ctx, now=t0 + 1.0)
        assert not result.allowed
        assert "rate"    in result.metadata
        assert "max_rate" in result.metadata
        assert "dt"      in result.metadata


# ── InterlockRule (R003) ──────────────────────────────────────────────────────

class TestInterlockRule:

    def _make_rule(self) -> InterlockRule:
        return InterlockRule(
            address=2,
            condition="tank_level >= 10",
            label="dry-run interlock",
        )

    @pytest.mark.parametrize("level,value,should_block", [
        (5.0,   1.0, True),   # below threshold, pump-ON → blocked
        (9.9,   1.0, True),   # just below threshold → blocked
        (10.0,  1.0, False),  # exactly at threshold → allowed
        (50.0,  1.0, False),  # well above → allowed
        (0.0,   0.0, False),  # turn-OFF at empty tank → always allowed (B03)
        (5.0,   0.0, False),  # turn-OFF with level violation → still allowed
    ])
    def test_pump_interlock_boundaries(
        self,
        level: float,
        value: float,
        should_block: bool,
    ) -> None:
        # Arrange
        rule = self._make_rule()
        ctx  = {"tank_level": level}
        # Act
        result = rule.evaluate(address=2, value=value, context=ctx)
        # Assert
        assert result.allowed == (not should_block), (
            f"InterlockRule: level={level} value={value} → "
            f"expected {'block' if should_block else 'allow'}, "
            f"got allowed={result.allowed}"
        )
        if should_block:
            assert result.rule_id == "R003"
            assert result.severity == SEVERITY_EMERGENCY

    def test_skips_different_address(self) -> None:
        rule   = self._make_rule()
        ctx    = {"tank_level": 0.0}
        result = rule.evaluate(address=1, value=1.0, context=ctx)
        assert result.allowed, "Rule for addr=2 must skip addr=1"

    def test_unknown_variable_blocks_failsafe(self) -> None:
        """Condition referencing unknown variable → fail-safe BLOCK."""
        # Arrange
        rule   = InterlockRule(address=2, condition="undefined_sensor >= 10")
        ctx    = {"tank_level": 50.0}
        # Act
        result = rule.evaluate(address=2, value=1.0, context=ctx)
        # Assert — must block (fail-safe), not pass
        assert not result.allowed, \
            "Unknown variable in condition must fail SAFE (block)"

    def test_compound_condition(self) -> None:
        rule = InterlockRule(
            address=2,
            condition="tank_level >= 10 and valve_position < 80",
            label="compound interlock",
        )
        # Both conditions satisfied
        ctx = {"tank_level": 50.0, "valve_position": 30.0}
        assert rule.evaluate(address=2, value=1.0, context=ctx).allowed

        # Second condition fails
        ctx = {"tank_level": 50.0, "valve_position": 90.0}
        result = rule.evaluate(address=2, value=1.0, context=ctx)
        assert not result.allowed

    def test_chained_comparison_condition(self) -> None:
        rule = InterlockRule(
            address=2,
            condition="5 < tank_level < 95",
            label="safe range interlock",
        )
        # 5 < 50.0 < 95 → True
        ctx = {"tank_level": 50.0}
        assert rule.evaluate(address=2, value=1.0, context=ctx).allowed

        # 5 < 3.0 is False → chained fails
        ctx = {"tank_level": 3.0}
        assert not rule.evaluate(address=2, value=1.0, context=ctx).allowed

        # 5 < 5.0 is False in Python (not strictly less than) → fails
        ctx = {"tank_level": 5.0}
        assert not rule.evaluate(address=2, value=1.0, context=ctx).allowed

    def test_bad_syntax_raises_at_construction(self) -> None:
        """Invalid expression must fail at __init__, not at runtime."""
        with pytest.raises(ValueError, match="syntax"):
            InterlockRule(address=2, condition="tank_level >=")

    def test_empty_condition_raises_at_construction(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            InterlockRule(address=2, condition="   ")


# ── ValidationEngine ─────────────────────────────────────────────────────────

class TestValidationEngine:

    def test_runs_rules_in_priority_order(self) -> None:
        """R001 (priority=10) must execute before R002 (priority=20)."""
        # Arrange
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.register_rule(RateRule(address=1, max_rate=5.0, context_key="valve_position"))
        t0  = time.monotonic()
        ctx = {"valve_position": 0.0, "last_cmd_time": t0}
        # Act — 200 violates R001; also would violate R002 but R001 runs first
        result = engine.validate(address=1, value=200.0, context=ctx, now=t0 + 0.001)
        # Assert
        assert not result.allowed
        assert result.rule_id == "R001", \
            f"R001 must block before R002 runs, got rule_id={result.rule_id}"

    def test_short_circuit_on_critical_block(self) -> None:
        """After CRITICAL block from R001, R002 must NOT execute."""
        # Arrange
        execution_order: list[str] = []

        class TrackingRange(RangeRule):
            def evaluate(self, address, value, context, now=None):
                execution_order.append(self.rule_id)
                return super().evaluate(address, value, context, now)

        class TrackingRate(RateRule):
            def evaluate(self, address, value, context, now=None):
                execution_order.append(self.rule_id)
                return super().evaluate(address, value, context, now)

        engine = ValidationEngine()
        r1     = TrackingRange(address=1, min_value=0.0, max_value=100.0)
        r1.rule_id = "R001"
        r2     = TrackingRate(address=1, max_rate=5.0, context_key="valve_position")
        r2.rule_id = "R002"
        engine.register_rule(r1)
        engine.register_rule(r2)
        ctx = {"valve_position": 0.0, "last_cmd_time": time.monotonic()}

        # Act
        engine.validate(address=1, value=200.0, context=ctx)

        # Assert
        assert "R001" in execution_order, "R001 must have executed"
        assert "R002" not in execution_order, \
            "R002 must NOT execute after R001 blocks (short-circuit)"

    def test_all_rules_pass_returns_allowed(self) -> None:
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        ctx    = {"valve_position": 0.0, "last_cmd_time": 0.0}
        result = engine.validate(address=1, value=50.0, context=ctx)
        assert result.allowed, f"Valid command must pass, got: {result}"

    def test_no_rules_passes(self) -> None:
        engine = ValidationEngine()
        result = engine.validate(address=1, value=999.0, context={})
        assert result.allowed, "Engine with no rules must pass everything"

    def test_register_duplicate_raises(self) -> None:
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        with pytest.raises(ValueError, match="already registered"):
            engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))

    def test_register_empty_rule_id_raises(self) -> None:
        engine = ValidationEngine()
        rule   = RangeRule(address=1, min_value=0.0, max_value=100.0)
        rule.rule_id = ""
        with pytest.raises(ValueError, match="empty rule_id"):
            engine.register_rule(rule)

    def test_unregister_removes_rule(self) -> None:
        # Arrange
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        # Act
        engine.unregister_rule("R001")
        # Assert — 999 now passes because R001 is gone
        result = engine.validate(address=1, value=999.0, context={})
        assert result.allowed, "After unregister, out-of-range must pass"

    def test_unregister_unknown_raises(self) -> None:
        engine = ValidationEngine()
        with pytest.raises(KeyError, match="not registered"):
            engine.unregister_rule("NONEXISTENT")

    def test_disabled_rule_is_skipped(self) -> None:
        # Arrange
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.set_enabled("R001", False)
        # Act — 999 should pass (R001 disabled)
        result = engine.validate(address=1, value=999.0, context={})
        # Assert
        assert result.allowed, "Disabled rule must be skipped"

    def test_re_enable_rule_resumes_blocking(self) -> None:
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.set_enabled("R001", False)
        engine.set_enabled("R001", True)
        result = engine.validate(address=1, value=999.0, context={})
        assert not result.allowed, "Re-enabled rule must block again"

    def test_set_enabled_unknown_raises(self) -> None:
        engine = ValidationEngine()
        with pytest.raises(KeyError):
            engine.set_enabled("NONEXISTENT", False)

    def test_get_rules_returns_sorted_snapshot(self) -> None:
        engine = ValidationEngine()
        engine.register_rule(RateRule(address=1, max_rate=5.0, context_key="v"))
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        rules = engine.get_rules()
        assert len(rules) == 2
        assert rules[0]["rule_id"] == "R001", "R001 (priority=10) must come first"
        assert rules[1]["rule_id"] == "R002"
        assert "priority" in rules[0]
        assert "enabled"  in rules[0]

    def test_rule_exception_blocks_emergency(self) -> None:
        """Any rule exception must fail SAFE → EMERGENCY block."""
        # Arrange
        class BrokenRule(RangeRule):
            def evaluate(self, address, value, context, now=None):
                raise RuntimeError("simulated rule failure")

        engine = ValidationEngine()
        broken = BrokenRule(address=1, min_value=0.0, max_value=100.0)
        broken.rule_id = "R001"
        engine.register_rule(broken)
        # Act
        result = engine.validate(address=1, value=50.0, context={})
        # Assert
        assert not result.allowed, "Rule exception must block"
        assert result.severity == SEVERITY_EMERGENCY, \
            f"Rule exception must escalate to EMERGENCY, got {result.severity}"


# ── ValidationEngine metrics ──────────────────────────────────────────────────

class TestEngineMetrics:

    def test_metrics_count_allowed_and_blocked(self) -> None:
        # Arrange
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        # Act
        engine.validate(address=1, value=50.0, context={})   # allowed
        engine.validate(address=1, value=150.0, context={})  # blocked
        engine.validate(address=1, value=200.0, context={})  # blocked
        # Assert
        m = engine.get_metrics()
        assert m.total_evaluated == 3,    f"Expected 3 total, got {m.total_evaluated}"
        assert m.total_allowed   == 1,    f"Expected 1 allowed, got {m.total_allowed}"
        assert m.total_blocked   == 2,    f"Expected 2 blocked, got {m.total_blocked}"

    def test_metrics_block_rate(self) -> None:
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.validate(address=1, value=50.0, context={})   # allowed
        engine.validate(address=1, value=150.0, context={})  # blocked
        m = engine.get_metrics()
        assert abs(m.block_rate - 0.5) < 1e-9, \
            f"1 blocked / 2 total = 0.5, got {m.block_rate}"

    def test_metrics_blocked_by_rule(self) -> None:
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.validate(address=1, value=150.0, context={})
        engine.validate(address=1, value=200.0, context={})
        m = engine.get_metrics()
        assert m.blocked_by_rule.get("R001", 0) == 2, \
            f"R001 should have 2 blocks, got {m.blocked_by_rule}"

    def test_metrics_reset(self) -> None:
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.validate(address=1, value=150.0, context={})
        engine.reset_metrics()
        m = engine.get_metrics()
        assert m.total_evaluated == 0, "After reset, total must be 0"
        assert m.total_blocked   == 0

    def test_metrics_latency_recorded(self) -> None:
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        for _ in range(10):
            engine.validate(address=1, value=50.0, context={})
        m = engine.get_metrics()
        assert m.mean_latency_us > 0, "Mean latency must be positive"
        assert m.p99_latency_us  > 0, "P99 latency must be positive"

    def test_empty_engine_zero_block_rate(self) -> None:
        m = ValidationEngine().get_metrics()
        assert m.block_rate      == 0.0
        assert m.total_evaluated == 0


# ── ConsequenceEngine integration ─────────────────────────────────────────────

class TestConsequenceEngineWiring:
    """Novel contribution #1: blocked results carry forward damage prediction."""

    def test_blocked_result_carries_consequence_metadata(self) -> None:
        """
        When CE is wired, a blocked result must include
        result.metadata["consequence"] with damage prediction fields.
        """
        from src.consequence_engine import ConsequenceEngine

        # Arrange
        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.set_consequence_engine(ConsequenceEngine())

        ctx = {
            "tank_level":     90.0,  # high level — overflow likely if valve opened
            "valve_position": 0.0,
            "pump_running":   False,
        }

        # Act — valve=150 blocked by R001; CE predicts what would happen
        result = engine.validate(address=1, value=150.0, context=ctx)

        # Assert — blocked with consequence metadata
        assert not result.allowed, "R001 must still block"
        assert "consequence" in result.metadata, \
            "Blocked result must carry consequence prediction"

        c = result.metadata["consequence"]
        assert "damage_predicted"           in c
        assert "damage_type"                in c
        assert "predicted_time_to_damage_s" in c
        assert "description"                in c

    def test_allowed_result_has_no_consequence_metadata(self) -> None:
        from src.consequence_engine import ConsequenceEngine

        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.set_consequence_engine(ConsequenceEngine())

        ctx    = {"tank_level": 50.0, "valve_position": 0.0, "pump_running": False}
        result = engine.validate(address=1, value=50.0, context=ctx)

        assert result.allowed
        assert "consequence" not in result.metadata, \
            "Allowed results must not carry consequence metadata"

    def test_ce_exception_does_not_affect_block_decision(self) -> None:
        """CE crash must never change the block decision — CE is advisory only."""
        from src.consequence_engine import ConsequenceEngine

        class BrokenCE(ConsequenceEngine):
            def evaluate(self, *args, **kwargs):
                raise RuntimeError("CE exploded")

        engine = ValidationEngine()
        engine.register_rule(RangeRule(address=1, min_value=0.0, max_value=100.0))
        engine.set_consequence_engine(BrokenCE())

        # Act — R001 blocks (value=150); CE explodes
        result = engine.validate(address=1, value=150.0, context={
            "tank_level": 50.0, "valve_position": 0.0, "pump_running": False,
        })

        # Assert — still blocked, no exception propagated
        assert not result.allowed, "Block decision must survive CE crash"


# ── Integration: build_water_tank_engine + A01/A02/A03 ───────────────────────

class TestIntegration:

    @pytest.mark.parametrize("value,expected_rule", [
        (150.0, "R001"),   # A01: out of range
        (-1.0,  "R001"),   # A01: below min
    ])
    def test_A01_out_of_range_blocked(
        self, value: float, expected_rule: str
    ) -> None:
        """A01 — Out-of-Range Setpoint (MITRE T0855) blocked by R001."""
        engine = build_water_tank_engine()
        ctx    = {"valve_position": 0.0, "tank_level": 50.0, "last_cmd_time": 0.0}
        result = engine.validate(address=1, value=value, context=ctx)
        assert not result.allowed, f"A01: value={value} must be blocked"
        assert result.rule_id == expected_rule

    def test_A02_rapid_change_blocked(self) -> None:
        """A02 — Rapid Setpoint Change (MITRE T0855) blocked by R002."""
        # Arrange
        engine = build_water_tank_engine()
        t0     = time.monotonic()
        ctx    = {"valve_position": 0.0, "tank_level": 50.0, "last_cmd_time": t0}
        # Act — 100% jump in 0.1 s = 1000 %/s >> 5 %/s limit
        result = engine.validate(address=1, value=100.0, context=ctx, now=t0 + 0.1)
        # Assert
        assert not result.allowed, "A02: rapid valve change must be blocked"
        assert result.rule_id == "R002", \
            f"Expected R002, got {result.rule_id}"

    def test_A02_same_tick_blocked(self) -> None:
        """A02 variant: same monotonic tick (dt=0) → D03 → blocked."""
        engine = build_water_tank_engine()
        t0     = time.monotonic()
        ctx    = {"valve_position": 0.0, "tank_level": 50.0, "last_cmd_time": t0}
        result = engine.validate(address=1, value=5.0, context=ctx, now=t0)
        assert not result.allowed, "Same-tick command must be blocked (D03)"

    def test_A03_pump_interlock_blocked(self) -> None:
        """A03 — Pump Dry-Run Interlock Bypass (MITRE T0813) blocked by R003."""
        engine = build_water_tank_engine()
        ctx    = {"valve_position": 0.0, "tank_level": 5.0, "last_cmd_time": 0.0}
        result = engine.validate(address=2, value=1.0, context=ctx)
        assert not result.allowed, "A03: pump start at 5% must be blocked"
        assert result.rule_id == "R003", \
            f"Expected R003, got {result.rule_id}"
        assert result.severity == SEVERITY_EMERGENCY

    def test_A03_pump_stop_always_allowed(self) -> None:
        """B03: turning pump OFF must always be allowed regardless of level."""
        engine = build_water_tank_engine()
        ctx    = {"valve_position": 0.0, "tank_level": 0.0, "last_cmd_time": 0.0}
        result = engine.validate(address=2, value=0.0, context=ctx)
        assert result.allowed, \
            "Pump turn-OFF must always be allowed (B03 principle)"

    def test_normal_slow_valve_move_passes(self) -> None:
        """Normal operator command must pass all three rules."""
        engine = build_water_tank_engine()
        t0     = time.monotonic()
        ctx    = {"valve_position": 0.0, "tank_level": 50.0, "last_cmd_time": t0}
        # 5% in 2 seconds = 2.5 %/s — within 5 %/s limit
        result = engine.validate(address=1, value=5.0, context=ctx, now=t0 + 2.0)
        assert result.allowed, f"Normal slow valve move must pass, got: {result}"

    def test_pump_start_at_adequate_level_passes(self) -> None:
        engine = build_water_tank_engine()
        ctx    = {"valve_position": 0.0, "tank_level": 50.0, "last_cmd_time": 0.0}
        result = engine.validate(address=2, value=1.0, context=ctx)
        assert result.allowed, "Pump start at 50% level must pass"

    def test_first_valve_command_skips_rate_check(self) -> None:
        """First-ever valve command has no baseline — R002 skipped, R001 still runs."""
        engine = build_water_tank_engine()
        ctx    = {"valve_position": 0.0, "tank_level": 50.0, "last_cmd_time": 0.0}
        # 100 %/s would violate R002 — but first command skips rate
        result = engine.validate(address=1, value=5.0, context=ctx)
        assert result.allowed, \
            "First valve command must skip R002 rate check"


# ── AuthRule (R004) ───────────────────────────────────────────────────────────

import datetime

from src.rules.auth_rule import AuthRule
from src.rules.time_rule import TimeRule


class TestAuthRule:

    @pytest.mark.parametrize("source_ip,should_block", [
        ("127.0.0.1",    False),
        ("192.168.1.10", False),
        ("10.0.0.99",    True),
        ("0.0.0.0",      True),
    ])
    def test_ip_whitelist(self, source_ip: str, should_block: bool) -> None:
        rule   = AuthRule(allowed_ips={"127.0.0.1", "192.168.1.10"})
        ctx    = {"source_ip": source_ip, "tank_level": 50.0}
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        assert result.allowed == (not should_block), (
            f"ip={source_ip!r} expected {'block' if should_block else 'allow'}, "
            f"got allowed={result.allowed}"
        )
        if should_block:
            assert result.rule_id  == "R004"
            assert result.severity == SEVERITY_CRITICAL

    def test_no_source_ip_skips(self) -> None:
        rule   = AuthRule(allowed_ips={"127.0.0.1"})
        result = rule.evaluate(address=1, value=50.0, context={"tank_level": 50.0})
        assert result.allowed, "Missing source_ip must skip (internal call)"

    def test_empty_whitelist_allows_all(self) -> None:
        rule   = AuthRule(allowed_ips=set())
        ctx    = {"source_ip": "99.99.99.99"}
        assert rule.evaluate(address=1, value=50.0, context=ctx).allowed

    def test_none_whitelist_allows_all(self) -> None:
        rule   = AuthRule(allowed_ips=None)
        ctx    = {"source_ip": "99.99.99.99"}
        assert rule.evaluate(address=1, value=50.0, context=ctx).allowed

    def test_address_filter_skips_other_registers(self) -> None:
        rule   = AuthRule(allowed_ips={"127.0.0.1"}, address=1)
        ctx    = {"source_ip": "10.0.0.99"}
        result = rule.evaluate(address=2, value=1.0, context=ctx)
        assert result.allowed

    def test_priority_is_5(self) -> None:
        assert AuthRule(allowed_ips=set()).priority == 5

    def test_metadata_on_block(self) -> None:
        rule   = AuthRule(allowed_ips={"127.0.0.1"})
        ctx    = {"source_ip": "10.0.0.99"}
        result = rule.evaluate(address=1, value=50.0, context=ctx)
        assert not result.allowed
        assert result.metadata["source_ip"]  == "10.0.0.99"
        assert "allowed_ips" in result.metadata


# ── TimeRule (R005) ───────────────────────────────────────────────────────────

class TestTimeRule:

    def _ts(self, hour: int) -> float:
        return datetime.datetime(2024, 1, 15, hour, 0, 0).timestamp()

    @pytest.mark.parametrize("hour,inside", [
        (8,  True),
        (12, True),
        (18, True),
        (7,  False),
        (19, False),
        (2,  False),
    ])
    def test_detection_mode_never_blocks(self, hour: int, inside: bool) -> None:
        """Detection mode (default): outside hours = WARNING, still allowed=True."""
        rule   = TimeRule(allowed_hours=(8, 18), block_outside_hours=False)
        result = rule.evaluate(address=1, value=50.0, context={}, now=self._ts(hour))
        assert result.allowed is True, \
            f"Detection mode must always allow; hour={hour} got allowed=False"
        if not inside:
            assert result.severity == "WARNING"

    @pytest.mark.parametrize("hour,should_block", [
        (8,  False),
        (18, False),
        (7,  True),
        (19, True),
    ])
    def test_enforcement_mode_blocks(self, hour: int, should_block: bool) -> None:
        rule   = TimeRule(allowed_hours=(8, 18), block_outside_hours=True)
        result = rule.evaluate(address=1, value=50.0, context={}, now=self._ts(hour))
        assert result.allowed == (not should_block), \
            f"Enforcement hour={hour}: expected {'block' if should_block else 'allow'}"
        if should_block:
            assert result.severity == SEVERITY_CRITICAL
            assert result.rule_id  == "R005"

    def test_midnight_wrapping_window(self) -> None:
        rule = TimeRule(allowed_hours=(22, 6), block_outside_hours=True)
        assert rule.evaluate(1, 50.0, {}, now=self._ts(23)).allowed
        assert rule.evaluate(1, 50.0, {}, now=self._ts(3)).allowed
        assert not rule.evaluate(1, 50.0, {}, now=self._ts(12)).allowed

    def test_address_filter_skips(self) -> None:
        rule   = TimeRule(allowed_hours=(8, 18), address=1, block_outside_hours=True)
        result = rule.evaluate(address=2, value=1.0, context={}, now=self._ts(2))
        assert result.allowed

    def test_invalid_start_hour_raises(self) -> None:
        with pytest.raises(ValueError, match="start_hour"):
            TimeRule(allowed_hours=(25, 18))

    def test_invalid_end_hour_raises(self) -> None:
        with pytest.raises(ValueError, match="end_hour"):
            TimeRule(allowed_hours=(8, 25))

    def test_priority_is_15(self) -> None:
        assert TimeRule(allowed_hours=(8, 18)).priority == 15

    def test_metadata_on_outside_hours(self) -> None:
        rule   = TimeRule(allowed_hours=(8, 18), block_outside_hours=True)
        result = rule.evaluate(1, 50.0, {}, now=self._ts(2))
        assert not result.allowed
        assert result.metadata["current_hour"]  == 2
        assert result.metadata["allowed_hours"] == (8, 18)


# ── YAML loader ───────────────────────────────────────────────────────────────

class TestYamlLoader:

    def test_loads_all_5_rules(self, tmp_path=None) -> None:
        from src.validation_engine import load_rules_from_yaml
        import shutil, os, tempfile
        _td  = tempfile.mkdtemp() if tmp_path is None else None
        _dir = _td if _td else str(tmp_path)
        try:
            yaml_src = os.path.join(os.path.dirname(__file__), "..", "config", "rules.yaml")
            yaml_dst = os.path.join(_dir, "rules.yaml")
            shutil.copy(yaml_src, yaml_dst)
            engine   = load_rules_from_yaml(yaml_dst)
            rule_ids = {r["rule_id"] for r in engine.get_rules()}
            for rid in ("R001", "R002", "R003", "R004", "R005"):
                assert rid in rule_ids, f"{rid} not loaded from YAML"
            assert len(engine.get_rules()) == 5
        finally:
            if _td:
                shutil.rmtree(_td, ignore_errors=True)

    def test_yaml_priority_order(self, tmp_path=None) -> None:
        from src.validation_engine import load_rules_from_yaml
        import shutil, os, tempfile
        _td  = tempfile.mkdtemp() if tmp_path is None else None
        _dir = _td if _td else str(tmp_path)
        try:
            yaml_src = os.path.join(os.path.dirname(__file__), "..", "config", "rules.yaml")
            shutil.copy(yaml_src, os.path.join(_dir, "rules.yaml"))
            rules = load_rules_from_yaml(os.path.join(_dir, "rules.yaml")).get_rules()
            ids   = [r["rule_id"] for r in rules]
            assert ids == ["R004", "R001", "R005", "R002", "R003"], \
                f"Wrong priority order: {ids}"
        finally:
            if _td:
                shutil.rmtree(_td, ignore_errors=True)

    def test_unknown_type_raises(self, tmp_path=None) -> None:
        from src.validation_engine import load_rules_from_yaml
        import tempfile, os, shutil
        _td = tempfile.mkdtemp()
        try:
            bad = os.path.join(_td, "bad.yaml")
            with open(bad, "w") as _f:
                _f.write("rules:\n  - rule_id: R999\n    type: unknown_type\n")
            with pytest.raises(ValueError, match="unknown rule type"):
                load_rules_from_yaml(bad)
        finally:
            shutil.rmtree(_td, ignore_errors=True)


# ── R004 + R005 integration ───────────────────────────────────────────────────

class TestR004R005Integration:

    def test_auth_blocks_before_range(self) -> None:
        """R004 (priority=5) must fire before R001 (priority=10)."""
        engine = build_water_tank_engine()
        engine.register_rule(AuthRule(allowed_ips={"127.0.0.1"}))
        ctx    = {"source_ip": "10.0.0.99", "valve_position": 0.0,
                  "tank_level": 50.0, "last_cmd_time": 0.0}
        result = engine.validate(address=1, value=150.0, context=ctx)
        assert not result.allowed
        assert result.rule_id == "R004", \
            f"R004 must block before R001 runs, got {result.rule_id}"

    def test_time_detection_does_not_block_valid(self) -> None:
        engine = build_water_tank_engine()
        engine.register_rule(TimeRule(allowed_hours=(8, 18), block_outside_hours=False))
        ts  = datetime.datetime(2024, 1, 15, 2, 0, 0).timestamp()
        ctx = {"valve_position": 0.0, "tank_level": 50.0, "last_cmd_time": 0.0}
        result = engine.validate(address=1, value=5.0, context=ctx, now=ts)
        assert result.allowed, "Detection mode must not block valid command"

    def test_time_enforcement_blocks_after_hours(self) -> None:
        engine = build_water_tank_engine()
        engine.register_rule(TimeRule(allowed_hours=(8, 18), block_outside_hours=True))
        ts  = datetime.datetime(2024, 1, 15, 2, 0, 0).timestamp()
        ctx = {"valve_position": 0.0, "tank_level": 50.0, "last_cmd_time": 0.0}
        result = engine.validate(address=1, value=5.0, context=ctx, now=ts)
        assert not result.allowed
        assert result.rule_id == "R005"


# ── Standalone runner ─────────────────────────────────────────────────────────
# Runs when executed directly: python tests/test_validation.py
# Handles:
#   - Plain test methods (no arguments)
#   - @pytest.mark.parametrize methods (expanded into individual cases)
#   - Class-based tests (instantiates each class)
#   - Methods with tmp_path=None default (fixture already made standalone-safe)

def _run_all() -> None:
    import inspect

    test_classes = [
        TestSafeEvalCondition,
        TestRangeRule,
        TestRateRule,
        TestInterlockRule,
        TestValidationEngine,
        TestEngineMetrics,
        TestConsequenceEngineWiring,
        TestIntegration,
        TestAuthRule,
        TestTimeRule,
        TestYamlLoader,
        TestR004R005Integration,
    ]

    passed = failed = 0
    failures: list[str] = []

    for cls in test_classes:
        instance = cls()
        methods  = sorted(
            [name for name in dir(cls) if name.startswith("test_")]
        )

        for method_name in methods:
            method = getattr(instance, method_name)
            # Get the underlying function for attribute inspection —
            # bound methods don't carry decorator-set attributes like
            # _parametrize_values or pytestmark; the raw function does.
            fn = getattr(cls, method_name)

            # ── Resolve parametrize data ──────────────────────────────────────
            # _standalone_args / _standalone_params are set by our bridge
            # wrapper at decoration time, regardless of whether real pytest
            # or the shim ran. Both paths always set these attributes.
            p_argnames: str | None  = None
            p_values:   list | None = None

            if hasattr(fn, "_standalone_params"):
                p_argnames = fn._standalone_args
                p_values   = fn._standalone_params

            # ── Parametrized test ─────────────────────────────────────────────
            if p_argnames is not None and p_values is not None:
                argnames = [a.strip() for a in p_argnames.split(",")]
                for case in p_values:
                    values = case if isinstance(case, tuple) else (case,)
                    kwargs = dict(zip(argnames, values))
                    label  = (
                        f"{cls.__name__}.{method_name}"
                        f"[{','.join(str(v) for v in values)}]"
                    )
                    try:
                        method(**kwargs)
                        print(f"  ✅  {label}")
                        passed += 1
                    except Exception as exc:
                        print(f"  ❌  {label}")
                        print(f"      {type(exc).__name__}: {exc}")
                        failed += 1
                        failures.append(label)

            # ── Plain test ────────────────────────────────────────────────────
            else:
                label = f"{cls.__name__}.{method_name}"
                sig    = inspect.signature(method)
                params = [
                    p for p in sig.parameters.values()
                    if p.default is inspect.Parameter.empty
                ]
                if params:
                    # Required args with no default and not parametrized
                    # → pytest fixture we cannot supply standalone
                    print(f"  ⚠️   {label}  [skipped — requires pytest fixture]")
                    continue
                try:
                    method()
                    print(f"  ✅  {label}")
                    passed += 1
                except Exception as exc:
                    print(f"  ❌  {label}")
                    print(f"      {type(exc).__name__}: {exc}")
                    failed += 1
                    failures.append(label)

    print()
    print("=" * 62)
    print(f"  Results: {passed} passed / {failed} failed / {passed + failed} total")
    if failures:
        print(f"  Failed:")
        for f in failures:
            print(f"    • {f}")
    else:
        print("  ✅  All tests passed")
    print("=" * 62)

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    print()
    print("=" * 62)
    print("  PhysicsGuard — Validation Engine Unit Tests  |  Layer 4")
    print("  R001 RangeRule  R002 RateRule  R003 InterlockRule")
    print("  R004 AuthRule   R005 TimeRule  Engine + Metrics + CE")
    print("=" * 62)
    _run_all()
