"""
test_water_tank.py  —  WaterTankController Unit Tests
======================================================
Layer 1  |  PhysicsGuard ICS Security Gateway
Week 1 deliverable: pure unit tests — no Modbus server, no network.

Test naming convention:
    test_<target>_<condition>_<expected_outcome>

Rules tested:
    R001 — Range:     valve outside [0, 100] is blocked
    R002 — Rate:      valve change exceeding 5 %/s is blocked
    R003 — Interlock: pump start with low tank is blocked

Physics tested:
    update_physics fills/drains correctly
    overflow safety force-closes valve AND resets rate timer (B11)
    drain-out safety stops pump

Injected time (now= parameter) prevents any time.sleep() in unit tests.
Every assert includes a failure message.

Design-fix notes:
  D03 — test_valve_rate_check_dt_zero_is_blocked: same-tick commands must
        be treated as infinite rate and blocked (not silently skipped).
  D17 — Tests use _seed_state() instead of direct _pump_running mutation.
  D18 — _run_all() discovers tests via introspection; no manual list.
"""

import time
import sys
import os

# Allow running as: python tests/test_water_tank.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.water_tank import WaterTankController


# ── Helpers ────────────────────────────────────────────────────────────────────

def make_tank(**kwargs) -> WaterTankController:
    """Create a WaterTankController; override any constant via kwargs."""
    return WaterTankController(**kwargs)


# ── Construction / validation ──────────────────────────────────────────────────

def test_construction_default_state_is_valid() -> None:
    tank = make_tank()
    state = tank.get_state()
    assert state["tank_level"] == 50.0, f"Expected 50.0 got {state['tank_level']}"
    assert state["valve_position"] == 0.0, f"Expected 0.0 got {state['valve_position']}"
    assert state["pump_running"] is False, "Pump should be off at startup"


def test_construction_invalid_capacity_raises() -> None:
    try:
        make_tank(TANK_CAPACITY_LITERS=0.0)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_construction_invalid_overflow_raises() -> None:
    try:
        make_tank(OVERFLOW_LEVEL=110.0)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


def test_construction_dryrun_above_overflow_raises() -> None:
    try:
        make_tank(DRY_RUN_LEVEL=96.0, OVERFLOW_LEVEL=95.0)
        assert False, "Should have raised ValueError"
    except ValueError:
        pass


# ── R001: Range rule ────────────────────────────────────────────────────────────

def test_valve_above_100_is_blocked() -> None:
    tank = make_tank()
    result = tank.set_valve_position(150.0)
    assert not result["allowed"], "Valve 150% must be blocked"
    assert result.get("rule_id") == "R001", f"Wrong rule: {result.get('rule_id')}"
    assert tank.get_state()["valve_position"] == 0.0, "Valve must remain unchanged"


def test_valve_below_0_is_blocked() -> None:
    tank = make_tank()
    result = tank.set_valve_position(-1.0)
    assert not result["allowed"], "Valve -1% must be blocked"
    assert result.get("rule_id") == "R001", f"Wrong rule: {result.get('rule_id')}"


def test_valve_at_exactly_0_is_allowed() -> None:
    tank = make_tank()
    result = tank.set_valve_position(0.0)
    assert result["allowed"], "Valve 0% must be allowed"
    assert tank.get_state()["valve_position"] == 0.0, "Valve must be 0.0"


def test_valve_at_exactly_100_is_allowed() -> None:
    tank = make_tank()
    result = tank.set_valve_position(100.0)
    assert result["allowed"], "Valve 100% must be allowed"
    assert tank.get_state()["valve_position"] == 100.0, "Valve must be 100.0"


def test_valve_at_50_is_allowed() -> None:
    tank = make_tank()
    result = tank.set_valve_position(50.0)
    assert result["allowed"], "Valve 50% must be allowed"
    assert tank.get_state()["valve_position"] == 50.0, "Valve must be 50.0"


# ── R002: Rate rule ─────────────────────────────────────────────────────────────

def test_valve_rapid_change_in_short_time_is_blocked() -> None:
    """
    Move valve 0 → 50 in 1 second: rate = 50 %/s > 5 %/s limit.
    Uses injected 'now' timestamps to avoid time.sleep().
    """
    tank = make_tank()
    t0 = time.monotonic()

    # First command: set valve to 0% (establishes rate-limit baseline)
    tank.set_valve_position(0.0, now=t0)

    # Second command: try to jump to 50% after only 1 second
    # rate = |50 - 0| / 1.0 = 50 %/s > 5 %/s limit
    result = tank.set_valve_position(50.0, now=t0 + 1.0)

    assert not result["allowed"], (
        f"Rapid valve change should be blocked, got allowed=True, reason={result}"
    )
    assert result.get("rule_id") == "R002", f"Wrong rule: {result.get('rule_id')}"
    # Valve must still be at 0 (unchanged)
    assert tank.get_state()["valve_position"] == 0.0, (
        f"Valve must remain 0.0 after blocked command, "
        f"got {tank.get_state()['valve_position']}"
    )


def test_valve_slow_change_over_enough_time_is_allowed() -> None:
    """
    Move valve 0 → 5% in 2 seconds: rate = 2.5 %/s < 5 %/s limit.
    """
    tank = make_tank()
    t0 = time.monotonic()

    tank.set_valve_position(0.0, now=t0)
    result = tank.set_valve_position(5.0, now=t0 + 2.0)

    assert result["allowed"], (
        f"Slow valve change should be allowed, got blocked, reason={result}"
    )
    assert tank.get_state()["valve_position"] == 5.0, (
        f"Valve must be 5.0 after allowed command, "
        f"got {tank.get_state()['valve_position']}"
    )


def test_valve_first_command_skips_rate_check() -> None:
    """
    The very first valve command has no prior timestamp, so rate check is skipped.
    This is correct: attacker cannot exploit this since R001 still applies.
    """
    tank = make_tank()
    # Jump to 80% on first command — no prior time to calculate rate from
    result = tank.set_valve_position(80.0)
    assert result["allowed"], (
        "First valve command should always pass rate check (no baseline)"
    )


def test_valve_exact_rate_limit_boundary_allowed() -> None:
    """
    Rate = exactly 5.0 %/s is allowed (boundary condition — inclusive ≤).
    Move 0 → 5% in exactly 1.0 second.
    """
    tank = make_tank()
    t0 = time.monotonic()
    tank.set_valve_position(0.0, now=t0)
    result = tank.set_valve_position(5.0, now=t0 + 1.0)
    assert result["allowed"], (
        f"Rate at exactly limit (5.0 %/s) should be allowed, got {result}"
    )



def test_valve_rate_check_dt_zero_is_blocked() -> None:
    """
    D03 fix: two commands at the exact same monotonic timestamp (dt == 0)
    must be treated as infinite rate and blocked, not silently skipped.
    """
    tank = make_tank()
    t0 = time.monotonic()
    tank.set_valve_position(0.0, now=t0)
    result = tank.set_valve_position(1.0, now=t0)   # same timestamp → dt=0 → inf rate
    assert not result["allowed"], (
        "dt==0 (same timestamp) must be blocked as infinite rate, "
        f"got allowed=True: {result}"
    )
    assert result.get("rule_id") == "R002", (
        f"Expected R002 to block dt==0 command, got {result.get('rule_id')}"
    )


# ── R003: Pump interlock ─────────────────────────────────────────────────────────

def test_pump_start_when_tank_low_is_blocked() -> None:
    """Pump start blocked when tank below 10%."""
    tank = make_tank(INITIAL_LEVEL=5.0)
    result = tank.set_pump_state(True)
    assert not result["allowed"], (
        f"Pump start at 5% level must be blocked, got {result}"
    )
    assert result.get("rule_id") == "R003", f"Wrong rule: {result.get('rule_id')}"
    assert tank.get_state()["pump_running"] is False, "Pump must remain off"


def test_pump_start_when_tank_adequate_is_allowed() -> None:
    """Pump start allowed when tank above 10%."""
    tank = make_tank(INITIAL_LEVEL=50.0)
    result = tank.set_pump_state(True)
    assert result["allowed"], f"Pump start at 50% level must be allowed, got {result}"
    assert tank.get_state()["pump_running"] is True, "Pump must be running"


def test_pump_stop_when_tank_low_is_allowed() -> None:
    """
    B03 fix: pump OFF is unconditionally allowed even at low tank level.
    An operator must always be able to stop the pump.
    """
    tank = make_tank(INITIAL_LEVEL=2.0)
    # Manually set pump running (bypassing interlock for test setup)
    tank._seed_state(pump_running=True)   # D17: approved test back-door
    result = tank.set_pump_state(False)
    assert result["allowed"], (
        f"Pump stop must always be allowed regardless of level, got {result}"
    )
    assert tank.get_state()["pump_running"] is False, "Pump must be stopped"


def test_pump_at_exact_dryrun_boundary_is_blocked() -> None:
    """Level exactly at DRY_RUN_LEVEL (10%) — this is the minimum to START the pump.
    Level < 10% is blocked; level >= 10% is allowed."""
    # Level just below threshold
    tank_low = make_tank(INITIAL_LEVEL=9.9)
    result_low = tank_low.set_pump_state(True)
    assert not result_low["allowed"], "Level 9.9% must block pump start"

    # Level exactly at threshold
    tank_ok = make_tank(INITIAL_LEVEL=10.0)
    result_ok = tank_ok.set_pump_state(True)
    assert result_ok["allowed"], "Level 10.0% must allow pump start"


# ── Physics simulation ───────────────────────────────────────────────────────────

def test_physics_fills_tank_with_valve_open() -> None:
    """Open valve increases tank level."""
    tank = make_tank(INITIAL_LEVEL=50.0)
    t0 = time.monotonic()

    # Open valve first
    tank.set_valve_position(100.0, now=t0)
    # Advance physics 10 seconds
    state = tank.update_physics(now=t0 + 10.0)

    assert state["tank_level"] > 50.0, (
        f"Tank level must increase with valve open. "
        f"Expected > 50.0, got {state['tank_level']:.2f}"
    )


def test_physics_drains_tank_with_pump_on() -> None:
    """Running pump decreases tank level."""
    tank = make_tank(INITIAL_LEVEL=80.0)
    t0 = time.monotonic()

    # Start pump
    tank.set_pump_state(True)
    # Advance physics 10 seconds
    state = tank.update_physics(now=t0 + 10.0)

    assert state["tank_level"] < 80.0, (
        f"Tank level must decrease with pump on. "
        f"Expected < 80.0, got {state['tank_level']:.2f}"
    )


def test_physics_overflow_forceclose_valve_and_resets_rate_timer() -> None:
    """
    B11 fix: when overflow force-closes the valve, _last_valve_cmd_time
    must be updated. Without this, an attacker could send a rapid valve
    command immediately after overflow without triggering R002.
    """
    tank = make_tank(INITIAL_LEVEL=94.9)
    t0 = time.monotonic()

    # Open valve to cause overflow
    tank.set_valve_position(100.0, now=t0)
    # Advance physics enough to hit OVERFLOW_LEVEL
    state = tank.update_physics(now=t0 + 5.0)

    # After overflow: valve should be force-closed
    assert state["valve_position"] == 0.0, (
        f"Valve must be force-closed on overflow, got {state['valve_position']}"
    )

    # Now try to set valve rapidly immediately after overflow
    # Rate = 100%/s would normally exceed 5%/s limit only if timer was reset.
    # If B11 is unfixed, _last_valve_cmd_time is the ORIGINAL t0, so
    # dt = 5.0 s, rate = 100/5 = 20 %/s — still blocked (but for wrong reason)
    # With B11 fixed: _last_valve_cmd_time = now of the force-close (~t0+5.0)
    # so dt is very small → rate is huge → correctly blocked by R002
    result = tank.set_valve_position(10.0, now=t0 + 5.001)
    assert not result["allowed"], (
        "Rapid valve command after overflow force-close must be blocked by R002 "
        "(B11 fix: rate timer must be reset at force-close time)"
    )
    assert result.get("rule_id") == "R002", (
        f"Expected R002 to block this, got {result.get('rule_id')}"
    )


def test_physics_level_clamped_at_0_and_100() -> None:
    """Tank level must never go below 0 or above 100."""
    tank_full = make_tank(INITIAL_LEVEL=99.0)
    t0 = time.monotonic()
    tank_full.set_valve_position(100.0, now=t0)
    state = tank_full.update_physics(now=t0 + 300.0)
    assert state["tank_level"] <= 100.0, (
        f"Tank level clamped at 100, got {state['tank_level']}"
    )

    tank_empty = make_tank(INITIAL_LEVEL=1.0)
    tank_empty._seed_state(pump_running=True)   # D17
    state_e = tank_empty.update_physics(now=t0 + 300.0)
    assert state_e["tank_level"] >= 0.0, (
        f"Tank level clamped at 0, got {state_e['tank_level']}"
    )


def test_physics_max_step_clamps_large_dt() -> None:
    """
    A very large dt (e.g., server paused 60s) must be clamped to MAX_PHYSICS_STEP.
    Without clamping, the level would jump to an unrealistic value.
    """
    tank = make_tank(INITIAL_LEVEL=50.0)
    t0 = time.monotonic()

    tank.set_valve_position(100.0, now=t0)
    # Huge dt: 1000 seconds. MAX_PHYSICS_STEP = 1.0 s → dt clamped to 1.0 s
    state = tank.update_physics(now=t0 + 1000.0)

    # Level change for 1.0 s with valve=100%, no pump:
    # net = 10 L/s, delta = 10*1/1000*100 = 1.0%
    expected_max_change = 1.5  # allow a little margin
    actual_change = abs(state["tank_level"] - 50.0)
    assert actual_change < expected_max_change, (
        f"Physics step must be clamped. "
        f"Expected change < {expected_max_change}%, got {actual_change:.2f}%"
    )


# ── Violations log ────────────────────────────────────────────────────────────────

def test_violations_log_populated_on_block() -> None:
    """Each blocked command appends to the violations log."""
    tank = make_tank()
    assert len(tank.violations) == 0, "Violations must start empty"

    tank.set_valve_position(200.0)   # R001 block
    assert len(tank.violations) == 1, (
        f"Expected 1 violation, got {len(tank.violations)}"
    )

    tank.set_valve_position(-10.0)   # another R001 block
    assert len(tank.violations) == 2, (
        f"Expected 2 violations, got {len(tank.violations)}"
    )


def test_violations_property_returns_copy_not_reference() -> None:
    """
    B07 fix: .violations returns a copy — caller cannot mutate internal deque.
    """
    tank = make_tank()
    tank.set_valve_position(999.0)  # one violation

    v1 = tank.violations
    v1.clear()  # clear the copy

    v2 = tank.violations
    assert len(v2) == 1, (
        f"Internal violations deque must not be affected by clearing the copy, "
        f"got {len(v2)} violations"
    )


def test_violations_have_wall_clock_timestamps() -> None:
    """B13 fix: violation timestamps must be wall-clock (time.time()), not monotonic."""
    import time as _time
    tank = make_tank()
    before = _time.time()
    tank.set_valve_position(999.0)
    after = _time.time()

    v = tank.violations[0]
    assert before <= v["timestamp"] <= after, (
        f"Violation timestamp {v['timestamp']} outside expected range "
        f"[{before}, {after}]"
    )


def test_violations_contain_expected_fields() -> None:
    """Each violation record must contain all required fields."""
    tank = make_tank()
    tank.set_valve_position(999.0)

    v = tank.violations[0]
    required_fields = {"timestamp", "register", "value", "reason", "rule_id",
                       "severity", "mitre_tag"}
    missing = required_fields - set(v.keys())
    assert not missing, f"Violation record missing fields: {missing}"


# ── Run standalone ────────────────────────────────────────────────────────────────

def _run_all() -> None:
    """Run all tests without pytest."""
    # D18: introspection-based discovery — never goes stale.
    # Any module-level callable starting with "test_" is included automatically.
    import inspect as _inspect
    test_fns = [
        obj
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]

    passed = 0
    failed = 0
    failures: list[str] = []

    for fn in test_fns:
        try:
            fn()
            print(f"  ✅  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  ❌  {fn.__name__}")
            print(f"      {e}")
            failed += 1
            failures.append(fn.__name__)
        except Exception as e:
            print(f"  💥  {fn.__name__}  [{type(e).__name__}: {e}]")
            failed += 1
            failures.append(fn.__name__)

    print()
    print(f"{'=' * 55}")
    print(f"  Results: {passed} passed / {failed} failed / {len(test_fns)} total")
    if failures:
        print(f"  Failed:  {', '.join(failures)}")
    print(f"{'=' * 55}")

    if failed > 0:
        raise SystemExit(1)


if __name__ == "__main__":
    print()
    print("=" * 55)
    print("  WaterTankController Unit Tests")
    print("  Layer 1 | PhysicsGuard")
    print("=" * 55)
    _run_all()
