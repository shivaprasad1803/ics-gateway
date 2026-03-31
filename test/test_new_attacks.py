"""
test_new_attacks.py  —  Verification of A11 (Correlation) and A12 (Cascade)
=========================================================================
PhysicsGuard ICS Security Gateway  |  Layer 4
"""

import sys
import os
import time
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from src.validation_engine import ValidationEngine, build_water_tank_engine
from src.rules.correlation_rule import CorrelationRule
from src.rules.cascade_rule import CascadeRule

def test_A11_correlation_failure():
    """A11: Tank level NOT rising despite valve 100% open."""
    engine = build_water_tank_engine()

    try:
        engine.unregister_rule("R011")
    except (ValueError, KeyError):
        pass
    # Manual registration for test in 'new'
    engine.register_rule(CorrelationRule(min_expected_rise=0.5))
    
    # 1. First probe: Establish history
    t0 = time.monotonic()
    ctx = {
        "tank_level": 50.0,
        "valve_position": 100.0, # Full open
        "pump_running": False
    }
    r1 = engine.validate(address=1, value=100.0, context=ctx, now=t0)
    assert r1.allowed, "First shot should pass and seed history"
    
    # 2. Second probe: 2 seconds later, level STILL 50.0 (Attack!)
    r2 = engine.validate(address=1, value=99.0, context=ctx, now=t0 + 2.0)
    assert not r2.allowed, "A11: Sensor mismatch should be blocked"
    assert r2.rule_id == "R011"

def test_A12_cascade_failure():
    """A12: Prevent high heater power when tank level is critical."""
    engine = build_water_tank_engine()

    try:
        engine.unregister_rule("R012")
    except (ValueError, KeyError):
        pass
    # Manual registration for test
    engine.register_rule(CascadeRule())
    
    # Critical state: Level < 5%
    ctx = {
        "tank_level": 4.0,
        "heater_power": 0.0,
        "valve_position": 0.0
    }
    
    # Attack: Trying to set heater (HR 11) to 80% while tank empty
    result = engine.validate(address=11, value=80.0, context=ctx)
    assert not result.allowed, "A12: Cascade danger must be blocked"
    assert result.rule_id == "R012"

