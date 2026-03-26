"""
src/rules/__init__.py  —  Validation Rule Package
==================================================
Layer 4  |  PhysicsGuard ICS Security Gateway

All five rules exported from one import:
    from src.rules import RangeRule, RateRule, InterlockRule, AuthRule, TimeRule

Execution priority order (lowest runs first):
    R004 AuthRule      priority=5   CRITICAL   T0817
    R001 RangeRule     priority=10  CRITICAL   T0855
    R005 TimeRule      priority=15  WARNING    T0855
    R002 RateRule      priority=20  CRITICAL   T0855
    R003 InterlockRule priority=30  EMERGENCY  T0813
"""

from src.rules.base_rule      import BaseRule, RuleResult, pass_result, block_result
from src.rules.auth_rule      import AuthRule
from src.rules.range_rule     import RangeRule
from src.rules.time_rule      import TimeRule
from src.rules.rate_rule      import RateRule
from src.rules.interlock_rule import InterlockRule

__all__ = [
    "BaseRule",
    "RuleResult",
    "pass_result",
    "block_result",
    "AuthRule",
    "RangeRule",
    "TimeRule",
    "RateRule",
    "InterlockRule",
]
