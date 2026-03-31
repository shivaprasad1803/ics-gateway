"""
src/rules/__init__.py  —  Validation Rule Package
==================================================
Layer 4  |  PhysicsGuard ICS Security Gateway

All eleven rules exported from one import:
    from src.rules import RangeRule, RateRule, InterlockRule, AuthRule, TimeRule
    from src.rules import TemporalRule, TopologyRule, ReplayRule, OscillationRule
    from src.rules import CorrelationRule, CascadeRule

Execution priority order (lowest runs first):
    R004 AuthRule         priority=5   CRITICAL   T0817
    R007 TopologyRule     priority=8   CRITICAL   T0888
    R001 RangeRule        priority=10  CRITICAL   T0855
    R008 ReplayRule       priority=12  CRITICAL   T0856
    R005 TimeRule         priority=15  WARNING    T0855
    R002 RateRule         priority=20  CRITICAL   T0855
    R009 OscillationRule  priority=22  CRITICAL   T0855
    R006 TemporalRule     priority=25  CRITICAL   T0855
    R003 InterlockRule    priority=30  EMERGENCY  T0813
    R011 CorrelationRule  priority=40  CRITICAL   T0856
    R012 CascadeRule      priority=45  EMERGENCY  T0855
"""

from src.rules.base_rule        import BaseRule, RuleResult, pass_result, block_result
from src.rules.auth_rule        import AuthRule
from src.rules.range_rule       import RangeRule
from src.rules.time_rule        import TimeRule
from src.rules.rate_rule        import RateRule
from src.rules.interlock_rule   import InterlockRule
from src.rules.temporal_rule    import TemporalRule
from src.rules.topology_rule    import TopologyRule
from src.rules.replay_rule      import ReplayRule
from src.rules.oscillation_rule import OscillationRule
from src.rules.correlation_rule import CorrelationRule
from src.rules.cascade_rule     import CascadeRule

__all__ = [
    # Base
    "BaseRule",
    "RuleResult",
    "pass_result",
    "block_result",
    # Core rules (R001–R005) — YAML-configurable
    "AuthRule",
    "RangeRule",
    "TimeRule",
    "RateRule",
    "InterlockRule",
    # Novel-contribution rules (R006–R009) — wired in code
    "TemporalRule",
    "TopologyRule",
    "ReplayRule",
    "OscillationRule",
    # Cross-PLC rules (R011–R012) — require merged global context
    "CorrelationRule",
    "CascadeRule",
]
