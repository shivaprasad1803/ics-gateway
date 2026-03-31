"""
validation_engine.py  —  Semantic Validation Engine
====================================================
Layer 4  |  PhysicsGuard ICS Security Gateway
Week 3 deliverable: priority-ordered, short-circuit rule pipeline with
consequence prediction, per-rule metrics, and P99 latency tracking.

Owns:
  - ValidationEngine: registers rules, runs validate(), exposes metrics
  - EngineMetrics:    snapshot of per-rule block counts + latency stats
  - build_water_tank_engine(): factory wiring R001 + R002 + R003

Does NOT own:
  - Rule logic        (src/rules/)
  - Physics state     (water_tank.py — Layer 1)
  - Alerting          (alerting.py — Layer 5)
  - Forensic logging  (forensic_logger.py — Layer 6)

Novel contribution #1 integration:
  When a command is blocked, the ValidationEngine optionally calls
  ConsequenceEngine.evaluate() and attaches the prediction to the
  blocked RuleResult's metadata.  This is the "consequence-aware
  blocking" that differentiates PhysicsGuard:
    "BLOCKED by R001: valve=150 out of range.
     Consequence if allowed: OVERFLOW in 4.2 s (EMERGENCY)"

  Wire it with: engine.set_consequence_engine(ConsequenceEngine())

Design notes:
  - Rules are sorted by priority (lowest first) on every validate() call
    from a snapshot taken under lock — rule registration is thread-safe
    but the execution run outside the lock for concurrency.
  - On any rule exception: fail SAFE → EMERGENCY block (never allow).
  - Metrics counters are protected by a separate _metrics_lock to avoid
    contention with _rules_lock during high-throughput command streams.
  - Latency measured with time.perf_counter() (higher resolution than
    monotonic for sub-millisecond intervals on Linux).
  - LATENCY_SAMPLE_MAXLEN: 1000 samples → P99 is meaningful above 100
    commands, ~100 kB memory at worst case.

Complexity: O(R) per validate() where R = number of enabled rules.
Expected P99 < 1 ms for R ≤ 10 rules on commodity hardware.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.rules import RangeRule, RateRule, InterlockRule, AuthRule, TimeRule
from src.rules.base_rule import (
    BaseRule,
    RuleResult,
    pass_result,
    block_result,
    SEVERITY_EMERGENCY,
)

if TYPE_CHECKING:
    # Runtime import avoided to prevent circular dependency.
    # ConsequenceEngine is imported only when set_consequence_engine() is called.
    from consequence_engine import ConsequenceEngine

__all__ = [
    "ValidationEngine",
    "EngineMetrics",
    "build_water_tank_engine",
]

log = logging.getLogger(__name__)

# Maximum number of latency samples to retain in the rolling window.
# At P99, 1000 samples → index 990 in sorted list → statistically meaningful
# after ~100 commands. Memory: 1000 × 8 bytes = 8 kB.
_LATENCY_SAMPLE_MAXLEN: int = 1_000

# Log a WARNING when a single validate() call exceeds this threshold.
# ICS rule-of-thumb: semantic validation should not add > 1 ms latency.
_LATENCY_WARN_THRESHOLD_US: float = 1_000.0


# ── EngineMetrics ─────────────────────────────────────────────────────────────

@dataclass(slots=True)
class EngineMetrics:
    """
    Snapshot of ValidationEngine performance and block statistics.

    Returned by ValidationEngine.get_metrics().
    All fields are copies — mutation does not affect the engine.

    Fields
    ------
    total_evaluated : total validate() calls since last reset
    total_allowed   : calls where all rules passed
    total_blocked   : calls where at least one rule blocked
    block_rate      : total_blocked / total_evaluated  (0.0 if no calls)
    blocked_by_rule : {rule_id: block_count} — identifies hot rules
    mean_latency_us : mean validate() latency in microseconds
    p99_latency_us  : 99th-percentile validate() latency in microseconds
    metrics_since   : wall-clock time when metrics were last reset
    """

    total_evaluated: int
    total_allowed:   int
    total_blocked:   int
    block_rate:      float
    blocked_by_rule: dict[str, int]
    mean_latency_us: float
    p99_latency_us:  float
    metrics_since:   float


# ── ValidationEngine ──────────────────────────────────────────────────────────

class ValidationEngine:
    """
    Priority-ordered validation pipeline for ICS write commands.

    Thread safety:
        _rules_lock   : guards _rules dict — registration / enable / get
        _metrics_lock : guards all _metrics_* fields — updated after each
                        validate() call; separate lock avoids contention
                        when rule execution is slow.

    Usage::

        engine = build_water_tank_engine()
        # Optionally wire consequence prediction (novel contribution #1):
        engine.set_consequence_engine(ConsequenceEngine())

        state  = tank.get_state()
        result = engine.validate(address=1, value=150.0, context=state)
        if not result.allowed:
            print(result.reason)
            # result.metadata["consequence"] available if CE is wired

        metrics = engine.get_metrics()
        print(f"P99 latency: {metrics.p99_latency_us:.0f} µs")
    """

    def __init__(self) -> None:
        self._rules_lock:   threading.Lock                = threading.Lock()
        self._rules:        dict[str, BaseRule]           = {}

        self._metrics_lock: threading.Lock                = threading.Lock()
        self._metrics_total:     int                      = 0
        self._metrics_allowed:   int                      = 0
        self._metrics_blocked:   int                      = 0
        self._metrics_by_rule:   dict[str, int]           = {}
        self._metrics_latency:   deque[float]             = deque(
            maxlen=_LATENCY_SAMPLE_MAXLEN
        )
        self._metrics_since:     float                    = time.time()

        # Optional ConsequenceEngine for novel-contribution #1 integration.
        # None by default — wired explicitly via set_consequence_engine().
        self._consequence_engine: ConsequenceEngine | None = None

    # ── Rule management ───────────────────────────────────────────────────────

    def register_rule(self, rule: BaseRule) -> None:
        """
        Register a rule with the engine.

        Raises:
            ValueError if rule_id is empty or already registered
              (use unregister_rule() first to replace a rule).
        """
        if not rule.rule_id:
            raise ValueError("Cannot register a rule with an empty rule_id")
        with self._rules_lock:
            if rule.rule_id in self._rules:
                raise ValueError(
                    f"Rule '{rule.rule_id}' is already registered. "
                    f"Call unregister_rule('{rule.rule_id}') first to replace it."
                )
            self._rules[rule.rule_id] = rule
            log.info(
                "ValidationEngine: registered %s "
                "(priority=%d, severity=%s, mitre=%s)",
                rule.rule_id, rule.priority, rule.severity, rule.mitre_tag,
            )

    def unregister_rule(self, rule_id: str) -> None:
        """
        Remove a rule from the engine.

        Raises:
            KeyError if rule_id is not registered.
        """
        with self._rules_lock:
            if rule_id not in self._rules:
                raise KeyError(
                    f"Rule '{rule_id}' is not registered in this engine"
                )
            del self._rules[rule_id]
            log.info("ValidationEngine: unregistered %s", rule_id)

    def set_enabled(self, rule_id: str, enabled: bool) -> None:
        """
        Enable or disable a rule at runtime without unregistering it.
        Useful for maintenance windows or testing specific rule behaviour.

        Raises:
            KeyError if rule_id is not registered.
        """
        with self._rules_lock:
            if rule_id not in self._rules:
                raise KeyError(
                    f"Rule '{rule_id}' is not registered in this engine"
                )
            self._rules[rule_id].enabled = enabled
            log.info(
                "ValidationEngine: rule %s %s",
                rule_id, "ENABLED" if enabled else "DISABLED",
            )

    def get_rules(self) -> list[dict[str, Any]]:
        """
        Return a sorted snapshot of registered rules (for the API/banner).
        Sorted by priority ascending (lowest = runs first).
        """
        with self._rules_lock:
            return [
                {
                    "rule_id":   r.rule_id,
                    "type":      type(r).__name__,
                    "priority":  r.priority,
                    "severity":  r.severity,
                    "mitre_tag": r.mitre_tag,
                    "enabled":   r.enabled,
                }
                for r in sorted(self._rules.values(), key=lambda x: x.priority)
            ]

    # ── Consequence engine (novel contribution #1) ────────────────────────────

    def set_consequence_engine(
        self,
        consequence_engine: ConsequenceEngine,
    ) -> None:
        """
        Wire a ConsequenceEngine for forward-physics damage prediction.

        When set, every blocked result will include a "consequence" key
        in its metadata:
            result.metadata["consequence"] = {
                "damage_predicted": True,
                "damage_type":      "OVERFLOW",
                "consequence_severity": "EMERGENCY",
                "predicted_time_to_damage_s": 4.2,
                "description": "OVERFLOW predicted in 4.2 s ...",
            }

        This is novel contribution #1:
          "Every blocked command comes with a prediction: 'if allowed,
          overflow would occur in 4.2 s'. No open-source ICS tool does
          this today."
        """
        self._consequence_engine = consequence_engine
        log.info(
            "ValidationEngine: ConsequenceEngine wired — "
            "blocked results will include damage predictions"
        )

    # ── Core validation ───────────────────────────────────────────────────────

    def validate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,
    ) -> RuleResult:
        """
        Run all enabled rules in priority order; return on first block.

        Algorithm:
            1. Snapshot active (enabled) rules under _rules_lock.
            2. Run rules outside the lock — no lock held during evaluation.
            3. Short-circuit on any is_blocking() result.
            4. On exception in any rule: fail SAFE → EMERGENCY block.
            5. If a block occurs and ConsequenceEngine is wired:
               attach damage prediction to the result metadata.
            6. Update metrics (under _metrics_lock) and return.

        Complexity: O(R) where R = number of enabled rules.

        Args:
            address : 0-based register address being written
            value   : proposed value
            context : WaterTankController.get_state() snapshot
            now     : time.monotonic() override for testing

        Returns:
            RuleResult — pass (all rules OK) or block (first failure)
        """
        t_start: float = time.perf_counter()

        # ── 1. Snapshot active rules (lock held briefly) ──────────────────────
        with self._rules_lock:
            active_rules: list[BaseRule] = sorted(
                [r for r in self._rules.values() if r.enabled],
                key=lambda r: r.priority,
            )

        # ── 2. Degenerate case: no rules ──────────────────────────────────────
        if not active_rules:
            result = pass_result(
                "ENGINE",
                "No rules registered — command accepted",
            )
            self._record_metrics(result, t_start)
            return result

        # ── 3. Run rules outside lock ─────────────────────────────────────────
        result: RuleResult = pass_result("ENGINE", "placeholder")

        for rule in active_rules:
            try:
                result = rule.evaluate(
                    address=address,
                    value=value,
                    context=context,
                    now=now,
                )
            except Exception as exc:
                # Fail-safe: rule exception → EMERGENCY block
                # Never allow a command when we can't confirm it is safe.
                log.exception(
                    "ValidationEngine: rule %s raised %s — "
                    "blocking EMERGENCY (fail-safe)",
                    rule.rule_id, type(exc).__name__,
                )
                result = block_result(
                    rule_id=rule.rule_id,
                    reason=f"Rule {rule.rule_id} raised {type(exc).__name__}: {exc}",
                    severity=SEVERITY_EMERGENCY,
                )

            if result.is_blocking():
                log.warning(
                    "ValidationEngine: BLOCKED by %s [%s] "
                    "addr=%d val=%.2f — %s",
                    result.rule_id, result.severity,
                    address, value, result.reason,
                )
                # ── 4. Consequence prediction (novel contribution #1) ─────────
                result = self._attach_consequence(
                    result, address, value, context
                )
                self._record_metrics(result, t_start)
                return result

            if result.severity == "WARNING":
                log.warning(
                    "ValidationEngine: WARNING from %s addr=%d val=%.2f — %s",
                    result.rule_id, address, value, result.reason,
                )

        # ── 5. All rules passed ───────────────────────────────────────────────
        result = pass_result(
            "ENGINE",
            f"All {len(active_rules)} rule(s) passed "
            f"for addr={address} val={value:.2f}",
        )
        self._record_metrics(result, t_start)
        return result

    # ── Metrics ───────────────────────────────────────────────────────────────

    def get_metrics(self) -> EngineMetrics:
        """
        Return a snapshot of engine performance and block statistics.

        Thread-safe copy — does not reset counters.
        Use reset_metrics() to start a fresh measurement window.

        Useful for:
          - Layer 7 dashboard block-rate graphs
          - Dissertation P99 latency claim verification
          - Identifying which rules fire most often under attack
        """
        with self._metrics_lock:
            total   = self._metrics_total
            allowed = self._metrics_allowed
            blocked = self._metrics_blocked
            by_rule = dict(self._metrics_by_rule)
            samples = list(self._metrics_latency)
            since   = self._metrics_since

        block_rate      = blocked / total if total > 0 else 0.0
        mean_latency_us = (sum(samples) / len(samples)) if samples else 0.0

        if len(samples) >= 2:
            sorted_s        = sorted(samples)
            p99_idx         = max(0, int(0.99 * len(sorted_s)) - 1)
            p99_latency_us  = sorted_s[p99_idx]
        else:
            p99_latency_us = samples[0] if samples else 0.0

        return EngineMetrics(
            total_evaluated = total,
            total_allowed   = allowed,
            total_blocked   = blocked,
            block_rate      = block_rate,
            blocked_by_rule = by_rule,
            mean_latency_us = mean_latency_us,
            p99_latency_us  = p99_latency_us,
            metrics_since   = since,
        )

    def reset_metrics(self) -> None:
        """Reset all counters and latency samples for a fresh measurement window."""
        with self._metrics_lock:
            self._metrics_total    = 0
            self._metrics_allowed  = 0
            self._metrics_blocked  = 0
            self._metrics_by_rule  = {}
            self._metrics_latency.clear()
            self._metrics_since    = time.time()
        log.info("ValidationEngine: metrics reset")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _attach_consequence(
        self,
        result:  RuleResult,
        address: int,
        value:   float,
        context: dict[str, Any],
    ) -> RuleResult:
        """
        If a ConsequenceEngine is wired, forward-simulate the plant with the
        proposed command and attach the prediction to result.metadata.

        Returns a new RuleResult (frozen dataclass — copy-and-replace).
        Returns the original result unchanged if no CE is wired or if the
        simulation itself raises (CE exceptions must never block the pipeline).
        """
        if self._consequence_engine is None:
            return result

        try:
            ce_result = self._consequence_engine.evaluate(
                current_state=context,
                proposed_address=address,
                proposed_value=value,
            )
            consequence_data: dict[str, Any] = {
                "damage_predicted":           ce_result.damage_predicted,
                "damage_type":                ce_result.damage_type,
                "consequence_severity":       ce_result.severity,
                "predicted_time_to_damage_s": ce_result.predicted_time_to_damage,
                "description":                ce_result.description,
                "simulated_horizon_s":        ce_result.simulated_horizon_s,
            }
            # Copy-and-replace (frozen dataclass pattern)
            return RuleResult(
                allowed=result.allowed,
                reason=result.reason,
                rule_id=result.rule_id,
                severity=result.severity,
                mitre_tag=result.mitre_tag,
                metadata={**result.metadata, "consequence": consequence_data},
            )
        except Exception as exc:
            # CE exception must NEVER affect the block decision.
            # Log and return original result unchanged.
            log.error(
                "ValidationEngine: ConsequenceEngine raised %s — "
                "consequence data omitted; block decision unchanged",
                type(exc).__name__,
            )
            return result

    def _record_metrics(self, result: RuleResult, t_start: float) -> None:
        """
        Update counters and latency rolling window.
        Called after every validate() invocation.
        """
        latency_us = (time.perf_counter() - t_start) * 1_000_000.0

        if latency_us > _LATENCY_WARN_THRESHOLD_US:
            log.warning(
                "ValidationEngine: SLOW validate() latency=%.0f µs "
                "(threshold=%.0f µs) — review rule complexity",
                latency_us, _LATENCY_WARN_THRESHOLD_US,
            )

        with self._metrics_lock:
            self._metrics_total   += 1
            self._metrics_latency.append(latency_us)

            if result.allowed:
                self._metrics_allowed += 1
            else:
                self._metrics_blocked += 1
                self._metrics_by_rule[result.rule_id] = (
                    self._metrics_by_rule.get(result.rule_id, 0) + 1
                )


# ── YAML factory ─────────────────────────────────────────────────────────────

def load_rules_from_yaml(path: str) -> ValidationEngine:
    """
    Build a ValidationEngine from a YAML configuration file.

    Implements §15.4 config-driven rules: separation of policy (config)
    from mechanism (code). Examiners can change rule parameters live
    during the demo without touching source code.

    Supported rule types (maps 'type' field to rule class):
        auth      → AuthRule
        range     → RangeRule
        time      → TimeRule
        rate      → RateRule
        interlock → InterlockRule

    Example YAML (see config/rules.yaml for full example)::

        rules:
          - rule_id:   R001
            type:      range
            priority:  10
            address:   1
            min_value: 0.0
            max_value: 100.0
            label:     "valve %"
            enabled:   true

    Args:
        path : path to the YAML config file

    Returns:
        Configured ValidationEngine

    Raises:
        FileNotFoundError : if the file does not exist
        ValueError        : if a rule entry has an unknown type or
                            missing required fields
        yaml.YAMLError    : if the file is not valid YAML
    """
    import yaml   # stdlib-compatible; PyYAML required

    from src.rules.auth_rule      import AuthRule
    from src.rules.range_rule     import RangeRule
    from src.rules.time_rule      import TimeRule
    from src.rules.rate_rule      import RateRule
    from src.rules.interlock_rule import InterlockRule

    with open(path) as fh:
        config: dict[str, Any] = yaml.safe_load(fh)

    if not isinstance(config, dict) or "rules" not in config:
        raise ValueError(
            f"load_rules_from_yaml: {path!r} must contain a top-level "
            f"'rules:' list"
        )

    engine = ValidationEngine()

    for entry in config["rules"]:
        rule_type:  str  = str(entry.get("type", "")).strip().lower()
        rule_id:    str  = str(entry.get("rule_id", ""))
        enabled:    bool = bool(entry.get("enabled", True))

        rule: BaseRule

        if rule_type == "auth":
            allowed_ips: list[str] = [
                str(ip) for ip in (entry.get("allowed_ips") or [])
            ]
            rule = AuthRule(
                allowed_ips=set(allowed_ips),
                label=str(entry.get("label", "IP whitelist")),
            )

        elif rule_type == "range":
            rule = RangeRule(
                address=int(entry["address"]),
                min_value=float(entry["min_value"]),
                max_value=float(entry["max_value"]),
                label=str(entry.get("label", "value")),
            )

        elif rule_type == "time":
            rule = TimeRule(
                allowed_hours=(
                    int(entry["allowed_hours_start"]),
                    int(entry["allowed_hours_end"]),
                ),
                label=str(entry.get("label", "operating hours")),
                block_outside_hours=bool(
                    entry.get("block_outside_hours", False)
                ),
            )

        elif rule_type == "rate":
            rule = RateRule(
                address=int(entry["address"]),
                max_rate=float(entry["max_rate"]),
                context_key=str(entry["context_key"]),
                label=str(entry.get("label", "value/s")),
            )

        elif rule_type == "interlock":
            rule = InterlockRule(
                address=int(entry["address"]),
                condition=str(entry["condition"]),
                label=str(entry.get("label", "interlock")),
                only_on_nonzero=bool(entry.get("only_on_nonzero", True)),
            )

        else:
            raise ValueError(
                f"load_rules_from_yaml: unknown rule type {rule_type!r} "
                f"in entry {entry}. "
                f"Supported: auth, range, time, rate, interlock"
            )

        # Override rule_id from config if explicitly specified
        if rule_id:
            rule.rule_id = rule_id
        rule.enabled = enabled

        engine.register_rule(rule)
        log.info(
            "load_rules_from_yaml: loaded %s (type=%s, priority=%d, enabled=%s)",
            rule.rule_id, rule_type, rule.priority, enabled,
        )

    return engine


# ── Factory ───────────────────────────────────────────────────────────────────
def build_water_tank_engine() -> "ValidationEngine":
    """
    Build the standard ValidationEngine with all production rules wired.

    Rules registered (in execution order):
        R001 — RangeRule        valve [0, 100]%        priority=10  CRITICAL   T0855
        R002 — RateRule         valve ≤ 5.0 %/s        priority=20  CRITICAL   T0855
        R003 — InterlockRule    pump-on ↔ level ≥ 10%  priority=30  EMERGENCY  T0813
        R006 — TemporalRule     slow-drip ≤ 15%/300s   priority=25  CRITICAL   T0855
        R007 — TopologyRule     lateral movement guard  priority=8   CRITICAL   T0888
        R008 — ReplayRule       replay detection 5s     priority=12  CRITICAL   T0856
        R009 — OscillationRule  oscillation ≤ 4 rev     priority=22  CRITICAL   T0855
        R011 — CorrelationRule  cross-sensor mismatch   priority=40  CRITICAL   T0856
        R012 — CascadeRule      cross-PLC cascade guard priority=45  EMERGENCY  T0855

    R004 (AuthRule) and R005 (TimeRule) are NOT included here because they
    require site-specific configuration (IP whitelist, operating hours).
    Load them via YAML or register manually:

        engine = build_water_tank_engine()
        engine.register_rule(AuthRule(allowed_ips={"127.0.0.1"}))
        engine.register_rule(TimeRule(allowed_hours=(8, 18)))

    R011 (CorrelationRule) and R012 (CascadeRule) operate on cross-PLC
    context keys (``temperature``, ``heater_power``, etc.). When those
    keys are absent from the context the rules pass silently — they are
    safe to include in single-PLC unit tests.

    Returns:
        Configured ValidationEngine ready for use in modbus_server.py.
    """
    from src.rules.range_rule       import RangeRule
    from src.rules.rate_rule        import RateRule
    from src.rules.interlock_rule   import InterlockRule
    from src.rules.temporal_rule    import TemporalRule
    from src.rules.topology_rule    import TopologyRule
    from src.plant_topology         import build_water_tank_topology
    from src.rules.replay_rule      import ReplayRule
    from src.rules.oscillation_rule import OscillationRule
    from src.rules.correlation_rule import CorrelationRule
    from src.rules.cascade_rule     import CascadeRule
    from src.consequence_engine     import ConsequenceEngine

    engine = ValidationEngine()

    # R001: valve position range [0, 100]%
    engine.register_rule(RangeRule(
        address=1,
        min_value=0.0,
        max_value=100.0,
        label="valve %",
    ))

    # R002: valve rate-of-change ≤ 5 %/s
    engine.register_rule(RateRule(
        address=1,
        max_rate=5.0,
        context_key="valve_position",
        label="%/s",
    ))

    # R003: pump start only when tank_level >= 10%
    engine.register_rule(InterlockRule(
        address=2,
        condition="tank_level >= 10",
        label="pump dry-run interlock",
        only_on_nonzero=True,
    ))

    # R006: slow-drip — cumulative valve movement ≤ 15% in 300 s
    engine.register_rule(TemporalRule(
        address=1,
        window_s=300.0,
        max_cumulative_delta=15.0,
        label="%",
    ))

    # R007: lateral movement topology guard
    engine.register_rule(TopologyRule(
        topology=build_water_tank_topology(),
        default_target="PLC_01",
    ))

    # R008: command replay detection (5 s window, all registers)
    engine.register_rule(ReplayRule(
        address=None,
        replay_window_s=5.0,
    ))

    # R009: setpoint oscillation (4 reversals in 120 s, min Δ = 10%)
    engine.register_rule(OscillationRule(
        address=1,
        window_s=120.0,
        max_reversals=4,
        min_delta_pct=10.0,
    ))

    # R011: cross-sensor correlation — passes silently when cross-PLC
    # context keys (valve_position history) are absent, so safe in unit tests.
    engine.register_rule(CorrelationRule(min_expected_rise=0.5))

    # R012: cross-PLC cascade guard — passes silently when temperature /
    # tank_level cross-PLC keys are absent from context.
    engine.register_rule(CascadeRule(
        cascade_level_threshold=5.0,
        heater_threshold=50.0,
        temp_danger_threshold=150.0,
    ))

    # Novel Contribution #1: ConsequenceEngine (forward damage prediction).
    # Blocked results carry metadata["consequence"] with time-to-damage.
    engine.set_consequence_engine(ConsequenceEngine())

    return engine
