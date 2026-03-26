"""
red_team.py  —  Adversarial Red-Team Engine
Layer 8  |  PhysicsGuard ICS Security Gateway
Week 8 deliverable: auto-generates attack sequences using five mutation
strategies and fires them at the ValidationEngine to find semantic bypasses.
"""
import logging
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# ── Physical constants ─────────────────────────────────────────────────────────
VALVE_SAFE_MIN: float = 0.0        # R001 lower bound (%)
VALVE_SAFE_MAX: float = 100.0      # R001 upper bound (%)
VALVE_ADDRESS: int = 1             # Modbus register — valve setpoint
PUMP_ADDRESS: int = 2              # Modbus register — pump command

# ── Rate-spike constants ───────────────────────────────────────────────────────
RATE_SPIKE_START: float = 10.0     # valve start value (%)
RATE_SPIKE_DELTA: float = 80.0     # large Δ to trigger R002 RateRule (%)

# ── Slow-drip constants ────────────────────────────────────────────────────────
SLOW_DRIP_STEP: float = 1.0        # per-step increment (%)
SLOW_DRIP_STEPS: int = 20          # 20 steps → 20% cumulative, > 15% threshold
SLOW_DRIP_INTERVAL_S: float = 15.0 # seconds between steps (within 300 s window)
SLOW_DRIP_BASE_VALUE: float = 20.0 # starting valve value for drip sequence

# ── Replay constants ───────────────────────────────────────────────────────────
REPLAY_VALUE: float = 50.0         # the replayed valve value (%)
REPLAY_WINDOW_S: float = 5.0       # R008 replay detection window (s)

# ── Lateral movement constants ─────────────────────────────────────────────────
LATERAL_SOURCE_PLC: str = "PLC_01"
LATERAL_TARGET_PLC: str = "PLC_04"
LATERAL_SOURCE_IP: str = "192.168.1.101"

# ── Strategy registry ──────────────────────────────────────────────────────────
BUILT_IN_STRATEGIES: list[str] = [
    "boundary_value",
    "rate_spike",
    "replay",
    "slow_drip",
    "lateral",
]

STRATEGY_MITRE: dict[str, str] = {
    "boundary_value": "T0855",
    "rate_spike":     "T0855",
    "replay":         "T0856",
    "slow_drip":      "T0855",
    "lateral":        "T0888",
}


# ── Data classes ───────────────────────────────────────────────────────────────

@dataclass
class AttackVector:
    """Single adversarial probe ready to be fired at the ValidationEngine."""

    strategy:    str
    address:     int
    value:       float
    context:     dict
    description: str


@dataclass
class AttackResult:
    """Result of firing one AttackVector through the ValidationEngine."""

    strategy:     str
    address:      int
    value:        float
    context:      dict
    description:  str
    allowed:      bool
    rule_id:      str
    severity:     str
    reason:       str
    mitre_tag:    str
    found_bypass: bool   # True = attacker got through — a security gap


# ── Engine ─────────────────────────────────────────────────────────────────────

class RedTeamEngine:
    """
    Adversarial Red-Team Engine — Novel Contribution #2.

    Auto-generates attack sequences using five mutation strategies and fires
    every probe through the real ValidationEngine.validate() to find semantic
    bypasses: commands that are protocol-valid but physically dangerous.

    Usage::

        engine = RedTeamEngine(validator=validation_engine)
        results = engine.run(rounds=1)
        summary = engine.bypass_summary(results)
        # {"boundary_value": 0, "rate_spike": 0, ...}  ← all zeros = no gaps
    """

    def __init__(
        self,
        validator: Any,
        strategies: list[str] | None = None,
    ) -> None:
        """
        Initialise the engine.

        Args:
            validator:  A ValidationEngine instance (or MagicMock in tests).
                        Must expose: validate(address, value, context) → result
                        where result has: allowed, rule_id, severity, reason,
                        mitre_tag.
            strategies: Optional explicit list of strategy names to run.
                        Defaults to all five built-in strategies.
                        Pass a subset to limit scope.

        Raises:
            ValueError: If any name in ``strategies`` is not a recognised
                        built-in strategy.
        """
        self._validator = validator
        if strategies is not None:
            unknown = [s for s in strategies if s not in BUILT_IN_STRATEGIES]
            if unknown:
                raise ValueError(
                    f"Unknown strategy names: {unknown}. "
                    f"Available: {BUILT_IN_STRATEGIES}"
                )
            self._strategies: list[str] = list(strategies)
        else:
            self._strategies = list(BUILT_IN_STRATEGIES)

        log.info(
            "RedTeamEngine initialised — strategies: %s",
            self._strategies,
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self, rounds: int = 1) -> list[AttackResult]:
        """
        Run all configured strategies for ``rounds`` full sweeps.

        Args:
            rounds: Number of complete sweeps (must be ≥ 1).

        Returns:
            Flat list[AttackResult].
            ``len(run(rounds=2)) == 2 * len(run(rounds=1))`` is guaranteed.

        Raises:
            ValueError: If ``rounds`` < 1.
        """
        if rounds < 1:
            raise ValueError(
                f"rounds must be >= 1, got {rounds}"
            )

        all_results: list[AttackResult] = []
        for _ in range(rounds):
            all_results.extend(self._run_once())

        log.info(
            "RedTeamEngine.run(rounds=%d): %d probes fired, "
            "%d bypasses found",
            rounds,
            len(all_results),
            sum(1 for r in all_results if r.found_bypass),
        )
        return all_results

    def run_strategy(self, strategy: str) -> list[AttackResult]:
        """
        Run a single named strategy and return its results.

        Args:
            strategy: One of the configured strategy names.

        Returns:
            list[AttackResult] for that strategy only.

        Raises:
            ValueError: If ``strategy`` is not in the configured strategy list.
        """
        if strategy not in self._strategies:
            raise ValueError(
                f"Unknown strategy '{strategy}'. "
                f"Configured strategies: {self._strategies}"
            )
        vectors: list[AttackVector] = self._generate(strategy)
        results: list[AttackResult] = [self._fire(v) for v in vectors]
        log.debug(
            "run_strategy('%s'): %d probes, %d bypasses",
            strategy,
            len(results),
            sum(1 for r in results if r.found_bypass),
        )
        return results

    def bypass_summary(
        self,
        results: list[AttackResult],
    ) -> dict[str, int]:
        """
        Count ``found_bypass=True`` results grouped by strategy.

        Args:
            results: Output of :meth:`run` or :meth:`run_strategy`.

        Returns:
            ``{"strategy_name": bypass_count, ...}``
            Returns an *empty dict* when no bypasses were found — an empty
            dict in the dissertation proves zero semantic gaps.
        """
        summary: dict[str, int] = {}
        for result in results:
            if result.found_bypass:
                summary[result.strategy] = (
                    summary.get(result.strategy, 0) + 1
                )
        return summary

    # ── Private helpers ────────────────────────────────────────────────────────

    def _run_once(self) -> list[AttackResult]:
        """Execute one full sweep across all configured strategies."""
        results: list[AttackResult] = []
        for strategy in self._strategies:
            results.extend(self.run_strategy(strategy))
        return results

    def _generate(self, strategy: str) -> list[AttackVector]:
        """Dispatch to the generator method for ``strategy``."""
        _generators: dict[str, Any] = {
            "boundary_value": self._gen_boundary_value,
            "rate_spike":     self._gen_rate_spike,
            "replay":         self._gen_replay,
            "slow_drip":      self._gen_slow_drip,
            "lateral":        self._gen_lateral,
        }
        gen_fn = _generators.get(strategy)
        if gen_fn is None:
            raise ValueError(
                f"No generator registered for strategy '{strategy}'"
            )
        return gen_fn()

    def _fire(self, vector: AttackVector) -> AttackResult:
        """
        Fire a single AttackVector through the ValidationEngine.

        Calls ``validator.validate()`` exactly once and maps the result to an
        AttackResult.  ``found_bypass`` is True when the validator ALLOWED the
        command — meaning the attacker's probe was not blocked.

        Two categories of probe are intentionally allowed and must NOT be
        counted as bypasses:

        1. Replay seed shots (description ends with "seeds R008 history"):
           The first shot is a legitimate command that seeds R008's internal
           _history deque. Being allowed is correct — it is the second shot
           that the bypass test applies to.

        2. Boundary positive-control probes (description contains "boundary probe"):
           _gen_boundary_value() sends two probes AT the boundary (val=100,
           val=0) to verify the validator does NOT over-block legitimate
           operator commands at the edge of the safe range. Being allowed at
           exactly safe_max or safe_min is the EXPECTED outcome — it is the
           probes OUTSIDE the range (101, -1, 150) that must be blocked.
        """
        result = self._validator.validate(
            address=vector.address,
            value=vector.value,
            context=vector.context,
        )
        # Positive-control probes: being allowed is the expected correct outcome.
        # Counting them as bypasses would be a false positive in the report.
        is_first_seed:       bool = vector.description.endswith("seeds R008 history")
        is_positive_control: bool = "boundary probe" in vector.description
        found_bypass: bool = (
            bool(result.allowed)
            and not is_first_seed
            and not is_positive_control
        )

        log.debug(
            "FIRE strategy=%-16s addr=%d val=%7.2f "
            "allowed=%-5s bypass=%s",
            vector.strategy,
            vector.address,
            vector.value,
            result.allowed,
            found_bypass,
        )
        return AttackResult(
            strategy=vector.strategy,
            address=vector.address,
            value=vector.value,
            context=vector.context,
            description=vector.description,
            allowed=result.allowed,
            rule_id=result.rule_id,
            severity=result.severity,
            reason=result.reason,
            mitre_tag=result.mitre_tag,
            found_bypass=found_bypass,
        )

    # ── Strategy generators ────────────────────────────────────────────────────

    def _gen_boundary_value(self) -> list[AttackVector]:
        """
        Boundary Value — targets R001 RangeRule (MITRE T0855).

        Probes the valve setpoint at safe_max+1, safe_max, safe_min,
        safe_min-1, and an extreme over-range value.  The validator MUST
        block any value outside [VALVE_SAFE_MIN, VALVE_SAFE_MAX].
        """
        base_ctx: dict = {"level": 50.0, "pump_running": False}
        return [
            AttackVector(
                strategy="boundary_value",
                address=VALVE_ADDRESS,
                value=VALVE_SAFE_MAX + 1.0,        # 101 — MUST block
                context=base_ctx,
                description=(
                    f"Valve 1% above safe_max "
                    f"({VALVE_SAFE_MAX + 1.0:.0f}%) — R001 T0855"
                ),
            ),
            AttackVector(
                strategy="boundary_value",
                address=VALVE_ADDRESS,
                value=VALVE_SAFE_MAX,               # 100 — at boundary
                context=base_ctx,
                description=(
                    f"Valve at safe_max "
                    f"({VALVE_SAFE_MAX:.0f}%) — boundary probe R001"
                ),
            ),
            AttackVector(
                strategy="boundary_value",
                address=VALVE_ADDRESS,
                value=VALVE_SAFE_MIN - 1.0,         # -1 — MUST block
                context=base_ctx,
                description=(
                    f"Valve 1% below safe_min "
                    f"({VALVE_SAFE_MIN - 1.0:.0f}%) — R001 T0855"
                ),
            ),
            AttackVector(
                strategy="boundary_value",
                address=VALVE_ADDRESS,
                value=VALVE_SAFE_MIN,               # 0 — at boundary
                context=base_ctx,
                description=(
                    f"Valve at safe_min "
                    f"({VALVE_SAFE_MIN:.0f}%) — boundary probe R001"
                ),
            ),
            AttackVector(
                strategy="boundary_value",
                address=VALVE_ADDRESS,
                value=VALVE_SAFE_MAX + 50.0,        # 150 — extreme over-range
                context=base_ctx,
                description=(
                    f"Valve extreme over-range "
                    f"({VALVE_SAFE_MAX + 50.0:.0f}%) — R001 T0855"
                ),
            ),
        ]

    def _gen_rate_spike(self) -> list[AttackVector]:
        """
        Rate Spike — targets R002 RateRule (MITRE T0855).

        Issues a large setpoint jump in near-zero time.  RateRule.evaluate()
        reads two specific context keys:
          context[context_key]    → current value  (key = "valve_position" per rules.yaml)
          context["last_cmd_time"] → monotonic timestamp of last accepted write

        Bug 2 fix: previous code used "last_valve_value" and "last_valve_time"
        (keys that RateRule never reads).  Because "last_cmd_time" was absent
        it defaulted to 0.0, which triggered the first-command-ever early
        return — the rate check was silently skipped every time.

        Fix: use the correct keys and set last_cmd_time = time.monotonic()
        (i.e. "right now").  When _fire() calls validate() fractions of a
        millisecond later, dt ≈ 0.001 s.  With Δ = 80%, rate ≈ 80,000 %/s,
        far above the 5 %/s limit → R002 correctly blocks.
        """
        import time as _time
        t0: float = _time.monotonic()
        base_ctx: dict = {
            "tank_level": 50.0,
            "pump_running": False,
            "valve_position": RATE_SPIKE_START,  # correct key: context_key from src.rules.yaml R002
            "last_cmd_time": t0,                 # correct key: non-zero → rate check fires
        }
        return [
            AttackVector(
                strategy="rate_spike",
                address=VALVE_ADDRESS,
                value=RATE_SPIKE_START + RATE_SPIKE_DELTA,   # 90%
                context=base_ctx,
                description=(
                    f"Rate spike +{RATE_SPIKE_DELTA:.0f}% in ~1 ms "
                    f"from {RATE_SPIKE_START:.0f}% — R002 T0855"
                ),
            ),
            AttackVector(
                strategy="rate_spike",
                address=VALVE_ADDRESS,
                value=VALVE_SAFE_MAX,                         # 100%
                context=base_ctx,
                description=(
                    f"Rate spike to safe_max "
                    f"({VALVE_SAFE_MAX:.0f}%) in ~1 ms — R002 T0855"
                ),
            ),
        ]

    def _gen_replay(self) -> list[AttackVector]:
        """
        Replay — targets R008 ReplayRule (MITRE T0856).

        Fires the SAME command TWICE against the same engine instance so that
        R008's internal _history deque is populated on the FIRST shot and
        detects the replay on the SECOND.

        R008 does NOT read context keys for prior history — it maintains its
        own thread-safe deque. Passing replay_last_value / replay_last_time
        in context has zero effect; those keys do not exist in ReplayRule.
        The only correct approach is two sequential validate() calls.

        First probe  : legitimate command — expected ALLOWED, recorded by R008.
        Second probe : replay within window — expected BLOCKED by R008 (T0856).

        _fire() uses the "seeds R008 history" sentinel in the description to
        mark the first shot as a non-bypass regardless of its result.
        """
        base_ctx: dict = {
            "tank_level": 50.0,
            "valve_position": REPLAY_VALUE,
            "pump_running": False,
            "last_cmd_time": 0.0,
        }
        # First probe: legitimate command — seeds R008's _history deque
        first = AttackVector(
            strategy="replay",
            address=VALVE_ADDRESS,
            value=REPLAY_VALUE,
            context=base_ctx,
            description=(
                f"Replay FIRST shot (addr={VALVE_ADDRESS}, val={REPLAY_VALUE:.0f}%) "
                f"— seeds R008 history"
            ),
        )
        # Second probe: replay within window — expected BLOCKED by R008
        second = AttackVector(
            strategy="replay",
            address=VALVE_ADDRESS,
            value=REPLAY_VALUE,
            context={**base_ctx, "cmd_timestamp": 2.0},   # 2s later, inside 5s window
            description=(
                f"Replay SECOND shot (addr={VALVE_ADDRESS}, val={REPLAY_VALUE:.0f}%) "
                f"at t=2s — inside {REPLAY_WINDOW_S:.0f}s window R008 T0856"
            ),
        )
        return [first, second]

    def _gen_slow_drip(self) -> list[AttackVector]:
        """
        Slow Drip — targets R006 TemporalRule (MITRE T0855).

        Generates ``SLOW_DRIP_STEPS`` incremental commands, each nudging the
        valve up by ``SLOW_DRIP_STEP``%.  The context carries the accumulated
        delta so R006's sliding window can detect the pattern.
        Steps 1–15 stay under the 15% threshold; step 16 onwards crosses it.
        """
        vectors: list[AttackVector] = []
        for step in range(SLOW_DRIP_STEPS):
            cumulative_delta: float = (step + 1) * SLOW_DRIP_STEP
            ctx: dict = {
                "level": 50.0,
                "pump_running": False,
                "temporal_cumulative_delta": cumulative_delta,
                "temporal_window_start": 0.0,
                "current_time": (step + 1) * SLOW_DRIP_INTERVAL_S,
            }
            vectors.append(
                AttackVector(
                    strategy="slow_drip",
                    address=VALVE_ADDRESS,
                    value=SLOW_DRIP_BASE_VALUE + cumulative_delta,
                    context=ctx,
                    description=(
                        f"Slow-drip step {step + 1:02d}: "
                        f"cumulative Δ={cumulative_delta:.1f}% "
                        f"at t={(step + 1) * SLOW_DRIP_INTERVAL_S:.0f}s — "
                        "R006 T0855"
                    ),
                )
            )
        return vectors

    def _gen_lateral(self) -> list[AttackVector]:
        """
        Lateral Movement — targets R007 TopologyRule (MITRE T0888).

        Crafts valve and pump commands that claim to originate from
        PLC_01 but target PLC_04, an unauthorised PLC-to-PLC path in the
        plant topology.

        Bug 3 fix: previous code used "source_plc" and "target_plc" (keys
        that TopologyRule never reads).  TopologyRule.evaluate() reads:
          context.get("source_plc_id")  ← exact key required
          context.get("target_plc_id")  ← exact key required
        With the old keys, src was None → rule logged "no source_plc_id —
        internal call" and skipped entirely.  Every lateral probe passed.
        """
        ctx_lateral: dict = {
            "tank_level": 50.0,
            "pump_running": False,
            "source_plc_id": LATERAL_SOURCE_PLC,   # correct key (was "source_plc")
            "target_plc_id": LATERAL_TARGET_PLC,   # correct key (was "target_plc")
            "source_ip":     LATERAL_SOURCE_IP,
        }
        return [
            AttackVector(
                strategy="lateral",
                address=VALVE_ADDRESS,
                value=50.0,
                context=ctx_lateral,
                description=(
                    f"Lateral movement "
                    f"{LATERAL_SOURCE_PLC}→{LATERAL_TARGET_PLC} "
                    f"valve cmd — R007 T0888"
                ),
            ),
            AttackVector(
                strategy="lateral",
                address=PUMP_ADDRESS,
                value=1.0,                      # pump ON from wrong PLC
                context=ctx_lateral,
                description=(
                    f"Lateral movement "
                    f"{LATERAL_SOURCE_PLC}→{LATERAL_TARGET_PLC} "
                    f"pump-ON cmd — R007 T0888"
                ),
            ),
        ]
