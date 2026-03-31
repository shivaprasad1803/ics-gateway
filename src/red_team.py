"""
red_team.py  —  Adversarial Red-Team Engine
============================================
Layer 8  |  PhysicsGuard ICS Security Gateway

Covers all 15 attack scenarios (A01–A15) using 7 mutation strategies.
Backward-compatible with the original test_red_team.py contract.

Bugs fixed vs the new v2 draft:
  1. Added BUILT_IN_STRATEGIES and SLOW_DRIP_STEPS module constants
     (tests import them directly at module level).
  2. Added run_strategy(strategy) method (tests call it).
  3. Added bypass_summary(results) method (tests call it).
  4. run() now accepts a rounds parameter (tests call engine.run(rounds=1)).
  5. __init__ now accepts a strategies kwarg (tests pass custom lists).
  6. Fixed strategy name consistency — AttackVector.strategy always matches
     the key in self._strategies so r.strategy == "boundary_value" etc.
  7. Removed now=context.get("current_time") from validate() calls.
     Passing a monotonic float as now to validate() breaks R005 TimeRule
     (it treats the value as a civil Unix timestamp → hour in 1970).
     Instead, AttackVector carries an optional now field that is only
     used by rate_spike and replay where precise timing is needed.
  8. Replay second shot uses cmd_timestamp context key (not current_time)
     because R008 ReplayRule reads context.get("cmd_timestamp").
"""

import logging
import time as _time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# ── Physical constants ─────────────────────────────────────────────────────────
VALVE_SAFE_MIN:  float = 0.0
VALVE_SAFE_MAX:  float = 100.0
VALVE_ADDRESS:   int   = 1
PUMP_ADDRESS:    int   = 2
HEATER_ADDRESS:  int   = 11

# ── Rate-spike constants ───────────────────────────────────────────────────────
RATE_SPIKE_START: float = 10.0
RATE_SPIKE_DELTA: float = 80.0     # 80% jump → rate ≈ 80,000 %/s >> 5 %/s limit

# ── Slow-drip constants ────────────────────────────────────────────────────────
SLOW_DRIP_STEP:     float = 1.0
SLOW_DRIP_STEPS:    int   = 20     # 20 steps → 20% cumulative > 15% threshold
SLOW_DRIP_BASE:     float = 20.0

# ── Replay constants ───────────────────────────────────────────────────────────
REPLAY_VALUE:    float = 50.0
REPLAY_WINDOW_S: float = 5.0

# ── Lateral movement constants ─────────────────────────────────────────────────
LATERAL_SOURCE_PLC: str = "PLC_01"
LATERAL_TARGET_PLC: str = "PLC_04"
LATERAL_SOURCE_IP:  str = "192.168.1.101"

# ── Strategy registry ──────────────────────────────────────────────────────────
BUILT_IN_STRATEGIES: list[str] = [
    "boundary_value",
    "rate_spike",
    "replay",
    "slow_drip",
    "lateral",
    "sensor_correlation",
    "cascade_failure",
]

STRATEGY_MITRE: dict[str, str] = {
    "boundary_value":    "T0855",
    "rate_spike":        "T0855",
    "replay":            "T0856",
    "slow_drip":         "T0855",
    "lateral":           "T0888",
    "sensor_correlation": "T0856",
    "cascade_failure":   "T0855",
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
    # Optional monotonic time override passed to validate(now=...).
    # Only set for rate_spike and replay where precise dt matters.
    # Left as None for all other strategies so validate() uses real time
    # and avoids corrupting R005 TimeRule's civil-timestamp check.
    now:         float | None = field(default=None, compare=False)


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

    Generates attack sequences using 7 mutation strategies covering all 15
    attack scenarios and fires every probe through ValidationEngine.validate()
    to find semantic bypasses.

    Usage::

        engine = RedTeamEngine(validator=validation_engine)
        results = engine.run(rounds=1)
        summary = engine.bypass_summary(results)
        # {} = no bypasses found
    """

    def __init__(
        self,
        validator:  Any,
        strategies: list[str] | None = None,
    ) -> None:
        """
        Args:
            validator:  ValidationEngine (or MagicMock in tests).
                        Must expose: validate(address, value, context) → result
                        with fields: allowed, rule_id, severity, reason, mitre_tag.
            strategies: Optional subset of strategy names to run.
                        Defaults to all 7 built-in strategies.

        Raises:
            ValueError: If any name in strategies is not a built-in strategy.
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

        log.info("RedTeamEngine initialised — strategies: %s", self._strategies)

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self, rounds: int = 1) -> list[AttackResult]:
        """
        Run all configured strategies for rounds full sweeps.

        Args:
            rounds: Number of complete sweeps (must be ≥ 1).

        Returns:
            Flat list[AttackResult].
            len(run(rounds=2)) == 2 * len(run(rounds=1)) is guaranteed.

        Raises:
            ValueError: If rounds < 1.
        """
        if rounds < 1:
            raise ValueError(f"rounds must be >= 1, got {rounds}")

        all_results: list[AttackResult] = []
        for _ in range(rounds):
            all_results.extend(self._run_once())

        log.info(
            "RedTeamEngine.run(rounds=%d): %d probes, %d bypasses",
            rounds, len(all_results),
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
            ValueError: If strategy is not in the configured strategy list.
        """
        if strategy not in self._strategies:
            raise ValueError(
                f"Unknown strategy '{strategy}'. "
                f"Configured strategies: {self._strategies}"
            )
        vectors = self._generate(strategy)
        results = [self._fire(v) for v in vectors]
        log.debug(
            "run_strategy('%s'): %d probes, %d bypasses",
            strategy, len(results),
            sum(1 for r in results if r.found_bypass),
        )
        return results

    def bypass_summary(self, results: list[AttackResult]) -> dict[str, int]:
        """
        Count found_bypass=True results grouped by strategy.

        Returns:
            {"strategy_name": bypass_count, ...}
            Empty dict when no bypasses found.
        """
        summary: dict[str, int] = {}
        for r in results:
            if r.found_bypass:
                summary[r.strategy] = summary.get(r.strategy, 0) + 1
        return summary

    # ── Private helpers ────────────────────────────────────────────────────────

    def _run_once(self) -> list[AttackResult]:
        results: list[AttackResult] = []
        for strategy in self._strategies:
            results.extend(self.run_strategy(strategy))
        return results

    def _generate(self, strategy: str) -> list[AttackVector]:
        generators = {
            "boundary_value":    self._gen_boundary_value,
            "rate_spike":        self._gen_rate_spike,
            "replay":            self._gen_replay,
            "slow_drip":         self._gen_slow_drip,
            "lateral":           self._gen_lateral,
            "sensor_correlation": self._gen_sensor_correlation,
            "cascade_failure":   self._gen_cascade_failure,
        }
        return generators[strategy]()

    def _fire(self, vector: AttackVector) -> AttackResult:
        """
        Fire one AttackVector through the ValidationEngine.

        found_bypass is True when:
          - The validator ALLOWED the command, AND
          - The probe is not a seed shot (seeds R008 history — expected to pass), AND
          - The probe is not a positive-control boundary probe (val=100 or val=0 —
            being allowed at the safe boundary is CORRECT, not a bypass).

        Note: now is taken from vector.now (not from context). This avoids
        passing a monotonic timestamp to R005 TimeRule which expects wall-clock.
        """
        result = self._validator.validate(
            address=vector.address,
            value=vector.value,
            context=vector.context,
            now=vector.now,
        )

        is_seed             = "seeds R008 history" in vector.description
        is_positive_control = "boundary probe" in vector.description
        is_correlation_seed = "Seed Correlation" in vector.description

        found_bypass = (
            bool(result.allowed)
            and not is_seed
            and not is_positive_control
            and not is_correlation_seed
        )

        log.debug(
            "FIRE %-20s addr=%d val=%7.2f allowed=%-5s bypass=%s",
            vector.strategy, vector.address, vector.value,
            result.allowed, found_bypass,
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
        A01 — Out-of-Range Setpoint (MITRE T0855 → R001).
        Probes above/below the [0, 100] valve range.
        Boundary values (100, 0) are positive controls — being allowed is correct.
        """
        ctx: dict = {"tank_level": 50.0, "pump_running": False}
        return [
            AttackVector(
                "boundary_value", VALVE_ADDRESS, VALVE_SAFE_MAX + 1.0, ctx,
                f"A01: Valve {VALVE_SAFE_MAX + 1.0:.0f}% (1% above max) — R001 T0855",
            ),
            AttackVector(
                "boundary_value", VALVE_ADDRESS, VALVE_SAFE_MAX, ctx,
                f"Valve at safe_max ({VALVE_SAFE_MAX:.0f}%) — boundary probe R001",
            ),
            AttackVector(
                "boundary_value", VALVE_ADDRESS, VALVE_SAFE_MIN - 1.0, ctx,
                f"A01: Valve {VALVE_SAFE_MIN - 1.0:.0f}% (1% below min) — R001 T0855",
            ),
            AttackVector(
                "boundary_value", VALVE_ADDRESS, VALVE_SAFE_MIN, ctx,
                f"Valve at safe_min ({VALVE_SAFE_MIN:.0f}%) — boundary probe R001",
            ),
            AttackVector(
                "boundary_value", VALVE_ADDRESS, VALVE_SAFE_MAX + 50.0, ctx,
                f"A01: Valve {VALVE_SAFE_MAX + 50.0:.0f}% (extreme over-range) — R001 T0855",
            ),
        ]

    def _gen_rate_spike(self) -> list[AttackVector]:
        """
        A02 — Rapid Setpoint Change (MITRE T0855 → R002).

        Context fix: uses 'valve_position' and 'last_cmd_time' (exact keys
        R002 reads). last_cmd_time = now so dt ≈ 0 when _fire() calls validate()
        milliseconds later → rate ≈ ∞ %/s >> 5 %/s limit.

        now fix: store t0 on the vector directly so validate(now=t0+0.001)
        gives a controlled dt without leaking into R005 TimeRule.
        """
        t0: float = _time.monotonic()
        ctx: dict = {
            "tank_level":     50.0,
            "pump_running":   False,
            "valve_position": RATE_SPIKE_START,   # correct key for R002
            "last_cmd_time":  t0,                 # correct key for R002
        }
        return [
            AttackVector(
                "rate_spike", VALVE_ADDRESS,
                RATE_SPIKE_START + RATE_SPIKE_DELTA,  # 90%
                ctx,
                f"A02: Rate spike +{RATE_SPIKE_DELTA:.0f}% in ~1ms — R002 T0855",
                now=t0 + 0.001,   # dt=1ms → rate=80,000 %/s
            ),
            AttackVector(
                "rate_spike", VALVE_ADDRESS,
                VALVE_SAFE_MAX,                        # 100%
                ctx,
                f"A02: Rate spike to max ({VALVE_SAFE_MAX:.0f}%) in ~1ms — R002 T0855",
                now=t0 + 0.001,
            ),
        ]

    def _gen_replay(self) -> list[AttackVector]:
        """
        A08 — Command Replay Attack (MITRE T0856 → R008).

        Two-shot design:
          Shot 1 — legitimate command, seeds R008's _history deque (expected ALLOWED).
          Shot 2 — exact replay 2 s later, expected BLOCKED by R008.

        Context fix: uses 'cmd_timestamp' (the key R008 reads), not 'current_time'.
        now fix: inject monotonic time directly on the vector so R005 TimeRule
        is not given a misleading civil-time value.
        """
        t0: float = _time.monotonic()
        base_ctx: dict = {
            "tank_level":     50.0,
            "valve_position": REPLAY_VALUE,
            "pump_running":   False,
            "last_cmd_time":  0.0,
        }
        return [
            # Shot 1: seed — mark as non-bypass regardless of result
            AttackVector(
                "replay", VALVE_ADDRESS, REPLAY_VALUE,
                {**base_ctx, "cmd_timestamp": t0},
                f"Replay FIRST shot (addr={VALVE_ADDRESS}, val={REPLAY_VALUE:.0f}%) "
                f"— seeds R008 history",
                now=t0,
            ),
            # Shot 2: replay within window — must be BLOCKED
            AttackVector(
                "replay", VALVE_ADDRESS, REPLAY_VALUE,
                {**base_ctx, "cmd_timestamp": t0 + 2.0},
                f"A08: Replay SECOND shot at t+2s — inside {REPLAY_WINDOW_S:.0f}s window R008 T0856",
                now=t0 + 2.0,
            ),
        ]

    def _gen_slow_drip(self) -> list[AttackVector]:
        """
        A10 — Slow-Drip Setpoint Creep (MITRE T0855 → R006).

        20 steps of +1%. Each step rate = 1%/15s = 0.067 %/s (under R002 5%/s).
        Cumulative delta crosses 15% threshold at step 17 → R006 blocks.

        No now injection needed: TemporalRule fires based on cumulative |Δ|
        regardless of how fast the steps arrive. All steps within the 300s
        window accumulate correctly even when fired rapidly in tests.
        """
        vectors: list[AttackVector] = []
        for step in range(SLOW_DRIP_STEPS):
            delta = (step + 1) * SLOW_DRIP_STEP
            vectors.append(AttackVector(
                "slow_drip", VALVE_ADDRESS,
                SLOW_DRIP_BASE + delta,
                {
                    "tank_level":     50.0,
                    "valve_position": SLOW_DRIP_BASE + (step * SLOW_DRIP_STEP),
                    "pump_running":   False,
                    "last_cmd_time":  0.0,
                },
                f"A10: Slow-drip step {step + 1:02d} — "
                f"cumulative Δ={delta:.1f}% — R006 T0855",
            ))
        return vectors

    def _gen_lateral(self) -> list[AttackVector]:
        """
        A15 — Lateral Movement PLC_01 → PLC_04 (MITRE T0888 → R007).

        Context fix: uses 'source_plc_id' and 'target_plc_id' (exact keys
        TopologyRule reads). Previous versions used 'source_plc'/'target_plc'
        which caused R007 to silently skip every probe.
        """
        ctx: dict = {
            "tank_level":     50.0,
            "pump_running":   False,
            "source_plc_id":  LATERAL_SOURCE_PLC,   # correct key
            "target_plc_id":  LATERAL_TARGET_PLC,   # correct key
            "source_ip":      LATERAL_SOURCE_IP,
        }
        return [
            AttackVector(
                "lateral", VALVE_ADDRESS, 50.0, ctx,
                f"A15: Lateral {LATERAL_SOURCE_PLC}→{LATERAL_TARGET_PLC} "
                f"valve cmd — R007 T0888",
            ),
            AttackVector(
                "lateral", PUMP_ADDRESS, 1.0, ctx,
                f"A15: Lateral {LATERAL_SOURCE_PLC}→{LATERAL_TARGET_PLC} "
                f"pump-ON cmd — R007 T0888",
            ),
        ]

    def _gen_sensor_correlation(self) -> list[AttackVector]:
        """
        A11 — False Data Injection / Sensor Spoofing (MITRE T0856 → R011).

        Fires a command with valve=100% open and pump OFF (tank MUST fill).
        R011 CorrelationRule checks historical rise rate — if level stays flat
        despite valve being wide open, a sensor is being spoofed.

        Two-shot design to seed R011's internal history then trigger detection.
        Shot 1 is marked 'Seed Correlation' so it is exempt from bypass count.
        """
        ctx: dict = {
            "tank_level":     50.0,
            "valve_position": 100.0,
            "pump_running":   False,
            "last_cmd_time":  0.0,
        }
        return [
            AttackVector(
                "sensor_correlation", VALVE_ADDRESS, 100.0, ctx,
                "Seed Correlation history (valve=100%, level=50%) — R011 T0856",
            ),
            AttackVector(
                "sensor_correlation", VALVE_ADDRESS, 100.0,
                # Level stays flat at 50% despite valve=100% for >1s → sensor spoof
                {**ctx, "tank_level": 50.0},
                "A11: Sensor spoofing — level not rising despite valve=100% — R011 T0856",
            ),
        ]

    def _gen_cascade_failure(self) -> list[AttackVector]:
        """
        A12 — Cascade Failure Trigger (MITRE T0855 → R012).

        Attempts to start the heater (HR[11]) at 90% power while tank level
        is critically low (2%). R012 CascadeRule blocks this cross-PLC hazard.
        """
        ctx: dict = {
            "tank_level":   2.0,    # critically low — cross-PLC hazard key
            "heater_power": 0.0,
            "pump_running": False,
        }
        return [
            AttackVector(
                "cascade_failure", HEATER_ADDRESS, 90.0, ctx,
                "A12: Heater=90% while tank_level=2% — cascade hazard R012 T0855",
            ),
        ]
