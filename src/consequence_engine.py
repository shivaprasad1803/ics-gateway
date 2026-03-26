"""
consequence_engine.py  —  Forward Physics Damage Simulator
===========================================================
Layer 0  |  PhysicsGuard ICS Security Gateway
Foundation deliverable: novel contribution #1 — given current
physical state + a proposed write command, forward-simulate the
plant to predict whether physical damage will occur.

Novel academic contribution:
  Every blocked command comes with a ConsequenceResult that says
  "if this command had been allowed, overflow would occur in 4.2 s".
  No open-source ICS tool does this today.

Owns:
  - ConsequenceResult dataclass (the answer)
  - ConsequenceEngine.evaluate() — deterministic forward simulation

Does NOT own:
  - Validation/blocking decisions  (validation_engine.py — Layer 4)
  - Actual physics state           (water_tank.py — Layer 1)
  - Alerting                       (alerting.py — Layer 5)

Design:
  - Stateless: takes state + params as inputs, returns result
  - Pure Python: no I/O, no locks — safe to call from any thread
  - Fast: runs a tight inner loop, completes in < 1 ms for 60-s horizon

Design-fix notes:
  D06 — batch_evaluate threads tank_level forward between steps via
        _simulate_final_level(); without this every step in a batch
        simulates from the same initial level, making multi-step attack
        sequences invisible to the engine.
  D07 — TankParams.from_controller() factory keeps constants in sync
        with WaterTankController without a runtime circular import
        (TYPE_CHECKING guard).
  D08 — DAMAGE_EMPTY sets damage_predicted=True; an emptying tank
        requires operator action. ConsequenceResult docstring explains
        the full severity/damage_predicted contract.
  D09 — Overflow severity threshold extracted to EMERGENCY_TIME_THRESHOLD_S
        class constant; previously a magic literal 5.0.

Terminology note:
  The pump-running-while-tank-empty condition is called DRY_RUN throughout
  this module (DAMAGE_DRY_RUN). Earlier handoff documents used the term
  DRAIN_OUT — that name is retired. DRY_RUN is the canonical term.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # D07: import only for type hints — no runtime circular dependency.
    from water_tank import WaterTankController

__all__ = [
    "ConsequenceResult",
    "TankParams",
    "ConsequenceEngine",
    "SEVERITY_NONE",
    "SEVERITY_WARNING",
    "SEVERITY_CRITICAL",
    "SEVERITY_EMERGENCY",
    "DAMAGE_NONE",
    "DAMAGE_OVERFLOW",
    "DAMAGE_DRY_RUN",   # canonical name — do NOT use DRAIN_OUT
    "DAMAGE_EMPTY",
]

log = logging.getLogger(__name__)

# ── Severity constants ────────────────────────────────────────────────────────

SEVERITY_NONE      = "NONE"
SEVERITY_WARNING   = "WARNING"
SEVERITY_CRITICAL  = "CRITICAL"
SEVERITY_EMERGENCY = "EMERGENCY"

# ── Damage type constants ─────────────────────────────────────────────────────

DAMAGE_NONE     = "NONE"
DAMAGE_OVERFLOW = "OVERFLOW"
DAMAGE_DRY_RUN  = "DRY_RUN"    # pump running while tank is empty — canonical name
DAMAGE_EMPTY    = "EMPTY"


@dataclass(frozen=True, slots=True)
class ConsequenceResult:
    """
    Result of a forward-physics simulation for a single proposed command.

    Fields
    ------
    damage_predicted : bool
        True if ANY damage or action-required state is reached within the
        simulation horizon.  Covers OVERFLOW, DRY_RUN, and EMPTY (D08).
        False only when severity == NONE.

    severity : str
        "NONE" | "WARNING" | "CRITICAL" | "EMERGENCY"
        EMERGENCY reserved for imminent overflow
        (< EMERGENCY_TIME_THRESHOLD_S seconds away — D09).

    predicted_time_to_damage : float
        Seconds until the damage/action-required state is reached.
        -1.0 when damage_predicted is False.

    damage_type : str
        "NONE" | "OVERFLOW" | "DRY_RUN" | "EMPTY"
        Note: DRY_RUN (pump ON, tank empty) was called DRAIN_OUT in early
        handoff documents — DRY_RUN is the canonical name used everywhere.

    description : str
        Human-readable explanation for logs / alert messages.

    simulated_horizon_s : float
        How many seconds were actually simulated (<= ConsequenceEngine.HORIZON_S).

    API contract note (D08)
    -----------------------
    damage_predicted == True does NOT always mean immediate physical destruction.
    DAMAGE_EMPTY with severity WARNING signals the tank will run dry and needs
    operator intervention even if the pump is OFF.
    Always check damage_type for the exact condition.
    """

    damage_predicted:         bool
    severity:                 str
    predicted_time_to_damage: float
    damage_type:              str
    description:              str
    simulated_horizon_s:      float


@dataclass(frozen=True, slots=True)
class TankParams:
    """
    Physical constants for the tank simulation.

    Mirrors WaterTankController constants so the consequence engine
    can be used without importing water_tank at runtime (avoids circular
    imports).

    Use TankParams.from_controller(tank) to construct from a live controller
    and keep the two in sync automatically (D07).
    """

    capacity_liters:   float = 1_000.0
    max_flow_rate_lps: float =    10.0
    drain_rate_lps:    float =     3.0
    overflow_level:    float =    95.0
    dry_run_level:     float =    10.0

    @classmethod
    def from_controller(cls, tank: "WaterTankController") -> "TankParams":
        """
        D07: Construct TankParams from a live WaterTankController.
        Guarantees the two sets of constants never drift apart.
        """
        return cls(
            capacity_liters=tank.TANK_CAPACITY_LITERS,
            max_flow_rate_lps=tank.MAX_FLOW_RATE_LPS,
            drain_rate_lps=tank.DRAIN_RATE_LPS,
            overflow_level=tank.OVERFLOW_LEVEL,
            dry_run_level=tank.DRY_RUN_LEVEL,
        )


class ConsequenceEngine:
    """
    Stateless forward simulator.

    evaluate() applies the proposed write then steps the physics model
    at TICK_S intervals for up to HORIZON_S seconds, checking damage
    conditions at each tick.
    """

    HORIZON_S: float = 60.0
    TICK_S:    float = 0.25

    # D09: named constant for the overflow severity boundary.
    EMERGENCY_TIME_THRESHOLD_S: float = 5.0

    def evaluate(
        self,
        current_state:    dict,
        proposed_address: int,
        proposed_value:   float,
        params:           TankParams | None = None,
    ) -> ConsequenceResult:
        """
        Forward-simulate the plant with the proposed command applied.

        Args:
            current_state:    output of WaterTankController.get_state()
            proposed_address: 0-based register address (1=valve, 2=pump)
            proposed_value:   the value to apply
            params:           TankParams; uses defaults if None

        Returns:
            ConsequenceResult with damage prediction.
        """
        if params is None:
            params = TankParams()

        level:   float = float(current_state.get("tank_level", 50.0))
        valve:   float = float(current_state.get("valve_position", 0.0))
        pump_on: bool  = bool(current_state.get("pump_running", False))

        if proposed_address == 1:
            valve = float(proposed_value)
        elif proposed_address == 2:
            pump_on = bool(proposed_value)

        valve = max(0.0, min(100.0, valve))

        elapsed: float = 0.0
        ticks:   int   = int(self.HORIZON_S / self.TICK_S)

        for _ in range(ticks):
            fill_lps  = (valve / 100.0) * params.max_flow_rate_lps
            drain_lps = params.drain_rate_lps if pump_on else 0.0
            net_lps   = fill_lps - drain_lps
            delta_pct = (net_lps * self.TICK_S / params.capacity_liters) * 100.0
            level     = max(0.0, min(100.0, level + delta_pct))
            elapsed  += self.TICK_S

            if level >= params.overflow_level:
                severity = (
                    SEVERITY_EMERGENCY
                    if elapsed < self.EMERGENCY_TIME_THRESHOLD_S   # D09
                    else SEVERITY_CRITICAL
                )
                return ConsequenceResult(
                    damage_predicted=True,
                    severity=severity,
                    predicted_time_to_damage=round(elapsed, 2),
                    damage_type=DAMAGE_OVERFLOW,
                    description=(
                        f"OVERFLOW predicted in {elapsed:.1f} s — "
                        f"tank will reach {params.overflow_level}% at current "
                        f"valve={valve:.0f}%, pump={'ON' if pump_on else 'OFF'}"
                    ),
                    simulated_horizon_s=elapsed,
                )

            # DRY_RUN: pump is ON and tank has emptied — mechanical damage
            if pump_on and level <= 0.0:
                return ConsequenceResult(
                    damage_predicted=True,
                    severity=SEVERITY_CRITICAL,
                    predicted_time_to_damage=round(elapsed, 2),
                    damage_type=DAMAGE_DRY_RUN,   # canonical — not DRAIN_OUT
                    description=(
                        f"DRY-RUN predicted in {elapsed:.1f} s — "
                        f"pump ON but tank will empty at "
                        f"drain={params.drain_rate_lps} L/s"
                    ),
                    simulated_horizon_s=elapsed,
                )

            # D08: damage_predicted=True — empty tank requires operator action
            if not pump_on and level <= 0.0:
                return ConsequenceResult(
                    damage_predicted=True,
                    severity=SEVERITY_WARNING,
                    predicted_time_to_damage=round(elapsed, 2),
                    damage_type=DAMAGE_EMPTY,
                    description=(
                        f"Tank will empty in {elapsed:.1f} s "
                        f"(pump OFF, drain={params.drain_rate_lps} L/s)"
                    ),
                    simulated_horizon_s=elapsed,
                )

        return ConsequenceResult(
            damage_predicted=False,
            severity=SEVERITY_NONE,
            predicted_time_to_damage=-1.0,
            damage_type=DAMAGE_NONE,
            description=(
                f"No damage predicted in {self.HORIZON_S:.0f} s simulation "
                f"(valve={valve:.0f}%, pump={'ON' if pump_on else 'OFF'}, "
                f"level_end={level:.1f}%)"
            ),
            simulated_horizon_s=self.HORIZON_S,
        )

    def _simulate_final_level(
        self,
        level:   float,
        valve:   float,
        pump_on: bool,
        params:  TankParams,
    ) -> float:
        """
        D06 helper: run the physics loop for HORIZON_S and return the final
        tank level (or the level at which a boundary condition fires).

        Used by batch_evaluate() to thread tank_level forward between steps.
        Mirrors evaluate() exactly so the two never diverge.
        """
        ticks: int = int(self.HORIZON_S / self.TICK_S)
        for _ in range(ticks):
            fill_lps  = (valve / 100.0) * params.max_flow_rate_lps
            drain_lps = params.drain_rate_lps if pump_on else 0.0
            net_lps   = fill_lps - drain_lps
            delta_pct = (net_lps * self.TICK_S / params.capacity_liters) * 100.0
            level     = max(0.0, min(100.0, level + delta_pct))
            if level >= params.overflow_level:
                break
            if level <= 0.0:
                break
        return level

    def batch_evaluate(
        self,
        current_state: dict,
        writes:        list[tuple[int, float]],
        params:        TankParams | None = None,
    ) -> list[ConsequenceResult]:
        """
        Evaluate a sequence of writes in order, threading state through.
        Used by RedTeamEngine (Layer 8) to simulate attack sequences.

        D06 fix: tank_level is propagated between steps via
        _simulate_final_level(). Previously only valve_position and
        pump_running were threaded forward; tank_level was frozen at the
        initial value, making multi-step attack simulations unreliable.
        """
        if params is None:
            params = TankParams()

        results: list[ConsequenceResult] = []
        state = dict(current_state)

        for address, value in writes:
            result = self.evaluate(state, address, value, params)
            results.append(result)

            if address == 1:
                state["valve_position"] = float(value)
            elif address == 2:
                state["pump_running"] = bool(value)

            # D06: thread tank_level forward using post-write valve/pump values
            state["tank_level"] = self._simulate_final_level(
                level=float(state.get("tank_level", 50.0)),
                valve=max(0.0, min(100.0, float(state.get("valve_position", 0.0)))),
                pump_on=bool(state.get("pump_running", False)),
                params=params,
            )

        return results
