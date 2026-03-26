"""
topology_rule.py  —  R007 Multi-PLC Lateral Movement Detector
==============================================================
Layer 4  |  PhysicsGuard ICS Security Gateway

Novel Contribution #4  |  H3 fix

Detects attacks:
  A15 — Lateral Movement PLC→PLC  (MITRE T0888)

The gap this closes
───────────────────
plant_topology.py (Layer 0) implements a full directed graph of PLC
connectivity with BFS reachability, runtime path revocation, and all
D10–D13 design fixes applied.  However, it was never connected to the
validation pipeline — no rule referenced PlantTopology.is_authorised_path()
and build_water_tank_topology() was never called from modbus_server.py.

Attack A15 exploits this gap:
  An attacker injects a Modbus command with context claiming it originates
  from PLC_01 but targets PLC_04 (Emergency Shutdown).  All five existing
  rules (R001 range, R002 rate, R003 interlock, R004 auth, R005 time)
  check the COMMAND CONTENT — none check whether PLC_01 is even authorised
  to send commands to PLC_04.  The Stuxnet-style multi-hop lateral movement
  attack goes completely undetected.

R007 closes this by calling PlantTopology.is_authorised_path(src, dst)
on every command that carries source_plc_id / target_plc_id in its context.

Context key design (opt-in, skip-if-absent)
────────────────────────────────────────────
  context["source_plc_id"] : ID of the PLC that originated the command
                              e.g. "PLC_01"
  context["target_plc_id"] : ID of the PLC the command is destined for
                              e.g. "PLC_04"

  These keys are optional — if either is absent, R007 skips (pass-through).
  This mirrors AuthRule's behaviour for source_ip: internal calls and the
  physics loop do not carry PLC routing context and must not be blocked.

  The Modbus server (or a future Layer 3 bridge) injects these keys when
  the physical network source can be determined from the session context.

Priority design
───────────────
  R007 priority=8 — after R004 (5, identity/IP check) and before R001 (10).
  Rationale: if the command's origin PLC is not authorised to reach the
  target PLC, there is no value in running physics-aware rules.  Topology
  check is cheap (O(1) dict lookup in PlantTopology._allowed) and decisive.

  Full priority order with R007:
    R004  priority=5   IP whitelist (identity)
    R007  priority=8   topology / lateral movement  ← NEW
    R001  priority=10  value range
    R005  priority=15  time window
    R002  priority=20  rate-of-change
    R006  priority=25  temporal slow-drip
    R003  priority=30  pump interlock

Thread safety
─────────────
  R007 is STATELESS — it holds only an immutable reference to the
  PlantTopology instance.  All thread safety is delegated to
  PlantTopology._lock (already implemented in plant_topology.py).

Example::

    from plant_topology import build_water_tank_topology
    topo = build_water_tank_topology()
    topo.add_plc(PLCNode("PLC_04", "Emergency Shutdown", "192.168.1.4"))
    # PLC_01 → PLC_04 not in allowed paths
    rule = TopologyRule(topology=topo)

    ctx = {
        "source_plc_id": "PLC_01",
        "target_plc_id": "PLC_04",
        "tank_level": 50.0,
    }
    result = rule.evaluate(address=1, value=50.0, context=ctx)
    assert result.allowed is False   # lateral movement blocked

    # No PLC context → skip (physics loop, internal call)
    ctx2 = {"tank_level": 50.0}
    result2 = rule.evaluate(address=1, value=50.0, context=ctx2)
    assert result2.allowed is True   # skip — no routing context

Dissertation defence note
─────────────────────────
  "How does PhysicsGuard detect multi-hop lateral movement between PLCs?"

  Answer: "R007 TopologyRule wraps the Layer 0 PlantTopology graph.
  Every command that carries a source and target PLC ID is checked against
  the authorised-paths set.  A command injected as if from PLC_01 targeting
  PLC_04 is blocked immediately — before any physics rule runs — because
  PLC_01 → PLC_04 is not an authorised path in the topology.  Path
  revocation at runtime (topo.revoke_path()) lets the operator isolate a
  compromised PLC without restarting the server.  This is Novel
  Contribution #4 — no open-source ICS gateway checks Stuxnet-style
  multi-hop topology violations today."
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from src.rules.base_rule import (
    BaseRule,
    RuleResult,
    pass_result,
    block_result,
    SEVERITY_CRITICAL,
)

if TYPE_CHECKING:
    from plant_topology import PlantTopology

log = logging.getLogger(__name__)


class TopologyRule(BaseRule):
    """
    R007 — Multi-PLC Lateral Movement Detector  (MITRE T0888)

    Blocks commands where the source PLC is not authorised to send
    commands to the target PLC according to the PlantTopology graph.

    Skip conditions (pass immediately, no block):
      1. context["source_plc_id"] is absent — internal call, skip
      2. context["target_plc_id"] is absent — target unknown, skip
      3. source == target  — same-PLC write, always allowed
         (PlantTopology.is_authorised_path() short-circuits this too)

    Attributes (class-level):
        rule_id   : "R007"
        priority  : 8  (after R004 auth=5, before R001 range=10)
        severity  : CRITICAL
        mitre_tag : "T0888"

    Args:
        topology      : PlantTopology instance (Layer 0).
        default_target: fallback target PLC ID used when
                        context["target_plc_id"] is absent but
                        context["source_plc_id"] IS present.
                        None (default) means skip if target absent.
    """

    rule_id:   str = "R007"
    priority:  int = 8          # After R004 (5), before R001 (10)
    severity:  str = SEVERITY_CRITICAL
    mitre_tag: str = "T0888"    # Lateral Movement

    def __init__(
        self,
        topology:       "PlantTopology",
        default_target: str | None = None,
    ) -> None:
        """
        Args:
            topology       : PlantTopology instance with PLCs and
                             authorised paths already configured.
            default_target : if set, used as target_plc_id when the
                             context does not carry one.  Useful for
                             single-PLC deployments where every command
                             implicitly targets the same PLC.
                             Default None → skip if target absent.
        """
        self._topology      = topology
        self._default_target = default_target

    def evaluate(
        self,
        address: int,
        value:   float,
        context: dict[str, Any],
        now:     float | None = None,   # unused — satisfies BaseRule contract
    ) -> RuleResult:
        """
        Block if source_plc_id → target_plc_id is not an authorised path.

        Reads source_plc_id and target_plc_id from context.  If either is
        absent (and no default_target is configured), the rule skips —
        matching AuthRule's opt-in pattern for source_ip.

        Complexity: O(1) — PlantTopology.is_authorised_path() is a
        frozenset lookup under a threading.Lock.

        Args:
            address : register being written (not used for topology check)
            value   : proposed new value (not used for topology check)
            context : must contain source_plc_id and target_plc_id for
                      the check to fire; missing keys → skip (pass)
            now     : unused (satisfies BaseRule.evaluate signature)
        """
        src: str | None = context.get("source_plc_id")
        dst: str | None = context.get("target_plc_id") or self._default_target

        # ── Skip if routing context is absent ─────────────────────────────
        # Internal calls and the physics loop do not carry PLC IDs.
        if src is None:
            return pass_result(
                self.rule_id,
                "R007 skipped (no source_plc_id in context — internal call)",
            )

        if dst is None:
            return pass_result(
                self.rule_id,
                "R007 skipped (no target_plc_id in context — target unknown)",
            )

        src = str(src).strip()
        dst = str(dst).strip()

        # ── Authorised path check ──────────────────────────────────────────
        # is_authorised_path() short-circuits when src == dst (same PLC)
        try:
            authorised = self._topology.is_authorised_path(src, dst)
        except Exception:
            # Defensive: topology lookup raised (e.g. PLC not registered).
            # Log and skip rather than crashing the validation pipeline.
            log.exception(
                "TopologyRule R007: is_authorised_path(%r, %r) raised — skipping",
                src, dst,
            )
            return pass_result(
                self.rule_id,
                f"R007 skipped (topology lookup error for {src!r}→{dst!r})",
            )

        if authorised:
            return pass_result(
                self.rule_id,
                f"R007 PASS | topology OK: {src!r} → {dst!r} is authorised",
            )

        # ── Block — lateral movement detected ─────────────────────────────
        reason = (
            f"R007 TOPOLOGY VIOLATION | "
            f"lateral movement: {src!r} → {dst!r} is NOT an authorised path | "
            f"MITRE {self.mitre_tag}"
        )
        log.warning(
            "TopologyRule R007: lateral movement BLOCKED | "
            "src=%r dst=%r addr=%d val=%.2f | MITRE %s",
            src, dst, address, value, self.mitre_tag,
        )
        return block_result(
            rule_id=self.rule_id,
            reason=reason,
            severity=self.severity,
            mitre_tag=self.mitre_tag,
            metadata={
                "source_plc_id": src,
                "target_plc_id": dst,
                "address":       address,
                "value":         value,
            },
        )
