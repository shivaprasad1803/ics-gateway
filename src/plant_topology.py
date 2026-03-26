"""
plant_topology.py  —  Digital Twin Plant Graph
===============================================
Layer 0  |  PhysicsGuard ICS Security Gateway
Foundation deliverable: multi-PLC topology model that maps
how PLCs connect in the physical plant.

Owns:
  - PLCNode definitions (id, ip, register map, neighbours)
  - PlantTopology graph (add nodes, connect edges, query paths)
  - Lateral-movement detection helper

Does NOT own:
  - Validation logic  (validation_engine.py — Layer 4)
  - Physics simulation (water_tank.py — Layer 1)
  - Network I/O

Design notes:
  - Starts with 1 PLC (water tank); grows to 4 by Week 6.
  - Undirected connectivity graph + separate directed allowed_paths.
  - Thread-safe: all mutations acquire self._lock.

Design-fix notes:
  D10 — get_reachable() snapshots _edges/_nodes under lock, runs BFS
        outside it; large topologies no longer block other operations.
  D11 — revoke_path() and disconnect() added for runtime PLC isolation.
  D12 — connect() raises ValueError on self-loops; get_neighbours()
        would otherwise return a PLC as its own neighbour.
  D13 — _edges stores frozenset[str] pairs instead of (min, max) tuples;
        orderless by definition, immune to subtle ordering bugs.
"""

import logging
import threading
from collections import deque
from dataclasses import dataclass, field

__all__ = ["PLCNode", "PlantTopology", "build_water_tank_topology"]

log = logging.getLogger(__name__)


@dataclass(slots=True)
class PLCNode:
    """
    Represents a single PLC in the plant.

    plc_id      : unique identifier, e.g. "PLC_01"
    name        : human-readable label
    ip          : expected source IP for commands TO this PLC
    port        : Modbus TCP port (default 5020)
    register_map: {0-based address: description}
    """

    plc_id:       str
    name:         str
    ip:           str
    port:         int = 5020
    register_map: dict[int, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.plc_id:
            raise ValueError("PLCNode.plc_id must not be empty")
        if not self.ip:
            raise ValueError("PLCNode.ip must not be empty")
        if not (1 <= self.port <= 65535):
            raise ValueError(f"PLCNode.port {self.port} out of range [1, 65535]")


class PlantTopology:
    """
    Directed graph of PLC nodes in the physical plant.

    Usage::

        topo = PlantTopology()
        topo.add_plc(PLCNode("PLC_01", "Water Tank", "127.0.0.1"))
        topo.add_plc(PLCNode("PLC_02", "Valve PLC",  "127.0.0.2"))
        topo.connect("PLC_01", "PLC_02")
        topo.allow_path("PLC_01", "PLC_02")
        assert topo.is_authorised_path("PLC_01", "PLC_02") is True

        # Isolate a compromised PLC at runtime (D11):
        topo.revoke_path("PLC_01", "PLC_02")
        topo.disconnect("PLC_01", "PLC_02")
    """

    def __init__(self) -> None:
        self._lock:    threading.Lock         = threading.Lock()
        self._nodes:   dict[str, PLCNode]     = {}
        # D13: frozenset pairs — orderless, immune to min/max tricks
        self._edges:   set[frozenset[str]]    = set()
        self._allowed: set[tuple[str, str]]   = set()

    # ── Node management ─────────────────────────────────────────────────

    def add_plc(self, node: PLCNode) -> None:
        with self._lock:
            if node.plc_id in self._nodes:
                raise ValueError(f"PLC '{node.plc_id}' already registered")
            self._nodes[node.plc_id] = node
            log.info("Topology: registered PLC '%s' (%s) at %s:%d",
                     node.plc_id, node.name, node.ip, node.port)

    def get_plc(self, plc_id: str) -> PLCNode:
        with self._lock:
            return self._nodes[plc_id]

    def get_all_plcs(self) -> list[PLCNode]:
        with self._lock:
            return list(self._nodes.values())

    # ── Edge management ──────────────────────────────────────────────────

    def connect(self, plc_id_a: str, plc_id_b: str) -> None:
        """
        Add undirected process-flow edge between two PLCs.
        D12: raises ValueError on self-loops.
        """
        if plc_id_a == plc_id_b:                   # D12
            raise ValueError(
                f"Cannot connect PLC '{plc_id_a}' to itself — "
                "self-loops are not valid process-flow edges"
            )
        with self._lock:
            self._assert_registered(plc_id_a)
            self._assert_registered(plc_id_b)
            self._edges.add(frozenset({plc_id_a, plc_id_b}))   # D13
            log.info("Topology: connected '%s' ↔ '%s'", plc_id_a, plc_id_b)

    def disconnect(self, plc_id_a: str, plc_id_b: str) -> None:
        """
        D11: Remove process-flow edge. Idempotent. Raises on self-loop.
        Used to isolate a compromised PLC at runtime.
        """
        if plc_id_a == plc_id_b:
            raise ValueError(
                f"Cannot disconnect PLC '{plc_id_a}' from itself"
            )
        with self._lock:
            self._assert_registered(plc_id_a)
            self._assert_registered(plc_id_b)
            self._edges.discard(frozenset({plc_id_a, plc_id_b}))
            log.info("Topology: disconnected '%s' ↔ '%s'", plc_id_a, plc_id_b)

    def get_neighbours(self, plc_id: str) -> list[str]:
        with self._lock:
            self._assert_registered(plc_id)
            result: list[str] = []
            for edge in self._edges:
                if plc_id in edge:
                    (other,) = edge - {plc_id}
                    result.append(other)
            return result

    # ── Authorised paths ─────────────────────────────────────────────────

    def allow_path(self, src_plc_id: str, dst_plc_id: str) -> None:
        with self._lock:
            self._assert_registered(src_plc_id)
            self._assert_registered(dst_plc_id)
            self._allowed.add((src_plc_id, dst_plc_id))
            log.info("Topology: authorised '%s' → '%s'", src_plc_id, dst_plc_id)

    def revoke_path(self, src_plc_id: str, dst_plc_id: str) -> None:
        """
        D11: Remove authorised command path. Idempotent.
        Used to isolate a compromised PLC at runtime without restart.
        """
        with self._lock:
            self._assert_registered(src_plc_id)
            self._assert_registered(dst_plc_id)
            self._allowed.discard((src_plc_id, dst_plc_id))
            log.info("Topology: revoked '%s' → '%s'", src_plc_id, dst_plc_id)

    def is_authorised_path(self, src_plc_id: str, dst_plc_id: str) -> bool:
        """Same-PLC writes are always allowed (src == dst short-circuits)."""
        if src_plc_id == dst_plc_id:
            return True
        with self._lock:
            return (src_plc_id, dst_plc_id) in self._allowed

    def get_reachable(self, plc_id: str) -> list[str]:
        """
        BFS from plc_id over undirected connectivity graph.
        Returns sorted list of reachable PLCs (excludes start node).

        D10: lock held only to snapshot edges/nodes; BFS runs outside
        the lock so large topologies don't block concurrent operations.
        """
        # Snapshot under lock (D10)
        with self._lock:
            if plc_id not in self._nodes:
                return []
            edges: frozenset[frozenset[str]] = frozenset(self._edges)
            nodes: set[str]                  = set(self._nodes)

        # BFS on immutable snapshot — no lock held
        if plc_id not in nodes:
            return []

        visited: set[str]   = {plc_id}
        queue:   deque[str] = deque([plc_id])

        while queue:
            current = queue.popleft()
            for edge in edges:
                if current in edge:
                    (other,) = edge - {current}
                    if other not in visited:
                        visited.add(other)
                        queue.append(other)

        visited.discard(plc_id)
        return sorted(visited)

    # ── Internal helpers ─────────────────────────────────────────────────

    def _assert_registered(self, plc_id: str) -> None:
        """Raise KeyError if plc_id not registered. Must be called inside _lock."""
        if plc_id not in self._nodes:
            raise KeyError(f"PLC '{plc_id}' is not registered in this topology")


# ── Pre-built topology ────────────────────────────────────────────────────────

def build_water_tank_topology() -> PlantTopology:
    """
    4-PLC water treatment plant topology.

    Physical process flow (undirected connectivity):
        PLC_01 (Water Tank) ↔ PLC_02 (Valve Controller)
        PLC_02 (Valve)      ↔ PLC_03 (Pressure Monitor)
        PLC_03 (Pressure)   ↔ PLC_04 (Emergency Shutdown)

    Authorised command paths (directed):
        PLC_01 → PLC_01  self-write (always allowed; explicit for clarity)
        PLC_01 → PLC_02  tank controller → valve controller
        PLC_02 → PLC_03  valve → pressure monitor
        PLC_03 → PLC_04  pressure → emergency shutdown

    Deliberately NOT authorised:
        PLC_01 → PLC_04  ← A15 lateral movement attack path (MITRE T0888)

    Bug 4 fix: the previous implementation registered only PLC_01.
    When RedTeamEngine fired lateral probes (PLC_01 → PLC_04), the
    topology lookup raised KeyError on PLC_04 not being registered.
    TopologyRule caught the exception, logged a skip, and allowed the
    probe through — producing a false bypass result even after Bug 3
    (wrong context keys) was fixed.  All 4 PLCs must be registered.
    """
    topo = PlantTopology()

    # ── PLC nodes ─────────────────────────────────────────────────────────
    plc01 = PLCNode(
        plc_id="PLC_01",
        name="Water Tank PLC",
        ip="127.0.0.1",
        port=5020,
        register_map={
            0: "TankLevel   [READ-ONLY,  0–100 %]",
            1: "ValvePos    [READ-WRITE, 0–100 %, rate ≤ 5 %/s]",
            2: "PumpState   [READ-WRITE, 0=OFF 1=ON, dry-run interlock]",
        },
    )
    plc02 = PLCNode(
        plc_id="PLC_02",
        name="Valve Controller PLC",
        ip="127.0.0.2",
        port=5021,
        register_map={
            0: "ValvePosition [READ-WRITE, 0–100 %]",
            1: "ValveStatus   [READ-ONLY,  0=CLOSED 1=OPEN 2=FAULT]",
        },
    )
    plc03 = PLCNode(
        plc_id="PLC_03",
        name="Pressure Monitor PLC",
        ip="127.0.0.3",
        port=5022,
        register_map={
            0: "PressurePSI  [READ-ONLY,  0–300 PSI]",
            1: "ReliefValve  [READ-WRITE, 0=CLOSED 1=OPEN]",
        },
    )
    plc04 = PLCNode(
        plc_id="PLC_04",
        name="Emergency Shutdown PLC",
        ip="127.0.0.4",
        port=5023,
        register_map={
            0: "EStopActive     [READ-WRITE, 0=NORMAL 1=SHUTDOWN]",
            1: "MasterPumpState [READ-ONLY,  0=OFF 1=ON 2=FAULT]",
        },
    )

    for plc in (plc01, plc02, plc03, plc04):
        topo.add_plc(plc)

    # ── Process-flow edges (undirected) ───────────────────────────────────
    topo.connect("PLC_01", "PLC_02")   # tank ↔ valve
    topo.connect("PLC_02", "PLC_03")   # valve ↔ pressure
    topo.connect("PLC_03", "PLC_04")   # pressure ↔ emergency shutdown

    # ── Authorised command paths (directed) ───────────────────────────────
    # Self-write always allowed by is_authorised_path() short-circuit;
    # explicit call retained for documentation / audit log clarity.
    topo.allow_path("PLC_01", "PLC_01")   # tank self-write
    topo.allow_path("PLC_01", "PLC_02")   # tank → valve controller
    topo.allow_path("PLC_02", "PLC_03")   # valve → pressure
    topo.allow_path("PLC_03", "PLC_04")   # pressure → emergency shutdown
    # PLC_01 → PLC_04 is NOT allowed — this is the A15 lateral movement
    # attack path that R007 TopologyRule must block (MITRE T0888).

    return topo
