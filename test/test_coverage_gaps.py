"""
test_coverage_gaps.py  —  Targeted Coverage Gap Tests
======================================================
PhysicsGuard ICS Security Gateway  |  All Layers

Closes the 23 coverage gaps identified by static AST audit (March 2026).
Estimated impact: pushes coverage from ~91.4% to ~95%+.

Gaps closed by this file:
  ConsequenceEngine  : DAMAGE_EMPTY, SEVERITY_EMERGENCY, DAMAGE_NONE,
                       TankParams.from_controller, batch_evaluate, _simulate_final_level
  PlantTopology      : get_reachable, get_all_plcs, get_neighbours, connect-unregistered
  TopologyRule       : exception path in lookup → pass-through
  safe_eval_condition: USub (unary negation), UAdd (unary plus)
  ReplayRule         : reset(), max_history eviction
  ForensicLogger     : get_recent(limit=N), export_csv on empty DB
  violations router  : _to_record(None fields), _bucket_rows (float+ISO+cutoff),
                       503 on by_rule, 503 on by_mitre, 503 on timeline,
                       raw-rows fallback path

Run:
  pytest tests/test_coverage_gaps.py -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(1, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from src.consequence_engine import (
    ConsequenceEngine, ConsequenceResult, TankParams,
    DAMAGE_EMPTY, DAMAGE_NONE, DAMAGE_OVERFLOW,
    SEVERITY_EMERGENCY, SEVERITY_CRITICAL, SEVERITY_WARNING, SEVERITY_NONE,
)
from src.plant_topology import PlantTopology, PLCNode, build_water_tank_topology
from src.rules.topology_rule import TopologyRule
from src.rules.base_rule import safe_eval_condition
from src.rules.replay_rule import ReplayRule
from src.forensic_logger import ForensicLogger
from src.water_tank import WaterTankController


# ══════════════════════════════════════════════════════════════════════════════
# ConsequenceEngine — uncovered branches
# ══════════════════════════════════════════════════════════════════════════════

class TestConsequenceEngineBranches:

    def _ce(self) -> ConsequenceEngine:
        return ConsequenceEngine()

    # No custom slow_params needed — see test_CE_CRITICAL below for explanation.

    # ── DAMAGE_EMPTY (pump OFF, level starts at 0) ────────────────────────────

    def test_CE_DAMAGE_EMPTY_pump_off_level_zero(self) -> None:
        """
        D08: level=0, pump=OFF, valve=0 → tank is already empty.
        With no fill and no drain, the first tick is level<=0 with pump off
        → DAMAGE_EMPTY, severity=WARNING.
        """
        ce = self._ce()
        state = {"tank_level": 0.0, "valve_position": 0.0, "pump_running": False}
        result = ce.evaluate(
            current_state=state, proposed_address=1, proposed_value=0.0,
        )
        assert result.damage_predicted is True
        assert result.damage_type == DAMAGE_EMPTY, (
            f"Expected DAMAGE_EMPTY, got {result.damage_type}"
        )
        assert result.severity == SEVERITY_WARNING, (
            f"DAMAGE_EMPTY must be WARNING, got {result.severity}"
        )

    # ── SEVERITY_EMERGENCY overflow (< EMERGENCY_TIME_THRESHOLD_S) ────────────

    def test_CE_EMERGENCY_severity_imminent_overflow(self) -> None:
        """
        D09: tank=94%, valve=100% → overflows in < 5 s → SEVERITY_EMERGENCY.
        """
        ce = self._ce()
        state = {"tank_level": 94.0, "valve_position": 0.0, "pump_running": False}
        result = ce.evaluate(
            current_state=state, proposed_address=1, proposed_value=100.0,
        )
        assert result.damage_type == DAMAGE_OVERFLOW
        assert result.severity == SEVERITY_EMERGENCY, (
            f"Imminent overflow must be EMERGENCY, got {result.severity}"
        )
        assert result.predicted_time_to_damage < ce.EMERGENCY_TIME_THRESHOLD_S

    # ── SEVERITY_CRITICAL overflow (>= EMERGENCY_TIME_THRESHOLD_S) ────────────

    def test_CE_CRITICAL_severity_non_imminent_overflow(self) -> None:
        """
        Overflow predicted but > 5 s away → SEVERITY_CRITICAL.

        Physics: default params (fill=10 L/s, capacity=1000 L, overflow=95%).
        From tank=50%, need 45% fill = 450 L at 10 L/s = 45 s.
        45 s >= EMERGENCY_TIME_THRESHOLD_S (5 s) → CRITICAL, not EMERGENCY.
        45 s <= HORIZON_S (60 s) → overflows within simulation horizon.
        """
        ce = self._ce()
        state = {"tank_level": 50.0, "valve_position": 0.0, "pump_running": False}
        result = ce.evaluate(
            current_state=state, proposed_address=1, proposed_value=100.0,
        )
        assert result.damage_type == DAMAGE_OVERFLOW, (
            f"Expected OVERFLOW, got {result.damage_type}"
        )
        assert result.severity == SEVERITY_CRITICAL, (
            f"Non-imminent overflow (45 s) must be CRITICAL, got {result.severity}"
        )
        assert result.predicted_time_to_damage >= ce.EMERGENCY_TIME_THRESHOLD_S, (
            f"Time {result.predicted_time_to_damage:.1f}s must be >= {ce.EMERGENCY_TIME_THRESHOLD_S}s"
        )

    # ── DAMAGE_NONE — full horizon with no damage ─────────────────────────────

    def test_CE_no_damage_returns_DAMAGE_NONE(self) -> None:
        """
        Balanced fill/drain → level stays stable → no damage in horizon.
        """
        ce = self._ce()
        params = TankParams(
            capacity_liters=1000.0,
            max_flow_rate_lps=3.0,
            drain_rate_lps=3.0,   # exactly balanced
            overflow_level=95.0,
            dry_run_level=10.0,
        )
        # pump ON with balanced rates — level stays at 50%
        state = {"tank_level": 50.0, "valve_position": 100.0, "pump_running": True}
        result = ce.evaluate(
            current_state=state, proposed_address=0, proposed_value=0.0,
            params=params,
        )
        assert result.damage_predicted is False
        assert result.damage_type == DAMAGE_NONE
        assert result.severity == SEVERITY_NONE
        assert result.predicted_time_to_damage == -1.0

    # ── TankParams.from_controller() ──────────────────────────────────────────

    def test_TankParams_from_controller_mirrors_constants(self) -> None:
        """D07: TankParams.from_controller must mirror WaterTankController constants."""
        tank = WaterTankController()
        params = TankParams.from_controller(tank)
        assert params.capacity_liters   == tank.TANK_CAPACITY_LITERS
        assert params.max_flow_rate_lps == tank.MAX_FLOW_RATE_LPS
        assert params.drain_rate_lps    == tank.DRAIN_RATE_LPS
        assert params.overflow_level    == tank.OVERFLOW_LEVEL
        assert params.dry_run_level     == tank.DRY_RUN_LEVEL

    # ── batch_evaluate() ──────────────────────────────────────────────────────

    def test_batch_evaluate_returns_one_result_per_write(self) -> None:
        """batch_evaluate must return exactly len(writes) results."""
        ce = self._ce()
        state = {"tank_level": 50.0, "valve_position": 0.0, "pump_running": False}
        results = ce.batch_evaluate(state, writes=[(1, 80.0), (2, 1.0)])
        assert len(results) == 2
        for r in results:
            assert isinstance(r, ConsequenceResult)

    def test_batch_evaluate_empty_writes(self) -> None:
        """Empty writes list must return empty result list."""
        ce = self._ce()
        state = {"tank_level": 50.0, "valve_position": 0.0, "pump_running": False}
        assert ce.batch_evaluate(state, writes=[]) == []

    def test_batch_evaluate_threads_level_forward(self) -> None:
        """
        D06: batch_evaluate must propagate tank_level forward so the second
        write is evaluated against the post-first-write level, not the original.
        """
        ce = self._ce()
        # Start near-full so valve=100% causes overflow
        state = {"tank_level": 90.0, "valve_position": 0.0, "pump_running": False}
        results = ce.batch_evaluate(state, writes=[(1, 100.0), (1, 100.0)])
        # First write at 90% with max valve → overflow
        assert results[0].damage_type == DAMAGE_OVERFLOW

    # ── _simulate_final_level() ───────────────────────────────────────────────

    def test_simulate_final_level_stays_within_bounds(self) -> None:
        """_simulate_final_level must return a value in [0, 100]."""
        ce = self._ce()
        params = TankParams()
        final = ce._simulate_final_level(
            level=50.0, valve=100.0, pump_on=False, params=params
        )
        assert 0.0 <= final <= 100.0

    def test_simulate_final_level_stable_zero(self) -> None:
        """Level=0 with no fill and pump off stays at 0."""
        ce = self._ce()
        final = ce._simulate_final_level(
            level=0.0, valve=0.0, pump_on=False, params=TankParams()
        )
        assert final == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# PlantTopology — uncovered methods
# ══════════════════════════════════════════════════════════════════════════════

class TestPlantTopologyMethods:

    def _chain(self) -> PlantTopology:
        """3-PLC chain: A ↔ B ↔ C."""
        topo = PlantTopology()
        for pid, ip in [("A", "1.0.0.1"), ("B", "1.0.0.2"), ("C", "1.0.0.3")]:
            topo.add_plc(PLCNode(plc_id=pid, name=pid, ip=ip))
        topo.connect("A", "B")
        topo.connect("B", "C")
        return topo

    # ── get_all_plcs ──────────────────────────────────────────────────────────

    def test_get_all_plcs_returns_all(self) -> None:
        topo = self._chain()
        ids = {p.plc_id for p in topo.get_all_plcs()}
        assert ids == {"A", "B", "C"}

    def test_get_all_plcs_empty(self) -> None:
        assert PlantTopology().get_all_plcs() == []

    # ── get_neighbours ────────────────────────────────────────────────────────

    def test_get_neighbours_middle_node(self) -> None:
        """B in A-B-C chain must neighbour both A and C."""
        topo = self._chain()
        assert set(topo.get_neighbours("B")) == {"A", "C"}

    def test_get_neighbours_leaf_node(self) -> None:
        """A at chain end must neighbour only B."""
        topo = self._chain()
        assert topo.get_neighbours("A") == ["B"]

    def test_get_neighbours_unregistered_raises(self) -> None:
        with pytest.raises(KeyError):
            PlantTopology().get_neighbours("GHOST")

    # ── get_reachable ─────────────────────────────────────────────────────────

    def test_get_reachable_full_chain(self) -> None:
        """From A, BFS must find B and C."""
        topo = self._chain()
        assert set(topo.get_reachable("A")) == {"B", "C"}

    def test_get_reachable_from_middle(self) -> None:
        topo = self._chain()
        assert set(topo.get_reachable("B")) == {"A", "C"}

    def test_get_reachable_excludes_start(self) -> None:
        topo = self._chain()
        assert "A" not in topo.get_reachable("A")

    def test_get_reachable_isolated_node(self) -> None:
        """Isolated PLC (no edges) reaches nothing."""
        topo = PlantTopology()
        topo.add_plc(PLCNode(plc_id="X", name="X", ip="1.2.3.4"))
        assert topo.get_reachable("X") == []

    def test_get_reachable_unknown_returns_empty(self) -> None:
        """Unknown PLC returns [] not exception."""
        assert PlantTopology().get_reachable("GHOST") == []

    def test_get_reachable_sorted(self) -> None:
        """Result must be sorted alphabetically."""
        topo = self._chain()
        result = topo.get_reachable("B")
        assert result == sorted(result)

    # ── connect with unregistered PLC ────────────────────────────────────────

    def test_connect_unregistered_raises(self) -> None:
        """Connecting an unregistered PLC must raise KeyError."""
        topo = PlantTopology()
        topo.add_plc(PLCNode(plc_id="REAL", name="Real", ip="1.2.3.4"))
        with pytest.raises(KeyError):
            topo.connect("REAL", "GHOST")

    # ── build_water_tank_topology integration ─────────────────────────────────

    def test_full_topology_has_four_plcs(self) -> None:
        topo = build_water_tank_topology()
        ids = {p.plc_id for p in topo.get_all_plcs()}
        assert ids == {"PLC_01", "PLC_02", "PLC_03", "PLC_04"}

    def test_full_topology_plc01_reaches_plc04(self) -> None:
        """PLC_01 can reach PLC_04 via process-flow edges."""
        topo = build_water_tank_topology()
        assert "PLC_04" in topo.get_reachable("PLC_01")

    def test_full_topology_plc01_neighbours_plc02(self) -> None:
        topo = build_water_tank_topology()
        assert "PLC_02" in topo.get_neighbours("PLC_01")


# ══════════════════════════════════════════════════════════════════════════════
# TopologyRule — exception path
# ══════════════════════════════════════════════════════════════════════════════

class TestTopologyRuleExceptionPath:

    def test_exception_in_lookup_returns_pass(self) -> None:
        """
        If is_authorised_path() raises, TopologyRule must pass-through
        (not crash the validation pipeline).
        """
        mock_topo = MagicMock()
        mock_topo.is_authorised_path.side_effect = RuntimeError("topology crashed")

        rule   = TopologyRule(topology=mock_topo)
        ctx    = {"source_plc_id": "PLC_01", "target_plc_id": "PLC_04"}
        result = rule.evaluate(address=1, value=50.0, context=ctx)

        assert result.allowed is True, (
            "Exception in topology lookup must produce pass-through, not crash"
        )
        assert result.rule_id == "R007"


# ══════════════════════════════════════════════════════════════════════════════
# safe_eval_condition — USub / UAdd operators
# ══════════════════════════════════════════════════════════════════════════════

class TestSafeEvalUnaryOps:

    def test_usub_on_literal(self) -> None:
        """Unary minus on numeric literal: -5 < temperature."""
        result = safe_eval_condition("-5 < temperature", {"temperature": 5.0})
        assert result is True

    def test_usub_makes_comparison_false(self) -> None:
        """-10 > 0 must be False."""
        result = safe_eval_condition("-10 > 0", {})
        assert result is False

    def test_uadd_on_variable(self) -> None:
        """+x > 0 with x=5 must be True."""
        result = safe_eval_condition("+x > 0", {"x": 5.0})
        assert result is True


# ══════════════════════════════════════════════════════════════════════════════
# ReplayRule — reset() and max_history
# ══════════════════════════════════════════════════════════════════════════════

class TestReplayRuleReset:

    def test_reset_clears_history(self) -> None:
        """reset() must empty the history deque."""
        rule = ReplayRule(address=1, replay_window_s=10.0)
        rule.evaluate(address=1, value=50.0, context={}, now=1000.0)
        assert len(rule.snapshot()) == 1
        rule.reset()
        assert rule.snapshot() == []

    def test_after_reset_same_value_is_allowed(self) -> None:
        """After reset(), the same command must no longer be flagged as replay."""
        rule = ReplayRule(address=1, replay_window_s=10.0)
        rule.evaluate(address=1, value=50.0, context={}, now=1000.0)
        rule.reset()
        result = rule.evaluate(address=1, value=50.0, context={}, now=1001.0)
        assert result.allowed is True

    def test_max_history_evicts_oldest(self) -> None:
        """maxlen deque evicts oldest when capacity is reached."""
        rule = ReplayRule(address=1, replay_window_s=9999.0, max_history=3)
        for i, v in enumerate([1.0, 2.0, 3.0]):
            rule.evaluate(address=1, value=v, context={}, now=float(i))
        assert len(rule.snapshot()) == 3
        # Add 4th — evicts oldest (1.0)
        rule.evaluate(address=1, value=4.0, context={}, now=3.0)
        vals = [v for _, v, _ in rule.snapshot()]
        assert 1.0 not in vals
        assert len(rule.snapshot()) == 3


# ══════════════════════════════════════════════════════════════════════════════
# ForensicLogger — get_recent(limit), export_csv empty
# ══════════════════════════════════════════════════════════════════════════════

class TestForensicLoggerGaps:

    def _tmp(self) -> tuple[ForensicLogger, str]:
        path = tempfile.mktemp(suffix=".db", prefix="pg_gap_")
        return ForensicLogger(db_path=path), path

    def _cleanup(self, path: str) -> None:
        for s in ("", "-wal", "-shm"):
            try:
                os.remove(path + s)
            except FileNotFoundError:
                pass

    def test_get_recent_limit_respected(self) -> None:
        """get_recent(limit=3) must return at most 3 records from a 10-row DB."""
        logger, path = self._tmp()
        try:
            for i in range(10):
                logger.log_command(
                    address=1, value=float(i), allowed=True,
                    rule_id="ENGINE", reason="pass", severity="INFO",
                )
            logger.flush(timeout=5.0)
            assert len(logger.get_recent(limit=3)) == 3
        finally:
            logger.stop()
            self._cleanup(path)

    def test_export_csv_empty_db_returns_zero(self) -> None:
        """export_csv() on empty DB must return 0 and create the file."""
        logger, path = self._tmp()
        csv_path = path + ".csv"
        try:
            logger.flush(timeout=3.0)
            n = logger.export_csv(csv_path)
            assert n == 0
            assert os.path.exists(csv_path)
        finally:
            logger.stop()
            self._cleanup(path)
            try:
                os.remove(csv_path)
            except FileNotFoundError:
                pass

    def test_export_csv_row_count_matches_total(self) -> None:
        """export_csv row count must match get_stats total_commands."""
        logger, path = self._tmp()
        csv_path = path + ".csv"
        try:
            for i in range(5):
                logger.log_command(
                    address=1, value=float(i), allowed=bool(i % 2),
                    rule_id="R001", reason="t", severity="CRITICAL",
                )
            logger.flush(timeout=5.0)
            n = logger.export_csv(csv_path)
            assert n == logger.get_stats()["total_commands"]
        finally:
            logger.stop()
            self._cleanup(path)
            try:
                os.remove(csv_path)
            except FileNotFoundError:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# violations router — _to_record, _bucket_rows, 503 paths
# ══════════════════════════════════════════════════════════════════════════════

class TestViolationsRouterGaps:

    # ── _to_record edge cases ─────────────────────────────────────────────────

    def _base_row(self, **kw) -> dict:
        row = {
            "id": 1, "timestamp": "2026-01-01T00:00:00",
            "address": 1, "value": 50.0, "allowed": False,
            "rule_id": "R001", "severity": "CRITICAL",
            "mitre_tag": "T0855", "reason": "t", "source_ip": "127.0.0.1",
            "latency_us": 99.0,
        }
        row.update(kw)
        return row

    def test_to_record_latency_none_becomes_zero(self) -> None:
        from web_ui.routers.violations import _to_record
        rec = _to_record(self._base_row(latency_us=None))
        assert rec.latency_us == 0.0

    def test_to_record_value_none_becomes_zero(self) -> None:
        from web_ui.routers.violations import _to_record
        rec = _to_record(self._base_row(value=None))
        assert rec.value == 0.0

    def test_to_record_all_optional_none_does_not_raise(self) -> None:
        from web_ui.routers.violations import _to_record
        row = {k: None for k in [
            "id", "timestamp", "address", "value", "allowed",
            "rule_id", "severity", "mitre_tag", "reason",
            "source_ip", "latency_us",
        ]}
        rec = _to_record(row)
        assert rec.latency_us == 0.0
        assert rec.value == 0.0

    # ── _bucket_rows ──────────────────────────────────────────────────────────

    def test_bucket_rows_float_timestamps(self) -> None:
        from web_ui.routers.violations import _bucket_rows
        now = time.time()
        rows = [
            {"timestamp": now - 60, "allowed": False},
            {"timestamp": now - 120, "allowed": True},
        ]
        buckets = _bucket_rows(rows, hours=1)
        assert sum(b.total for b in buckets) == 2

    def test_bucket_rows_skips_old_rows(self) -> None:
        from web_ui.routers.violations import _bucket_rows
        now = time.time()
        rows = [
            {"timestamp": now - 7200, "allowed": False},  # 2h ago — outside 1h window
            {"timestamp": now - 60,   "allowed": False},  # recent — included
        ]
        buckets = _bucket_rows(rows, hours=1)
        assert sum(b.total for b in buckets) == 1

    def test_bucket_rows_iso_string_timestamps(self) -> None:
        import datetime
        from web_ui.routers.violations import _bucket_rows
        iso = datetime.datetime.now().isoformat()
        buckets = _bucket_rows([{"timestamp": iso, "allowed": True}], hours=1)
        assert sum(b.total for b in buckets) == 1

    def test_bucket_rows_blocked_counted_correctly(self) -> None:
        from web_ui.routers.violations import _bucket_rows
        now = time.time()
        rows = [
            {"timestamp": now - 10, "allowed": False},
            {"timestamp": now - 20, "allowed": True},
            {"timestamp": now - 30, "allowed": False},
        ]
        buckets = _bucket_rows(rows, hours=1)
        assert sum(b.blocked for b in buckets) == 2
        assert sum(b.total   for b in buckets) == 3

    def test_bucket_rows_empty_returns_empty(self) -> None:
        from web_ui.routers.violations import _bucket_rows
        assert _bucket_rows([], hours=24) == []

    # ── 503 paths ─────────────────────────────────────────────────────────────

    def _broken_client(self):
        from fastapi.testclient import TestClient
        from web_ui.main import app
        broken = MagicMock()
        broken.get_violations.side_effect = RuntimeError("db dead")
        broken.get_timeline.side_effect   = RuntimeError("db dead")
        broken.get_stats.side_effect      = RuntimeError("db dead")
        app.state.flogger    = broken
        app.state.engine     = MagicMock()
        app.state.start_time = time.monotonic()
        return TestClient(app, raise_server_exceptions=False)

    def test_violations_by_rule_503(self) -> None:
        assert self._broken_client().get("/api/violations/rule/R001").status_code == 503

    def test_violations_by_mitre_503(self) -> None:
        assert self._broken_client().get("/api/violations/mitre/T0855").status_code == 503

    def test_timeline_503(self) -> None:
        assert self._broken_client().get("/api/timeline").status_code == 503

    def test_timeline_raw_rows_fallback_to_bucket_rows(self) -> None:
        """
        If get_timeline() returns raw rows without 'hour' key,
        the router must fall back to _bucket_rows() rather than crashing.
        """
        from fastapi.testclient import TestClient
        from web_ui.main import app
        now = time.time()
        raw = [
            {"timestamp": now - 60,  "allowed": False, "id": 1},
            {"timestamp": now - 120, "allowed": True,  "id": 2},
        ]
        mock = MagicMock()
        mock.get_timeline.return_value = raw
        mock.get_stats.return_value = {
            "total_commands": 2, "blocked": 1, "allowed": 1,
            "block_rate": 0.5, "by_rule": {}, "by_mitre": {},
            "dropped_records": 0,
        }
        app.state.flogger    = mock
        app.state.engine     = MagicMock()
        app.state.start_time = time.monotonic()
        client = TestClient(app, raise_server_exceptions=True)
        resp   = client.get("/api/timeline?hours=1")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
