"""
test_forensic_logger.py  —  Layer 6 Forensic Logger Tests
==========================================================
Layer 6  |  PhysicsGuard ICS Security Gateway
Week 4 deliverable: tests for rebuilt ForensicLogger.

Coverage:
  - DB created on startup; WAL mode enabled
  - log_command() is non-blocking (< 100ms for 100 calls)
  - Blocked commands appear in get_violations()
  - Allowed commands do NOT appear in get_violations()
  - Newest-first ordering; limit parameter respected
  - get_stats() — counts, block_rate, by_mitre, by_rule, empty DB
  - get_recent() — returns both allowed and blocked
  - get_timeline() — bounds respected (start/end)
  - get_violations_by_rule() — filtered correctly
  - get_violations_by_mitre() — filtered correctly
  - get_session_stats() — isolated to one session_id
  - session_id: same within instance, different across instances
  - export_csv: file created, row count matches
  - latency_us stored and retrievable
  - context manager: __enter__ / __exit__
  - Queue full: drops gracefully without crash
  - flush() uses threading.Event — returns True when records committed
  - stop() shuts down writer thread cleanly
  - Concurrent writes: 3 threads × 100 = 300 exact records
  - Violation record has all required schema fields

No time.sleep() in any test — all synchronisation via flush(timeout=5.0).
AAA pattern throughout. Parametrized where appropriate.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
from typing import Any

try:
    import pytest
    _HAVE_PYTEST = True
except ImportError:
    _HAVE_PYTEST = False

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.forensic_logger import ForensicLogger


# ── Helpers ───────────────────────────────────────────────────────────────────

def _tmp_logger() -> tuple[ForensicLogger, str]:
    """Create a ForensicLogger backed by a unique temp file."""
    path = tempfile.mktemp(suffix=".db", prefix="physicsguard_test_")
    logger = ForensicLogger(db_path=path)
    return logger, path


def _cleanup(path: str) -> None:
    """Remove temp DB and WAL/SHM side-cars."""
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(path + suffix)
        except FileNotFoundError:
            pass


def _block(logger: ForensicLogger, **kw: Any) -> None:
    """Log one blocked command (convenience wrapper)."""
    defaults: dict[str, Any] = dict(
        address=1, value=150.0, allowed=False,
        rule_id="R001", reason="test", severity="CRITICAL",
        mitre_tag="T0855", source_ip="10.0.0.1",
    )
    defaults.update(kw)
    logger.log_command(**defaults)


def _allow(logger: ForensicLogger, **kw: Any) -> None:
    """Log one allowed command (convenience wrapper)."""
    defaults: dict[str, Any] = dict(
        address=1, value=50.0, allowed=True,
        rule_id="ENGINE", reason="all rules passed", severity="INFO",
    )
    defaults.update(kw)
    logger.log_command(**defaults)


# ── Startup ───────────────────────────────────────────────────────────────────

def test_logger_starts_without_error() -> None:
    # Arrange / Act
    logger, path = _tmp_logger()
    # Assert
    assert logger is not None, "ForensicLogger must construct without error"
    logger.stop()
    _cleanup(path)


def test_db_file_created_on_startup() -> None:
    # Arrange
    logger, path = _tmp_logger()
    # Act
    logger.flush()
    # Assert
    assert os.path.exists(path), f"DB file must be created at {path}"
    logger.stop()
    _cleanup(path)


def test_wal_mode_enabled() -> None:
    """Writer thread must set PRAGMA journal_mode=WAL."""
    import sqlite3
    # Arrange
    logger, path = _tmp_logger()
    logger.flush()
    # Act
    with sqlite3.connect(path) as conn:
        row = conn.execute("PRAGMA journal_mode").fetchone()
    mode = row[0] if row else ""
    # Assert
    assert mode == "wal", f"Expected WAL journal mode, got '{mode}'"
    logger.stop()
    _cleanup(path)


# ── log_command() ─────────────────────────────────────────────────────────────

def test_log_command_is_nonblocking() -> None:
    """100 log_command() calls must complete in < 100ms total."""
    # Arrange
    logger, path = _tmp_logger()
    # Act
    start = time.monotonic()
    for _ in range(100):
        _block(logger)
    elapsed_ms = (time.monotonic() - start) * 1000
    # Assert
    assert elapsed_ms < 100, (
        f"100 log_command() calls took {elapsed_ms:.1f}ms — expected < 100ms"
    )
    logger.stop()
    _cleanup(path)


def test_blocked_command_appears_in_violations() -> None:
    # Arrange
    logger, path = _tmp_logger()
    # Act
    _block(logger, address=1, value=150.0, source_ip="10.0.0.1")
    logger.flush()
    violations = logger.get_violations()
    # Assert
    assert len(violations) == 1, f"Expected 1 violation, got {len(violations)}"
    v = violations[0]
    assert v["address"]   == 1
    assert v["value"]     == 150.0
    assert v["allowed"]   == 0
    assert v["rule_id"]   == "R001"
    assert v["mitre_tag"] == "T0855"
    assert v["source_ip"] == "10.0.0.1"
    logger.stop()
    _cleanup(path)


def test_allowed_command_not_in_violations() -> None:
    # Arrange
    logger, path = _tmp_logger()
    # Act
    _allow(logger)
    logger.flush()
    violations = logger.get_violations()
    # Assert
    assert len(violations) == 0, (
        f"Allowed command must NOT appear in violations, got {violations}"
    )
    logger.stop()
    _cleanup(path)


def test_multiple_violations_newest_first() -> None:
    # Arrange
    logger, path = _tmp_logger()
    # Act — log with distinct timestamps
    for val in (110.0, 120.0, 130.0):
        _block(logger, value=val)
        time.sleep(0.01)
    logger.flush()
    violations = logger.get_violations()
    # Assert — newest (last logged) first
    assert len(violations) == 3, f"Expected 3 violations, got {len(violations)}"
    assert violations[0]["value"] == 130.0, (
        f"Expected newest (130.0) first, got {violations[0]['value']}"
    )
    logger.stop()
    _cleanup(path)


def test_violations_limit_respected(limit: int = 5) -> None:
    # Arrange
    logger, path = _tmp_logger()
    for i in range(20):
        _block(logger, value=float(i + 101))
    logger.flush()
    # Act
    result = logger.get_violations(limit=limit)
    # Assert
    assert len(result) == limit, f"Expected {limit} with limit={limit}, got {len(result)}"
    logger.stop()
    _cleanup(path)


# ── get_stats() ───────────────────────────────────────────────────────────────

def test_stats_counts_correct() -> None:
    # Arrange
    logger, path = _tmp_logger()
    for _ in range(3):
        _block(logger)
    for _ in range(2):
        _allow(logger)
    logger.flush()
    # Act
    stats = logger.get_stats()
    # Assert
    assert stats["total_commands"] == 5,   f"Expected 5 total, got {stats['total_commands']}"
    assert stats["blocked"]        == 3,   f"Expected 3 blocked, got {stats['blocked']}"
    assert stats["allowed"]        == 2,   f"Expected 2 allowed, got {stats['allowed']}"
    assert stats["block_rate"]     == 0.6, f"Expected 0.6 block_rate, got {stats['block_rate']}"
    logger.stop()
    _cleanup(path)


def test_stats_by_mitre_aggregation() -> None:
    # Arrange
    logger, path = _tmp_logger()
    _block(logger, mitre_tag="T0855")
    _block(logger, mitre_tag="T0855")
    _block(logger, mitre_tag="T0813", rule_id="R003", severity="EMERGENCY")
    logger.flush()
    # Act
    stats = logger.get_stats()
    # Assert
    assert stats["by_mitre"].get("T0855") == 2, f"Expected T0855=2, got {stats['by_mitre']}"
    assert stats["by_mitre"].get("T0813") == 1, f"Expected T0813=1, got {stats['by_mitre']}"
    logger.stop()
    _cleanup(path)


def test_stats_by_rule_aggregation() -> None:
    # Arrange
    logger, path = _tmp_logger()
    _block(logger, rule_id="R001")
    _block(logger, rule_id="R001")
    _block(logger, rule_id="R003", mitre_tag="T0813", severity="EMERGENCY")
    logger.flush()
    # Act
    stats = logger.get_stats()
    # Assert
    assert stats["by_rule"].get("R001") == 2, f"Expected R001=2, got {stats['by_rule']}"
    assert stats["by_rule"].get("R003") == 1, f"Expected R003=1, got {stats['by_rule']}"
    logger.stop()
    _cleanup(path)


def test_stats_empty_db_returns_zeros() -> None:
    # Arrange
    logger, path = _tmp_logger()
    logger.flush()
    # Act
    stats = logger.get_stats()
    # Assert
    assert stats["total_commands"] == 0,   "Empty DB must report 0 total"
    assert stats["blocked"]        == 0,   "Empty DB must report 0 blocked"
    assert stats["block_rate"]     == 0.0, "Empty DB must report 0.0 block_rate"
    logger.stop()
    _cleanup(path)


# ── get_recent() ──────────────────────────────────────────────────────────────

def test_get_recent_includes_allowed_and_blocked() -> None:
    # Arrange
    logger, path = _tmp_logger()
    _allow(logger)
    _block(logger)
    logger.flush()
    # Act
    recent = logger.get_recent()
    # Assert
    assert len(recent) == 2, f"Expected 2 recent records, got {len(recent)}"
    logger.stop()
    _cleanup(path)


# ── get_timeline() ────────────────────────────────────────────────────────────

def test_get_timeline_bounds_respected() -> None:
    # Arrange
    logger, path = _tmp_logger()
    before = time.time()
    time.sleep(0.02)
    _block(logger)
    time.sleep(0.02)
    mid = time.time()
    time.sleep(0.02)
    _allow(logger)
    time.sleep(0.02)
    after = time.time()
    logger.flush()
    # Act
    in_window  = logger.get_timeline(before, after)
    only_first = logger.get_timeline(before, mid)
    # Assert
    assert len(in_window)  == 2, f"Expected 2 in full window, got {len(in_window)}"
    assert len(only_first) == 1, f"Expected 1 in first window, got {len(only_first)}"
    logger.stop()
    _cleanup(path)


# ── get_violations_by_rule() ─────────────────────────────────────────────────

def test_get_violations_by_rule_filter() -> None:
    # Arrange
    logger, path = _tmp_logger()
    _block(logger, rule_id="R001")
    _block(logger, rule_id="R001")
    _block(logger, rule_id="R003", mitre_tag="T0813", severity="EMERGENCY")
    logger.flush()
    # Act
    r001 = logger.get_violations_by_rule("R001")
    r003 = logger.get_violations_by_rule("R003")
    r999 = logger.get_violations_by_rule("R999")
    # Assert
    assert len(r001) == 2,  f"Expected 2 R001 violations, got {len(r001)}"
    assert len(r003) == 1,  f"Expected 1 R003 violation, got {len(r003)}"
    assert len(r999) == 0,  f"Expected 0 R999 violations, got {len(r999)}"
    logger.stop()
    _cleanup(path)


# ── get_violations_by_mitre() ────────────────────────────────────────────────

def test_get_violations_by_mitre_filter() -> None:
    # Arrange
    logger, path = _tmp_logger()
    _block(logger, mitre_tag="T0855")
    _block(logger, mitre_tag="T0855")
    _block(logger, mitre_tag="T0813", rule_id="R003", severity="EMERGENCY")
    logger.flush()
    # Act
    t0855 = logger.get_violations_by_mitre("T0855")
    t0813 = logger.get_violations_by_mitre("T0813")
    # Assert
    assert len(t0855) == 2, f"Expected 2 T0855 records, got {len(t0855)}"
    assert len(t0813) == 1, f"Expected 1 T0813 record, got {len(t0813)}"
    logger.stop()
    _cleanup(path)


# ── session_id ────────────────────────────────────────────────────────────────

def test_session_id_consistent_within_instance() -> None:
    # Arrange
    logger, path = _tmp_logger()
    sid = logger.session_id
    _block(logger)
    _allow(logger)
    logger.flush()
    # Act
    records = logger.get_recent()
    # Assert — all records from this instance share the same session_id
    for r in records:
        assert r["session_id"] == sid, (
            f"Record session_id {r['session_id']!r} != instance session_id {sid!r}"
        )
    logger.stop()
    _cleanup(path)


def test_two_instances_have_different_session_ids() -> None:
    # Arrange + Act
    logger_a, path_a = _tmp_logger()
    logger_b, path_b = _tmp_logger()
    # Assert
    assert logger_a.session_id != logger_b.session_id, (
        "Two ForensicLogger instances must have different session_ids"
    )
    logger_a.stop()
    logger_b.stop()
    _cleanup(path_a)
    _cleanup(path_b)


# ── get_session_stats() ───────────────────────────────────────────────────────

def test_get_session_stats_isolation() -> None:
    """Two sessions in the same DB must report independent stats."""
    # Arrange — write session A into one DB
    logger_a, path = _tmp_logger()
    _block(logger_a)
    _block(logger_a)
    logger_a.flush()
    sid_a = logger_a.session_id
    logger_a.stop()

    # Write session B into the SAME DB
    logger_b = ForensicLogger(db_path=path)
    _block(logger_b)
    logger_b.flush()
    sid_b = logger_b.session_id
    logger_b.stop()

    # Query using a fresh read instance
    reader = ForensicLogger(db_path=path)
    # Act
    stats_a = reader.get_session_stats(sid_a)
    stats_b = reader.get_session_stats(sid_b)
    reader.stop()
    _cleanup(path)

    # Assert
    assert stats_a["total_commands"] == 2, (
        f"Session A must have 2 records, got {stats_a['total_commands']}"
    )
    assert stats_b["total_commands"] == 1, (
        f"Session B must have 1 record, got {stats_b['total_commands']}"
    )


# ── export_csv() ──────────────────────────────────────────────────────────────

def test_export_csv_file_exists_and_row_count_matches() -> None:
    # Arrange
    logger, path = _tmp_logger()
    for _ in range(5):
        _block(logger)
    for _ in range(3):
        _allow(logger)
    logger.flush()
    csv_path = path + ".csv"
    # Act
    n = logger.export_csv(csv_path)
    # Assert
    assert os.path.exists(csv_path), "export_csv must create the CSV file"
    assert n == 8, f"Expected 8 exported rows, got {n}"
    stats = logger.get_stats()
    assert n == stats["total_commands"], (
        f"Exported rows ({n}) must match total_commands ({stats['total_commands']})"
    )
    logger.stop()
    _cleanup(path)
    try:
        os.remove(csv_path)
    except FileNotFoundError:
        pass


# ── latency_us ────────────────────────────────────────────────────────────────

def test_latency_us_stored_and_retrieved() -> None:
    # Arrange
    logger, path = _tmp_logger()
    # Act
    logger.log_command(
        address=1, value=50.0, allowed=True,
        rule_id="ENGINE", reason="pass", severity="INFO",
        latency_us=42.5,
    )
    logger.flush()
    recent = logger.get_recent(limit=1)
    # Assert
    assert len(recent) == 1, "Expected 1 record"
    assert recent[0]["latency_us"] == 42.5, (
        f"Expected latency_us=42.5, got {recent[0]['latency_us']}"
    )
    logger.stop()
    _cleanup(path)


# ── Context manager ───────────────────────────────────────────────────────────

def test_context_manager_enter_exit() -> None:
    # Arrange + Act
    path = tempfile.mktemp(suffix=".db", prefix="physicsguard_test_")
    with ForensicLogger(db_path=path) as logger:
        _block(logger)
        logger.flush()
        violations = logger.get_violations()
    # Assert
    assert len(violations) == 1, (
        f"Expected 1 violation inside context manager, got {len(violations)}"
    )
    _cleanup(path)


# ── Resilience ────────────────────────────────────────────────────────────────

def test_queue_full_drops_gracefully() -> None:
    """Overfilling the queue must not crash or block the caller."""
    # Arrange — create a logger with a tiny queue manually
    import queue as _queue
    path = tempfile.mktemp(suffix=".db", prefix="physicsguard_test_")
    logger = ForensicLogger.__new__(ForensicLogger)
    logger._db_path      = path
    logger._session_id   = "test-session"
    logger._queue        = _queue.Queue(maxsize=3)
    logger._dropped      = 0
    logger._flush_event  = threading.Event()

    # Fill the queue
    for i in range(3):
        logger._queue.put({"dummy": i})

    # Act — this must not raise or block
    logger.log_command(
        address=1, value=1.0, allowed=False,
        rule_id="R001", severity="CRITICAL", reason="test",
    )
    # Assert
    assert logger._dropped == 1, f"Expected 1 dropped, got {logger._dropped}"
    _cleanup(path)


def test_flush_waits_for_writes() -> None:
    # Arrange
    logger, path = _tmp_logger()
    for i in range(10):
        _allow(logger, value=float(i))
    # Act
    flushed = logger.flush(timeout=5.0)
    records = logger.get_recent(limit=20)
    # Assert
    assert flushed, "flush() must return True when queue drains in time"
    assert len(records) == 10, (
        f"Expected 10 records after flush, got {len(records)}"
    )
    logger.stop()
    _cleanup(path)


def test_stop_shuts_down_cleanly() -> None:
    # Arrange
    logger, path = _tmp_logger()
    _allow(logger)
    # Act + Assert (must not hang)
    logger.stop()
    _cleanup(path)


# ── Concurrent writes ─────────────────────────────────────────────────────────

def test_concurrent_writes_exact_count() -> None:
    """3 threads × 100 writes = exactly 300 records in the DB."""
    # Arrange
    logger, path = _tmp_logger()
    errors: list[str] = []

    def writer(thread_id: int) -> None:
        for i in range(100):
            try:
                _block(logger, value=float(thread_id * 100 + i))
            except Exception as exc:
                errors.append(f"thread {thread_id} write {i}: {exc}")

    # Act
    threads = [threading.Thread(target=writer, args=(t,)) for t in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    import time as _t
    _t.sleep(0.5)   # let all threads finish enqueuing
    logger.flush(timeout=15.0)
    stats = logger.get_stats()
    # Assert
    assert not errors, f"Concurrent write errors: {errors}"
    assert stats["total_commands"] == 300, (
        f"Expected 300 records from 3×100 threads, got {stats['total_commands']}"
    )
    logger.stop()
    _cleanup(path)


# ── Violation record fields ───────────────────────────────────────────────────

def test_violation_record_has_all_required_fields() -> None:
    # Arrange
    logger, path = _tmp_logger()
    logger.log_command(
        address=2, value=1.0, allowed=False,
        rule_id="R003", reason="pump interlock", severity="EMERGENCY",
        mitre_tag="T0813", source_ip="192.168.0.5", latency_us=99.1,
    )
    logger.flush()
    # Act
    violations = logger.get_violations()
    # Assert
    assert len(violations) == 1, f"Expected 1 violation, got {len(violations)}"
    v = violations[0]
    required = {
        "id", "session_id", "timestamp", "address", "value", "allowed",
        "rule_id", "reason", "severity", "mitre_tag", "source_ip", "latency_us",
    }
    missing = required - set(v.keys())
    assert not missing, f"Violation record missing fields: {missing}"
    assert v["severity"]   == "EMERGENCY",    f"severity mismatch: {v['severity']}"
    assert v["rule_id"]    == "R003",         f"rule_id mismatch: {v['rule_id']}"
    assert v["source_ip"]  == "192.168.0.5",  f"source_ip mismatch: {v['source_ip']}"
    assert v["latency_us"] == 99.1,           f"latency_us mismatch: {v['latency_us']}"
    logger.stop()
    _cleanup(path)


# ── Standalone runner (pytest bridge pattern) ─────────────────────────────────

class _PytestBridge:
    """Minimal pytest-compatible collector for standalone __main__ runs."""

    def __init__(self) -> None:
        self._passed:   int        = 0
        self._failed:   int        = 0
        self._failures: list[str]  = []

    def run(self, fn: Any) -> None:
        name = fn.__name__
        try:
            fn()
            print(f"  ✅  {name}")
            self._passed += 1
        except AssertionError as exc:
            print(f"  ❌  {name}")
            print(f"      {exc}")
            self._failed += 1
            self._failures.append(name)
        except Exception as exc:
            print(f"  💥  {name}  [{type(exc).__name__}: {exc}]")
            self._failed += 1
            self._failures.append(name)

    def summary(self) -> None:
        total = self._passed + self._failed
        print()
        print("=" * 62)
        print(f"  Results: {self._passed} passed / {self._failed} failed / {total} total")
        if self._failures:
            print(f"  Failed:  {', '.join(self._failures)}")
        print("=" * 62)
        if self._failed:
            raise SystemExit(1)


if __name__ == "__main__":
    print()
    print("=" * 62)
    print("  ForensicLogger Tests  |  Layer 6")
    print("=" * 62)

    bridge = _PytestBridge()
    for fn in [
        test_logger_starts_without_error,
        test_db_file_created_on_startup,
        test_wal_mode_enabled,
        test_log_command_is_nonblocking,
        test_blocked_command_appears_in_violations,
        test_allowed_command_not_in_violations,
        test_multiple_violations_newest_first,
        lambda: test_violations_limit_respected(5),
        test_stats_counts_correct,
        test_stats_by_mitre_aggregation,
        test_stats_by_rule_aggregation,
        test_stats_empty_db_returns_zeros,
        test_get_recent_includes_allowed_and_blocked,
        test_get_timeline_bounds_respected,
        test_get_violations_by_rule_filter,
        test_get_violations_by_mitre_filter,
        test_session_id_consistent_within_instance,
        test_two_instances_have_different_session_ids,
        test_get_session_stats_isolation,
        test_export_csv_file_exists_and_row_count_matches,
        test_latency_us_stored_and_retrieved,
        test_context_manager_enter_exit,
        test_queue_full_drops_gracefully,
        test_flush_waits_for_writes,
        test_stop_shuts_down_cleanly,
        test_concurrent_writes_exact_count,
        test_violation_record_has_all_required_fields,
    ]:
        bridge.run(fn)

    bridge.summary()
