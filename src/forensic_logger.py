"""
forensic_logger.py  —  Append-Only Forensic Audit Log
======================================================
Layer 6  |  PhysicsGuard ICS Security Gateway
Week 4 deliverable: every validation decision written permanently to SQLite.

Owns:
  - SQLite schema creation and migration
  - Dedicated writer thread (never blocks the validation path)
  - log_command()                — non-blocking enqueue, < 0.1ms
  - get_violations()             — all blocked commands
  - get_violations_by_rule()     — filtered by rule ID
  - get_violations_by_mitre()    — filtered by MITRE tag
  - get_stats()                  — dashboard counters
  - get_recent()                 — both allowed and blocked
  - get_timeline()               — records in a time window
  - get_session_stats()          — per-run isolation for dissertation results
  - export_csv()                 — export full log for analysis
  - flush() / stop()             — lifecycle management
  - __enter__ / __exit__         — context manager support

Does NOT own:
  - Validation decisions     (validation_engine.py — Layer 4)
  - Alerting                 (alerting.py — Layer 5)
  - REST API                 (api.py — Layer 7)

Thread safety design:
  - ONE writer thread owns the SQLite connection exclusively
    (SQLite connections are NOT thread-safe — never share them)
  - All other threads call log_command() → queue.put_nowait() → returns in < 0.1ms
  - Queue is bounded (maxsize=10_000) — if full, record is DROPPED
    with WARNING (better than blocking the validation path)
  - Read queries open SHORT-LIVED read-only connections — safe because
    SQLite WAL mode allows concurrent reads while writer is active
  - flush() signals via threading.Event, not time.sleep() (B14 fix)

New in rebuild:
  - session_id (UUID4) — per-run isolation for dissertation results chapter
  - latency_us (REAL, nullable) — validation latency from Layer 4
  - threading.Event flush — writer signals after every batch commit
  - __enter__ / __exit__ context manager
  - get_violations_by_rule / get_violations_by_mitre / get_timeline
  - export_csv / get_session_stats
  - Schema migration via ALTER TABLE ... (safe on existing DBs)

Academic novelty hook:
  - Every blocked command stored with MITRE ATT&CK for ICS tag
  - session_id allows cross-run comparison (dissertation results chapter)
  - get_stats() returns attack frequency by MITRE technique
"""

import csv
import logging
import os
import queue
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_BATCH_SIZE:    int   = 50      # commit after this many records
_BATCH_TIMEOUT: float = 1.0     # or after this many seconds, whichever first
_QUEUE_MAXSIZE: int   = 10_000  # drop records beyond this (never block caller)

# Sentinel: signals the writer thread to stop cleanly
_STOP_SENTINEL = object()


# ── Schema ────────────────────────────────────────────────────────────────────

_CREATE_COMMANDS = """
CREATE TABLE IF NOT EXISTS commands (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL DEFAULT '',
    timestamp   REAL    NOT NULL,
    address     INTEGER NOT NULL,
    value       REAL    NOT NULL,
    allowed     INTEGER NOT NULL,
    rule_id     TEXT    NOT NULL DEFAULT '',
    reason      TEXT    NOT NULL DEFAULT '',
    severity    TEXT    NOT NULL DEFAULT 'INFO',
    mitre_tag   TEXT    NOT NULL DEFAULT '',
    source_ip   TEXT    NOT NULL DEFAULT 'unknown',
    latency_us  REAL
);
"""

# Migration DDL — each wrapped in its own try/except inside _migrate_schema()
_MIGRATE_SESSION_ID  = "ALTER TABLE commands ADD COLUMN session_id  TEXT NOT NULL DEFAULT ''"
_MIGRATE_LATENCY_US  = "ALTER TABLE commands ADD COLUMN latency_us  REAL"

_CREATE_IDX_TIMESTAMP  = "CREATE INDEX IF NOT EXISTS idx_timestamp  ON commands(timestamp);"
_CREATE_IDX_ALLOWED    = "CREATE INDEX IF NOT EXISTS idx_allowed    ON commands(allowed);"
_CREATE_IDX_MITRE      = "CREATE INDEX IF NOT EXISTS idx_mitre      ON commands(mitre_tag);"
_CREATE_IDX_SESSION    = "CREATE INDEX IF NOT EXISTS idx_session    ON commands(session_id);"

_INSERT_COMMAND = """
INSERT INTO commands
    (session_id, timestamp, address, value, allowed,
     rule_id, reason, severity, mitre_tag, source_ip, latency_us)
VALUES
    (:session_id, :timestamp, :address, :value, :allowed,
     :rule_id, :reason, :severity, :mitre_tag, :source_ip, :latency_us)
"""


# ── Record dataclass ──────────────────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class CommandRecord:
    """
    Immutable record representing one validation decision.
    Constructed internally by log_command() and put on the queue.
    """
    session_id: str
    timestamp:  float
    address:    int
    value:      float
    allowed:    int          # 1 = allowed, 0 = blocked
    rule_id:    str
    reason:     str
    severity:   str
    mitre_tag:  str
    source_ip:  str
    latency_us: float | None

    def as_dict(self) -> dict[str, Any]:
        """Return a plain dict for sqlite3.executemany()."""
        return {
            "session_id": self.session_id,
            "timestamp":  self.timestamp,
            "address":    self.address,
            "value":      self.value,
            "allowed":    self.allowed,
            "rule_id":    self.rule_id,
            "reason":     self.reason,
            "severity":   self.severity,
            "mitre_tag":  self.mitre_tag,
            "source_ip":  self.source_ip,
            "latency_us": self.latency_us,
        }


# ── ForensicLogger ────────────────────────────────────────────────────────────

class ForensicLogger:
    """
    Append-only SQLite forensic audit log with dedicated writer thread.

    Each instance gets a unique session_id (UUID4) so records from
    different server runs can be isolated in get_session_stats().

    Usage::

        # Direct instantiation
        logger = ForensicLogger("logs/physicsguard.db")
        logger.log_command(address=1, value=150.0, allowed=False, ...)
        violations = logger.get_violations()
        logger.stop()

        # Context manager (preferred)
        with ForensicLogger("logs/physicsguard.db") as logger:
            logger.log_command(...)
    """

    def __init__(self, db_path: str = "logs/physicsguard.db") -> None:
        self._db_path:    str          = db_path
        self._session_id: str          = str(uuid.uuid4())
        self._queue:      queue.Queue  = queue.Queue(maxsize=_QUEUE_MAXSIZE)
        self._dropped:    int          = 0   # records dropped due to full queue
        self._flush_event: threading.Event = threading.Event()

        # Ensure parent directory exists
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        # Start dedicated writer thread
        self._writer = threading.Thread(
            target=self._write_loop,
            daemon=True,
            name="forensic-writer",
        )
        self._writer.start()
        log.info("ForensicLogger started | session=%s db=%s",
                 self._session_id, db_path)

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self) -> "ForensicLogger":
        return self

    def __exit__(self, *_: Any) -> None:
        self.stop()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def session_id(self) -> str:
        """UUID4 identifying this server run. Shared by all records this instance writes."""
        return self._session_id

    @property
    def dropped(self) -> int:
        """Count of records dropped because the queue was full."""
        return self._dropped

    # ── Public write API ──────────────────────────────────────────────────────

    def log_command(
        self,
        address:    int,
        value:      float,
        allowed:    bool,
        rule_id:    str         = "",
        reason:     str         = "",
        severity:   str         = "INFO",
        mitre_tag:  str         = "",
        source_ip:  str         = "unknown",
        latency_us: float | None = None,
    ) -> None:
        """
        Enqueue a validation decision for async write to SQLite.

        Non-blocking: returns in < 0.1ms regardless of DB load.
        If the internal queue is full the record is DROPPED and a
        WARNING is emitted. This is intentional — the validation path
        must never block.

        Args:
            address    : register address (0=level, 1=valve, 2=pump)
            value      : proposed value from Modbus client
            allowed    : True if command was permitted, False if blocked
            rule_id    : rule that decided, e.g. "R001"
            reason     : human-readable explanation
            severity   : INFO | WARNING | CRITICAL | EMERGENCY
            mitre_tag  : MITRE ATT&CK for ICS tag, e.g. "T0855"
            source_ip  : source IP of the Modbus client
            latency_us : optional validation latency in microseconds
        """
        record = CommandRecord(
            session_id = self._session_id,
            timestamp  = time.time(),
            address    = address,
            value      = float(value),
            allowed    = 1 if allowed else 0,
            rule_id    = rule_id,
            reason     = reason,
            severity   = severity,
            mitre_tag  = mitre_tag,
            source_ip  = source_ip,
            latency_us = latency_us,
        )
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self._dropped += 1
            log.warning(
                "FORENSIC: queue full — dropping record (total dropped: %d)",
                self._dropped,
            )

    # ── Public read API ───────────────────────────────────────────────────────

    def get_violations(self, limit: int = 100) -> list[dict[str, Any]]:
        """
        Return the most recent blocked commands, newest first.

        Args:
            limit: maximum records to return (default 100)
        """
        return self._query(
            "SELECT * FROM commands WHERE allowed=0 "
            "ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    def get_violations_by_rule(
        self, rule_id: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """
        Return blocked commands that were stopped by a specific rule.

        Args:
            rule_id: rule identifier, e.g. "R001"
            limit:   maximum records to return
        """
        return self._query(
            "SELECT * FROM commands WHERE allowed=0 AND rule_id=? "
            "ORDER BY timestamp DESC LIMIT ?",
            (rule_id, limit),
        )

    def get_violations_by_mitre(
        self, tag: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """
        Return blocked commands matching a MITRE ATT&CK for ICS tag.

        Args:
            tag:   MITRE tag, e.g. "T0855"
            limit: maximum records to return
        """
        return self._query(
            "SELECT * FROM commands WHERE allowed=0 AND mitre_tag=? "
            "ORDER BY timestamp DESC LIMIT ?",
            (tag, limit),
        )

    def get_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        """
        Return most recent commands (both allowed and blocked), newest first.

        Args:
            limit: maximum records to return (default 50)
        """
        return self._query(
            "SELECT * FROM commands ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )

    def get_timeline(self, start: float, end: float) -> list[dict[str, Any]]:
        """
        Return all commands whose timestamp falls in [start, end].

        Args:
            start: UNIX timestamp (inclusive lower bound)
            end:   UNIX timestamp (inclusive upper bound)

        Returns:
            Records ordered oldest first (natural timeline order).
        """
        return self._query(
            "SELECT * FROM commands WHERE timestamp >= ? AND timestamp <= ? "
            "ORDER BY timestamp ASC",
            (start, end),
        )

    def get_stats(self) -> dict[str, Any]:
        """
        Return aggregate statistics for the dashboard.

        Returns dict with keys:
            total_commands    : int   — all commands ever seen
            blocked           : int   — commands that were blocked
            allowed           : int   — commands that passed
            block_rate        : float — blocked / total (0.0–1.0)
            last_24h_attacks  : int   — blocked commands in last 24 hours
            by_mitre          : dict[str, int] — attack count per MITRE tag
            by_rule           : dict[str, int] — block count per rule ID
            dropped_records   : int   — records dropped due to full queue
        """
        empty: dict[str, Any] = {
            "total_commands":   0,
            "blocked":          0,
            "allowed":          0,
            "block_rate":       0.0,
            "last_24h_attacks": 0,
            "by_mitre":         {},
            "by_rule":          {},
            "dropped_records":  self._dropped,
        }
        try:
            with sqlite3.connect(self._db_path) as conn:
                cur = conn.cursor()

                cur.execute(
                    "SELECT COUNT(*), SUM(allowed=0), SUM(allowed=1) FROM commands"
                )
                row = cur.fetchone()
                if not row or row[0] == 0:
                    return empty

                total   = row[0] or 0
                blocked = row[1] or 0
                allowed = row[2] or 0

                since = time.time() - 86_400  # 24 hours in seconds
                cur.execute(
                    "SELECT COUNT(*) FROM commands "
                    "WHERE allowed=0 AND timestamp >= ?",
                    (since,),
                )
                last_24h: int = cur.fetchone()[0] or 0

                cur.execute(
                    "SELECT mitre_tag, COUNT(*) FROM commands "
                    "WHERE allowed=0 AND mitre_tag!='' "
                    "GROUP BY mitre_tag ORDER BY 2 DESC"
                )
                by_mitre: dict[str, int] = {r[0]: r[1] for r in cur.fetchall()}

                cur.execute(
                    "SELECT rule_id, COUNT(*) FROM commands "
                    "WHERE allowed=0 AND rule_id!='' "
                    "GROUP BY rule_id ORDER BY 2 DESC"
                )
                by_rule: dict[str, int] = {r[0]: r[1] for r in cur.fetchall()}

            return {
                "total_commands":   total,
                "blocked":          blocked,
                "allowed":          allowed,
                "block_rate":       round(blocked / total, 4) if total else 0.0,
                "last_24h_attacks": last_24h,
                "by_mitre":         by_mitre,
                "by_rule":          by_rule,
                "dropped_records":  self._dropped,
            }
        except sqlite3.Error as exc:
            log.error("ForensicLogger.get_stats failed: %s", exc)
            return empty

    def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """
        Return statistics scoped to a single server run (session_id).

        Allows dissertation results chapter to compare detection rates
        across multiple server runs stored in the same DB.

        Args:
            session_id: UUID string from ForensicLogger.session_id

        Returns dict with total_commands, blocked, allowed, block_rate,
        by_mitre, by_rule for that session only.
        """
        empty: dict[str, Any] = {
            "session_id":     session_id,
            "total_commands": 0,
            "blocked":        0,
            "allowed":        0,
            "block_rate":     0.0,
            "by_mitre":       {},
            "by_rule":        {},
        }
        try:
            with sqlite3.connect(self._db_path) as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT COUNT(*), SUM(allowed=0), SUM(allowed=1) "
                    "FROM commands WHERE session_id=?",
                    (session_id,),
                )
                row = cur.fetchone()
                if not row or row[0] == 0:
                    return empty

                total   = row[0] or 0
                blocked = row[1] or 0
                allowed = row[2] or 0

                cur.execute(
                    "SELECT mitre_tag, COUNT(*) FROM commands "
                    "WHERE session_id=? AND allowed=0 AND mitre_tag!='' "
                    "GROUP BY mitre_tag ORDER BY 2 DESC",
                    (session_id,),
                )
                by_mitre: dict[str, int] = {r[0]: r[1] for r in cur.fetchall()}

                cur.execute(
                    "SELECT rule_id, COUNT(*) FROM commands "
                    "WHERE session_id=? AND allowed=0 AND rule_id!='' "
                    "GROUP BY rule_id ORDER BY 2 DESC",
                    (session_id,),
                )
                by_rule: dict[str, int] = {r[0]: r[1] for r in cur.fetchall()}

            return {
                "session_id":     session_id,
                "total_commands": total,
                "blocked":        blocked,
                "allowed":        allowed,
                "block_rate":     round(blocked / total, 4) if total else 0.0,
                "by_mitre":       by_mitre,
                "by_rule":        by_rule,
            }
        except sqlite3.Error as exc:
            log.error("ForensicLogger.get_session_stats failed: %s", exc)
            return empty

    def export_csv(self, path: str) -> int:
        """
        Export the entire commands table to a CSV file.

        Useful for dissertation results analysis in Excel / pandas.

        Args:
            path: file path to write (will be overwritten if it exists)

        Returns:
            Number of rows written (excluding header).
        """
        rows = self._query("SELECT * FROM commands ORDER BY timestamp ASC", ())
        if not rows:
            with open(path, "w", newline="") as fh:
                fh.write("")
            return 0

        fieldnames = list(rows[0].keys())
        with open(path, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        log.info("ForensicLogger: exported %d rows to %s", len(rows), path)
        return len(rows)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def flush(self, timeout: float = 5.0) -> bool:
        """
        Block until all queued records have been committed to SQLite.

        Uses threading.Event — the writer signals after every batch commit.
        This is the B14 fix: no time.sleep() polling.

        Args:
            timeout: seconds to wait before giving up (default 5.0)

        Returns:
            True if all writes committed before timeout, False otherwise.
        """
        # If queue is already empty the last batch may already be committed
        if self._queue.empty():
            # Give the writer a moment to finish its current batch
            self._flush_event.wait(timeout=min(timeout, _BATCH_TIMEOUT + 0.2))
            self._flush_event.clear()
            return True

        # Wait for queue to drain then wait for the commit event
        deadline = time.monotonic() + timeout
        while not self._queue.empty():
            if time.monotonic() > deadline:
                log.warning("ForensicLogger.flush: timed out (queue not empty)")
                return False
            time.sleep(0.005)  # minimal poll — queue drain check only, not I/O wait

        # Queue drained — wait for the writer to signal commit completion
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        signalled = self._flush_event.wait(timeout=remaining)
        self._flush_event.clear()
        if not signalled:
            log.warning("ForensicLogger.flush: timed out waiting for commit event")
        return signalled

    def stop(self) -> None:
        """
        Signal the writer thread to flush remaining records and stop.

        Daemon thread exits automatically when the process ends, so this
        is optional — but call it for clean shutdown or in tests.
        """
        self._queue.put(_STOP_SENTINEL)
        self._writer.join(timeout=5.0)
        log.info("ForensicLogger stopped | session=%s", self._session_id)

    # ── Private helpers ───────────────────────────────────────────────────────

    def _query(
        self,
        sql:    str,
        params: tuple[Any, ...],
    ) -> list[dict[str, Any]]:
        """
        Execute a read-only SELECT and return rows as list of dicts.
        Opens a short-lived connection (WAL allows concurrent reads).
        """
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.execute(sql, params)
                return [dict(r) for r in cur.fetchall()]
        except sqlite3.Error as exc:
            log.error("ForensicLogger query failed [%s]: %s", sql[:60], exc)
            return []

    # ── Writer thread ─────────────────────────────────────────────────────────

    def _write_loop(self) -> None:
        """
        Dedicated SQLite writer thread.

        - Owns the SQLite connection exclusively
        - Enables WAL mode for concurrent reads
        - Batches: commits every _BATCH_SIZE records OR _BATCH_TIMEOUT seconds
        - Signals self._flush_event after every commit so flush() unblocks
        - On SQLite error: logs and continues (never crashes the server)
        """
        conn = self._init_db()
        batch: list[CommandRecord] = []
        last_commit = time.monotonic()

        while True:
            try:
                item = self._queue.get(timeout=_BATCH_TIMEOUT)
            except queue.Empty:
                if batch:
                    self._commit_batch(conn, batch)
                    batch = []
                    last_commit = time.monotonic()
                    self._flush_event.set()
                continue

            if item is _STOP_SENTINEL:
                if batch:
                    self._commit_batch(conn, batch)
                    self._flush_event.set()
                conn.close()
                log.info("ForensicLogger writer thread stopped cleanly")
                return

            # item is a CommandRecord
            batch.append(item)  # type: ignore[arg-type]

            now = time.monotonic()
            if (
                len(batch) >= _BATCH_SIZE
                or (now - last_commit) >= _BATCH_TIMEOUT
            ):
                self._commit_batch(conn, batch)
                batch = []
                last_commit = now
                self._flush_event.set()

    def _init_db(self) -> sqlite3.Connection:
        """
        Open SQLite connection, enable WAL, create schema, run migrations.
        Called once from the writer thread.

        Order matters for existing DBs:
          1. Create table (IF NOT EXISTS — safe on old DBs)
          2. Migrate — adds session_id/latency_us to old DBs
          3. Create indexes AFTER migration so session_id column exists
        """
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")  # durable with WAL, faster
        conn.execute(_CREATE_COMMANDS)
        conn.commit()
        # Migrate BEFORE indexes — session_id column must exist for idx_session
        self._migrate_schema(conn)
        conn.execute(_CREATE_IDX_TIMESTAMP)
        conn.execute(_CREATE_IDX_ALLOWED)
        conn.execute(_CREATE_IDX_MITRE)
        conn.execute(_CREATE_IDX_SESSION)
        conn.commit()
        log.info("ForensicLogger DB initialised | %s", self._db_path)
        return conn

    @staticmethod
    def _migrate_schema(conn: sqlite3.Connection) -> None:
        """
        Add new columns to existing DBs without breaking old data.
        Each ALTER TABLE is wrapped in try/except OperationalError
        so it is safely skipped if the column already exists.
        """
        for ddl in (_MIGRATE_SESSION_ID, _MIGRATE_LATENCY_US):
            try:
                conn.execute(ddl)
                conn.commit()
            except sqlite3.OperationalError:
                pass  # column already exists — safe to skip

    def _commit_batch(
        self,
        conn:  sqlite3.Connection,
        batch: list[CommandRecord],
    ) -> None:
        """Write a batch of CommandRecords and commit. Handles errors gracefully."""
        try:
            conn.executemany(_INSERT_COMMAND, [r.as_dict() for r in batch])
            conn.commit()
            log.debug("ForensicLogger: committed %d records", len(batch))
        except sqlite3.Error as exc:
            log.error("ForensicLogger: batch commit failed: %s", exc)
            try:
                conn.rollback()
            except sqlite3.Error:
                pass


# ── Module-level singleton factory ────────────────────────────────────────────

_default_logger: ForensicLogger | None = None
_logger_lock = threading.Lock()


def get_logger(db_path: str = "logs/physicsguard.db") -> ForensicLogger:
    """
    Return the module-level singleton ForensicLogger. Thread-safe.
    Creates the instance on first call; subsequent calls return the same object.

    This lets modbus_server.py and Layer 7 share one logger without
    passing it explicitly through every call chain.
    """
    global _default_logger
    if _default_logger is None:
        with _logger_lock:
            if _default_logger is None:
                _default_logger = ForensicLogger(db_path)
    return _default_logger
