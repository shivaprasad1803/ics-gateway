"""
test_web_ui.py  —  Layer 7 REST API tests (FastAPI TestClient, no running server)
Layer 7  |  PhysicsGuard ICS Security Gateway
Week 7 deliverable: ≥ 20 unit tests covering all endpoints
"""
import time
import logging
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from web_ui.main import app

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared mock data
# ---------------------------------------------------------------------------

MOCK_STATS: dict = {
    "total": 50,
    "blocked": 12,
    "block_rate": 0.24,
    "by_rule": {"R001": 5, "R002": 4, "R003": 3},
    "by_mitre": {"T0855": 8, "T0813": 4},
}

MOCK_VIOLATIONS: list[dict] = [
    {
        "id": 1,
        "timestamp": "2026-03-17T10:00:00",
        "address": 1,
        "value": 150.0,
        "allowed": False,
        "rule_id": "R001",
        "severity": "CRITICAL",
        "mitre_tag": "T0855",
        "reason": "valve out of range",
        "source_ip": "127.0.0.1",
        "latency_us": 841.3,
    },
    {
        "id": 2,
        "timestamp": "2026-03-17T11:00:00",
        "address": 2,
        "value": 1.0,
        "allowed": False,
        "rule_id": "R003",
        "severity": "EMERGENCY",
        "mitre_tag": "T0813",
        "reason": "pump interlock",
        "source_ip": "127.0.0.1",
        "latency_us": 312.5,
    },
    {
        "id": 3,
        "timestamp": "2026-03-17T12:00:00",
        "address": 1,
        "value": 50.0,
        "allowed": True,
        "rule_id": "R001",
        "severity": "INFO",
        "mitre_tag": "T0855",
        "reason": "",
        "source_ip": "127.0.0.1",
        "latency_us": 120.0,
    },
]

MOCK_TIMELINE: list[dict] = [
    {"hour": "2026-03-17T10:00", "total": 5, "blocked": 2},
    {"hour": "2026-03-17T11:00", "total": 8, "blocked": 3},
]

MOCK_RULES: list[dict] = [
    {"rule_id": "R001", "enabled": True, "severity": "CRITICAL", "priority": 10, "mitre_tag": "T0855"},
    {"rule_id": "R003", "enabled": True, "severity": "EMERGENCY", "priority": 30, "mitre_tag": "T0813"},
]

MOCK_METRICS: dict = {
    "total_validated": 1500,
    "total_blocked": 42,
    "avg_latency_us": 312.4,
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client() -> TestClient:
    """Return a TestClient with mocked ForensicLogger and ValidationEngine.

    Mocks are injected into app.state *before* TestClient starts so that
    the lifespan _already_injected guard in main.py skips real DB/YAML
    imports entirely.
    """
    mock_flogger = MagicMock()
    mock_flogger.get_stats.return_value = MOCK_STATS
    mock_flogger.get_violations.return_value = MOCK_VIOLATIONS
    mock_flogger.get_timeline.return_value = MOCK_TIMELINE

    mock_engine = MagicMock()
    mock_engine.get_rules.return_value = MOCK_RULES
    mock_engine.get_metrics.return_value = MOCK_METRICS

    app.state.start_time = time.monotonic()
    app.state.flogger = mock_flogger
    app.state.engine = mock_engine

    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


# ---------------------------------------------------------------------------
# /api/health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_returns_200(self, client: TestClient) -> None:
        """GET /api/health must return HTTP 200."""
        resp = client.get("/api/health")
        assert resp.status_code == 200, "Expected 200 from /api/health"

    def test_health_status_is_ok(self, client: TestClient) -> None:
        """Response body must contain status='ok'."""
        body = client.get("/api/health").json()
        assert body["status"] == "ok", f"Expected status='ok', got {body['status']!r}"

    def test_health_has_required_keys(self, client: TestClient) -> None:
        """Response must include status, uptime_s, and version keys."""
        body = client.get("/api/health").json()
        for key in ("status", "uptime_s", "version"):
            assert key in body, f"Missing key {key!r} in /api/health response"

    def test_health_uptime_is_non_negative(self, client: TestClient) -> None:
        """uptime_s must be a non-negative float."""
        body = client.get("/api/health").json()
        assert body["uptime_s"] >= 0.0, "uptime_s must be >= 0"

    def test_health_version_string(self, client: TestClient) -> None:
        """version field must be a non-empty string."""
        body = client.get("/api/health").json()
        assert isinstance(body["version"], str) and body["version"], (
            "version must be a non-empty string"
        )

    def test_health_version_matches_app_metadata(self, client: TestClient) -> None:
        """version in response must match the FastAPI app.version (single source of truth)."""
        body = client.get("/api/health").json()
        assert body["version"] == app.version, (
            f"Health version {body['version']!r} != app.version {app.version!r}"
        )

    def test_health_uptime_increases(self, client: TestClient) -> None:
        """Two successive health probes must show non-decreasing uptime."""
        first = client.get("/api/health").json()["uptime_s"]
        second = client.get("/api/health").json()["uptime_s"]
        assert second >= first, "uptime_s must not decrease between calls"


# ---------------------------------------------------------------------------
# /api/stats
# ---------------------------------------------------------------------------

class TestStats:
    def test_stats_returns_200(self, client: TestClient) -> None:
        """GET /api/stats must return HTTP 200."""
        assert client.get("/api/stats").status_code == 200, "Expected 200 from /api/stats"

    def test_stats_has_required_keys(self, client: TestClient) -> None:
        """Response must contain total, blocked, block_rate, by_rule, by_mitre."""
        body = client.get("/api/stats").json()
        for key in ("total", "blocked", "block_rate", "by_rule", "by_mitre"):
            assert key in body, f"Missing key {key!r} in /api/stats response"

    def test_stats_block_rate_is_between_0_and_1(self, client: TestClient) -> None:
        """block_rate must be a float in [0.0, 1.0]."""
        block_rate = client.get("/api/stats").json()["block_rate"]
        assert 0.0 <= block_rate <= 1.0, f"block_rate={block_rate} out of [0, 1]"

    def test_stats_by_rule_is_dict(self, client: TestClient) -> None:
        """by_rule must be a dict mapping rule IDs to counts."""
        assert isinstance(client.get("/api/stats").json()["by_rule"], dict), (
            "by_rule must be a dict"
        )

    def test_stats_by_mitre_is_dict(self, client: TestClient) -> None:
        """by_mitre must be a dict mapping MITRE tags to counts."""
        assert isinstance(client.get("/api/stats").json()["by_mitre"], dict), (
            "by_mitre must be a dict"
        )

    def test_stats_returns_503_when_logger_fails(self, client: TestClient) -> None:
        """GET /api/stats must return 503 when ForensicLogger raises."""
        app.state.flogger.get_stats.side_effect = RuntimeError("db locked")
        resp = client.get("/api/stats")
        assert resp.status_code == 503, f"Expected 503, got {resp.status_code}"
        # Teardown
        app.state.flogger.get_stats.side_effect = None
        app.state.flogger.get_stats.return_value = MOCK_STATS


# ---------------------------------------------------------------------------
# /api/violations
# ---------------------------------------------------------------------------

class TestViolations:
    def test_violations_returns_200(self, client: TestClient) -> None:
        """GET /api/violations must return HTTP 200."""
        assert client.get("/api/violations").status_code == 200, "Expected 200"

    def test_violations_returns_list(self, client: TestClient) -> None:
        """Response body must be a JSON array."""
        assert isinstance(client.get("/api/violations").json(), list), (
            "Expected a list from /api/violations"
        )

    def test_violations_limit_parameter(self, client: TestClient) -> None:
        """?limit=1 must return at most 1 item."""
        # Arrange — scoped side_effect; reset in teardown to avoid leaking state
        app.state.flogger.get_violations.side_effect = lambda limit: MOCK_VIOLATIONS[:limit]
        body = client.get("/api/violations?limit=1").json()
        assert len(body) <= 1, f"Expected at most 1 violation, got {len(body)}"
        # Teardown
        app.state.flogger.get_violations.side_effect = None
        app.state.flogger.get_violations.return_value = MOCK_VIOLATIONS

    def test_violations_record_has_required_fields(self, client: TestClient) -> None:
        """Every violation record must have all documented fields."""
        body = client.get("/api/violations").json()
        required = {
            "id", "timestamp", "address", "value", "allowed",
            "rule_id", "severity", "mitre_tag", "reason", "source_ip", "latency_us",
        }
        for record in body:
            missing = required - record.keys()
            assert not missing, f"Violation record missing fields: {missing}"

    def test_violations_by_rule_returns_only_matching(self, client: TestClient) -> None:
        """GET /api/violations/rule/R001 must return only R001 records."""
        body = client.get("/api/violations/rule/R001").json()
        assert len(body) > 0, "Expected at least one R001 violation in mock data"
        assert all(r["rule_id"] == "R001" for r in body), "Non-R001 records in filtered result"

    def test_violations_by_rule_nonexistent_returns_empty_list(self, client: TestClient) -> None:
        """Unknown rule_id must return [] not 404."""
        resp = client.get("/api/violations/rule/NONEXISTENT")
        assert resp.status_code == 200, "Expected 200, not 404, for unknown rule_id"
        assert resp.json() == [], "Expected empty list for unknown rule_id"

    def test_violations_by_mitre_returns_only_matching(self, client: TestClient) -> None:
        """GET /api/violations/mitre/T0855 must return only T0855 records."""
        body = client.get("/api/violations/mitre/T0855").json()
        assert len(body) > 0, "Expected at least one T0855 violation in mock data"
        assert all(r["mitre_tag"] == "T0855" for r in body), "Non-T0855 records in MITRE filter"

    def test_violations_by_mitre_nonexistent_returns_empty_list(self, client: TestClient) -> None:
        """Unknown MITRE tag must return [] not 404."""
        resp = client.get("/api/violations/mitre/T9999")
        assert resp.status_code == 200, "Expected 200 for unknown MITRE tag"
        assert resp.json() == [], "Expected empty list for unknown MITRE tag"

    def test_violations_returns_503_when_logger_fails(self, client: TestClient) -> None:
        """GET /api/violations must return 503 when ForensicLogger raises."""
        app.state.flogger.get_violations.side_effect = RuntimeError("db locked")
        resp = client.get("/api/violations")
        assert resp.status_code == 503, f"Expected 503, got {resp.status_code}"
        # Teardown
        app.state.flogger.get_violations.side_effect = None
        app.state.flogger.get_violations.return_value = MOCK_VIOLATIONS

    def test_timeline_returns_200(self, client: TestClient) -> None:
        """GET /api/timeline must return HTTP 200."""
        assert client.get("/api/timeline").status_code == 200, "Expected 200 from /api/timeline"

    def test_timeline_returns_list(self, client: TestClient) -> None:
        """GET /api/timeline must return a JSON array."""
        assert isinstance(client.get("/api/timeline").json(), list), (
            "Expected list from /api/timeline"
        )

    def test_timeline_bucket_has_required_fields(self, client: TestClient) -> None:
        """Each timeline bucket must have hour, total, blocked."""
        body = client.get("/api/timeline").json()
        for bucket in body:
            for key in ("hour", "total", "blocked"):
                assert key in bucket, f"Timeline bucket missing field {key!r}"


# ---------------------------------------------------------------------------
# /api/rules
# ---------------------------------------------------------------------------

class TestRules:
    def test_rules_returns_200(self, client: TestClient) -> None:
        """GET /api/rules must return HTTP 200."""
        assert client.get("/api/rules").status_code == 200, "Expected 200 from /api/rules"

    def test_rules_returns_list(self, client: TestClient) -> None:
        """Response must be a JSON array."""
        assert isinstance(client.get("/api/rules").json(), list), "Expected list from /api/rules"

    def test_rules_each_has_required_fields(self, client: TestClient) -> None:
        """Every rule must have rule_id, enabled, severity, priority, mitre_tag."""
        body = client.get("/api/rules").json()
        required = {"rule_id", "enabled", "severity", "priority", "mitre_tag"}
        for rule in body:
            missing = required - rule.keys()
            assert not missing, f"Rule record missing fields: {missing}"

    def test_rules_enabled_is_bool(self, client: TestClient) -> None:
        """The enabled field must be a boolean."""
        body = client.get("/api/rules").json()
        for rule in body:
            assert isinstance(rule["enabled"], bool), (
                f"enabled is not bool in rule {rule['rule_id']}"
            )

    def test_rules_returns_503_when_engine_fails(self, client: TestClient) -> None:
        """GET /api/rules must return 503 when ValidationEngine raises."""
        app.state.engine.get_rules.side_effect = RuntimeError("engine crashed")
        resp = client.get("/api/rules")
        assert resp.status_code == 503, f"Expected 503, got {resp.status_code}"
        # Teardown
        app.state.engine.get_rules.side_effect = None
        app.state.engine.get_rules.return_value = MOCK_RULES


# ---------------------------------------------------------------------------
# /api/metrics
# ---------------------------------------------------------------------------

class TestMetrics:
    def test_metrics_returns_200(self, client: TestClient) -> None:
        """GET /api/metrics must return HTTP 200."""
        assert client.get("/api/metrics").status_code == 200, "Expected 200 from /api/metrics"

    def test_metrics_has_required_keys(self, client: TestClient) -> None:
        """Response must include total_validated, total_blocked, avg_latency_us."""
        body = client.get("/api/metrics").json()
        for key in ("total_validated", "total_blocked", "avg_latency_us"):
            assert key in body, f"Missing key {key!r} in /api/metrics"

    def test_metrics_avg_latency_non_negative(self, client: TestClient) -> None:
        """avg_latency_us must be >= 0."""
        avg = client.get("/api/metrics").json()["avg_latency_us"]
        assert avg >= 0.0, f"avg_latency_us={avg} is negative"

    def test_metrics_returns_503_when_engine_fails(self, client: TestClient) -> None:
        """GET /api/metrics must return 503 when ValidationEngine raises."""
        app.state.engine.get_metrics.side_effect = RuntimeError("engine crashed")
        resp = client.get("/api/metrics")
        assert resp.status_code == 503, f"Expected 503, got {resp.status_code}"
        # Teardown
        app.state.engine.get_metrics.side_effect = None
        app.state.engine.get_metrics.return_value = MOCK_METRICS
