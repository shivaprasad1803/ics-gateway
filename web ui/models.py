"""
models.py  —  Pydantic response models for PhysicsGuard REST API
Layer 7  |  PhysicsGuard ICS Security Gateway
Week 7 deliverable: typed response schemas for all endpoints
"""
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Response schema for GET /api/health."""

    status: str
    uptime_s: float
    version: str


class ViolationRecord(BaseModel):
    """Single forensic log entry returned by the violations endpoints."""

    id: int
    timestamp: str
    address: int
    value: float
    allowed: bool
    rule_id: str
    severity: str
    mitre_tag: str
    reason: str
    source_ip: str
    latency_us: float


class StatsResponse(BaseModel):
    """Aggregate statistics returned by GET /api/stats."""

    total: int
    blocked: int
    block_rate: float = Field(ge=0.0, le=1.0, description="Fraction of commands blocked [0, 1]")
    by_rule: dict[str, int]
    by_mitre: dict[str, int]


class TimelinePoint(BaseModel):
    """One hourly bucket returned by GET /api/timeline."""

    hour: str
    total: int
    blocked: int


class RuleInfo(BaseModel):
    """Summary of a single validation rule returned by GET /api/rules."""

    rule_id: str
    enabled: bool
    severity: str
    priority: int
    mitre_tag: str


class MetricsResponse(BaseModel):
    """Live engine metrics returned by GET /api/metrics."""

    total_validated: int
    total_blocked: int
    avg_latency_us: float

