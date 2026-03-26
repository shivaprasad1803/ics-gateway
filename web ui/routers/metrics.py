"""
metrics.py  —  GET /api/metrics live engine performance metrics
Layer 7  |  PhysicsGuard ICS Security Gateway
Week 7 deliverable: total validated, blocked, and average latency
"""
import logging

from fastapi import APIRouter, HTTPException, Request

from web_ui.models import MetricsResponse

log = logging.getLogger(__name__)

router = APIRouter(tags=["metrics"])


@router.get("/metrics", response_model=MetricsResponse)
def get_metrics(request: Request) -> MetricsResponse:
    """Return live performance counters from the ValidationEngine.

    ValidationEngine.get_metrics() may return either a dict or an
    EngineMetrics dataclass/namedtuple.  We handle both forms and map
    the real field names:
      total_evaluated  -> total_validated
      mean_latency_us  -> avg_latency_us

    Raises:
        HTTPException 503: If the validation engine is unavailable.
    """
    try:
        raw = request.app.state.engine.get_metrics()
    except Exception as exc:
        log.error("metrics query failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Validation engine unavailable") from exc

    # Support both dict and object (dataclass / namedtuple) return types.
    if isinstance(raw, dict):
        get = lambda key, fallback=0: raw.get(key, fallback)
    else:
        get = lambda key, fallback=0: getattr(raw, key, fallback)

    # Map actual field names → our API field names.
    total_validated = int(
        get("total_validated") or get("total_evaluated") or 0
    )
    total_blocked = int(
        get("total_blocked") or 0
    )
    avg_latency_us = float(
        get("avg_latency_us") or get("mean_latency_us") or 0.0
    )

    log.debug(
        "metrics query — validated=%d blocked=%d avg_us=%.1f",
        total_validated, total_blocked, avg_latency_us,
    )
    return MetricsResponse(
        total_validated=total_validated,
        total_blocked=total_blocked,
        avg_latency_us=avg_latency_us,
    )
