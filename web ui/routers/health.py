"""
health.py  —  GET /api/health liveness endpoint
Layer 7  |  PhysicsGuard ICS Security Gateway
Week 7 deliverable: uptime and version heartbeat
"""
import logging
import time

from fastapi import APIRouter, Request

from web_ui.models import HealthResponse

log = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def get_health(request: Request) -> HealthResponse:
    """Return gateway liveness, uptime in seconds, and software version.

    Version is sourced from the FastAPI app metadata so it can never
    drift out of sync with the value declared in main.py.
    """
    start: float = request.app.state.start_time
    uptime_s: float = round(time.monotonic() - start, 3)
    version: str = request.app.version
    log.debug("health probe — uptime_s=%.3f version=%s", uptime_s, version)
    return HealthResponse(status="ok", uptime_s=uptime_s, version=version)
