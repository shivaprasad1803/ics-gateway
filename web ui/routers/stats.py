"""
stats.py  —  GET /api/stats aggregate forensic statistics
Layer 7  |  PhysicsGuard ICS Security Gateway
Week 7 deliverable: summary counts, block rate, per-rule and per-MITRE breakdown
"""
import logging

from fastapi import APIRouter, HTTPException, Request

from web_ui.models import StatsResponse

log = logging.getLogger(__name__)

router = APIRouter(tags=["stats"])


@router.get("/stats", response_model=StatsResponse)
def get_stats(request: Request) -> StatsResponse:
    """Return aggregate statistics from the forensic log.

    ForensicLogger.get_stats() returns 'total_commands' (not 'total').
    We accept both key names for forward/backward compatibility.

    Raises:
        HTTPException 503: If the forensic logger is unavailable.
    """
    try:
        raw: dict = request.app.state.flogger.get_stats()
    except Exception as exc:
        log.error("stats query failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Forensic logger unavailable") from exc

    # ForensicLogger returns 'total_commands'; fall back to 'total' for compatibility.
    total   = int(raw.get("total_commands") or raw.get("total") or 0)
    blocked = int(raw.get("blocked") or 0)
    log.debug("stats query — total=%d blocked=%d", total, blocked)

    # Clamp block_rate defensively before handing to Pydantic validator.
    block_rate = max(0.0, min(1.0, float(raw.get("block_rate") or 0.0)))

    return StatsResponse(
        total=total,
        blocked=blocked,
        block_rate=block_rate,
        by_rule=raw.get("by_rule", {}),
        by_mitre=raw.get("by_mitre", {}),
    )
