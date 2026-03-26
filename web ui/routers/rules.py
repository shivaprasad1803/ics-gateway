"""
rules.py  —  GET /api/rules active validation-rule listing
Layer 7  |  PhysicsGuard ICS Security Gateway
Week 7 deliverable: live rule catalogue from ValidationEngine
"""
import logging

from fastapi import APIRouter, HTTPException, Request

from web_ui.models import RuleInfo

log = logging.getLogger(__name__)

router = APIRouter(tags=["rules"])


@router.get("/rules", response_model=list[RuleInfo])
def get_rules(request: Request) -> list[RuleInfo]:
    """Return metadata for every rule loaded in the ValidationEngine.

    Raises:
        HTTPException 503: If the validation engine is unavailable.
    """
    try:
        raw: list[dict] = request.app.state.engine.get_rules()
    except Exception as exc:
        log.error("rules query failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Validation engine unavailable") from exc

    log.debug("rules query — count=%d", len(raw))
    return [
        RuleInfo(
            rule_id=r["rule_id"],
            enabled=bool(r.get("enabled", True)),
            severity=r.get("severity", ""),
            priority=int(r.get("priority", 0)),
            mitre_tag=r.get("mitre_tag", ""),
        )
        for r in raw
    ]
