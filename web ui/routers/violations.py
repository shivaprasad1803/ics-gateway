"""
violations.py  —  GET /api/violations* endpoints
Layer 7  |  PhysicsGuard ICS Security Gateway
Week 7 deliverable: paginated violation log with rule and MITRE filters
"""
import logging
import time as _time

from fastapi import APIRouter, HTTPException, Query, Request

from web_ui.models import ViolationRecord, TimelinePoint

log = logging.getLogger(__name__)

router = APIRouter(tags=["violations"])

DEFAULT_LIMIT = 100
DEFAULT_TIMELINE_HOURS = 24

# Internal fetch ceiling used when filtering by rule/MITRE so that the
# user-facing limit applies *after* filtering, not before.
_FILTER_FETCH_CEILING = 10_000


def _to_record(row: dict) -> ViolationRecord:
    """Convert a raw forensic-log dict to a typed ViolationRecord.

    Uses .get() with safe defaults for every field so that a NULL value
    or missing key from SQLite never raises KeyError or TypeError.
    """
    raw_value   = row.get("value")
    raw_latency = row.get("latency_us")
    return ViolationRecord(
        id=int(row.get("id") or 0),
        timestamp=str(row.get("timestamp") or ""),
        address=int(row.get("address") or 0),
        value=float(raw_value) if raw_value is not None else 0.0,
        allowed=bool(row.get("allowed")),
        rule_id=row.get("rule_id") or "",
        severity=row.get("severity") or "",
        mitre_tag=row.get("mitre_tag") or "",
        reason=row.get("reason") or "",
        source_ip=row.get("source_ip") or "",
        latency_us=float(raw_latency) if raw_latency is not None else 0.0,
    )


def _bucket_rows(rows: list[dict], hours: int) -> list[TimelinePoint]:
    """Group raw violation rows into per-hour buckets client-side.

    Used as a fallback when ForensicLogger.get_timeline() returns raw
    rows instead of pre-aggregated buckets.
    """
    from collections import defaultdict
    import datetime

    counts: dict[str, dict] = defaultdict(lambda: {"total": 0, "blocked": 0})
    cutoff = _time.time() - hours * 3600.0

    for r in rows:
        ts_raw = r.get("timestamp") or 0
        try:
            ts = float(ts_raw)
        except (TypeError, ValueError):
            # ISO string timestamp
            try:
                ts = datetime.datetime.fromisoformat(str(ts_raw)).timestamp()
            except Exception:
                continue
        if ts < cutoff:
            continue
        hour_key = datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%dT%H:00")
        counts[hour_key]["total"] += 1
        if not r.get("allowed"):
            counts[hour_key]["blocked"] += 1

    return [
        TimelinePoint(hour=k, total=v["total"], blocked=v["blocked"])
        for k, v in sorted(counts.items())
    ]


@router.get("/violations", response_model=list[ViolationRecord])
def get_violations(
    request: Request,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=10_000, description="Max rows to return"),
) -> list[ViolationRecord]:
    """Return the most recent *limit* forensic log entries (all commands).

    Raises:
        HTTPException 503: If the forensic logger is unavailable.
    """
    try:
        rows: list[dict] = request.app.state.flogger.get_violations(limit=limit)
    except Exception as exc:
        log.error("violations query failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Forensic logger unavailable") from exc

    log.debug("violations query — limit=%d returned=%d", limit, len(rows))
    return [_to_record(r) for r in rows]


@router.get("/violations/rule/{rule_id}", response_model=list[ViolationRecord])
def get_violations_by_rule(
    rule_id: str,
    request: Request,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=10_000),
) -> list[ViolationRecord]:
    """Return up to *limit* violations triggered by a specific rule.

    Returns an empty list (not 404) when *rule_id* has no matches.

    Raises:
        HTTPException 503: If the forensic logger is unavailable.
    """
    try:
        rows: list[dict] = request.app.state.flogger.get_violations(limit=_FILTER_FETCH_CEILING)
    except Exception as exc:
        log.error("violations/rule/%s query failed: %s", rule_id, exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Forensic logger unavailable") from exc

    filtered = [r for r in rows if r.get("rule_id") == rule_id][:limit]
    log.debug("violations/rule/%s — matched=%d (limit=%d)", rule_id, len(filtered), limit)
    return [_to_record(r) for r in filtered]


@router.get("/violations/mitre/{tag}", response_model=list[ViolationRecord])
def get_violations_by_mitre(
    tag: str,
    request: Request,
    limit: int = Query(default=DEFAULT_LIMIT, ge=1, le=10_000),
) -> list[ViolationRecord]:
    """Return up to *limit* violations associated with a specific MITRE ATT&CK tag.

    Returns an empty list (not 404) when *tag* has no matches.

    Raises:
        HTTPException 503: If the forensic logger is unavailable.
    """
    try:
        rows: list[dict] = request.app.state.flogger.get_violations(limit=_FILTER_FETCH_CEILING)
    except Exception as exc:
        log.error("violations/mitre/%s query failed: %s", tag, exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Forensic logger unavailable") from exc

    filtered = [r for r in rows if r.get("mitre_tag") == tag][:limit]
    log.debug("violations/mitre/%s — matched=%d (limit=%d)", tag, len(filtered), limit)
    return [_to_record(r) for r in filtered]


@router.get("/timeline", response_model=list[TimelinePoint])
def get_timeline(
    request: Request,
    hours: int = Query(default=DEFAULT_TIMELINE_HOURS, ge=1, le=720, description="Lookback window"),
) -> list[TimelinePoint]:
    """Return per-hour command totals and block counts for the last *hours* hours.

    ForensicLogger.get_timeline() signature is (start: float, end: float).
    We compute UNIX timestamps from the requested hours window and pass
    them as positional arguments.

    Raises:
        HTTPException 503: If the forensic logger is unavailable.
    """
    end   = _time.time()
    start = end - hours * 3600.0

    try:
        result = request.app.state.flogger.get_timeline(start, end)
    except Exception as exc:
        log.error("timeline query failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=503, detail="Forensic logger unavailable") from exc

    # get_timeline may return either pre-aggregated dicts with 'hour'/'total'/'blocked'
    # keys, or raw violation rows — handle both gracefully.
    if result and isinstance(result[0], dict) and "hour" in result[0]:
        # Pre-aggregated path — direct mapping
        buckets = [
            TimelinePoint(
                hour=str(b.get("hour") or ""),
                total=int(b.get("total") or 0),
                blocked=int(b.get("blocked") or 0),
            )
            for b in result
        ]
    else:
        # Raw rows path — bucket them ourselves
        buckets = _bucket_rows(result, hours)

    log.debug("timeline query — hours=%d buckets=%d", hours, len(buckets))
    return buckets
