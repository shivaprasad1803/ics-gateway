"""
main.py  —  PhysicsGuard FastAPI application entry point
Layer 7  |  PhysicsGuard ICS Security Gateway
Week 7 deliverable: REST API wiring ForensicLogger and ValidationEngine
"""
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from web_ui.routers import health, metrics, rules, stats, violations

log = logging.getLogger(__name__)

_DASHBOARD = Path(__file__).parent / "dashboard.html"


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """Start-up and shut-down logic for the PhysicsGuard API.

    If ``app.state`` already contains ``flogger`` and ``engine`` (injected by
    unit tests) the real database / YAML files are not touched.
    """
    _already_injected = (
        hasattr(application.state, "flogger")
        and hasattr(application.state, "engine")
    )

    if not _already_injected:
        from src.forensic_logger import get_logger
        from src.validation_engine import load_rules_from_yaml, build_water_tank_engine

        application.state.start_time = time.monotonic()
        application.state.flogger = get_logger("logs/physicsguard.db")
        
        base_engine = build_water_tank_engine()
        application.state.engine = load_rules_from_yaml("config/rules.yaml", engine=base_engine)
        log.info("PhysicsGuard Layer 7 started — ForensicLogger and ValidationEngine ready")
    else:
        if not hasattr(application.state, "start_time"):
            application.state.start_time = time.monotonic()
        log.debug("PhysicsGuard Layer 7 started with pre-injected test state")

    yield

    if hasattr(application.state, "flogger") and not _already_injected:
        application.state.flogger.stop()
        log.info("PhysicsGuard Layer 7 shutdown — ForensicLogger stopped")


app = FastAPI(
    title="PhysicsGuard",
    version="1.0.0",
    description=(
        "Consequence-Aware Semantic Validation gateway — "
        "read-only monitoring REST API (Layer 7)."
    ),
    lifespan=lifespan,
)

app.include_router(health.router,     prefix="/api")
app.include_router(stats.router,      prefix="/api")
app.include_router(violations.router, prefix="/api")
app.include_router(rules.router,      prefix="/api")
app.include_router(metrics.router,    prefix="/api")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the PhysicsGuard monitoring dashboard."""
    return FileResponse(_DASHBOARD, media_type="text/html")
