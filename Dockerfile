# Dockerfile — PhysicsGuard ICS Security Gateway
# ================================================
# Layout (confirmed from find ~/ics-security-gateway):
#   src/          ← Layer 1-6 modules + src/rules/
#   web_ui/       ← Layer 7 FastAPI app + routers/
#   config/       ← rules.yaml

FROM python:3.12-slim

# ── System dependencies ────────────────────────────────────────────────────────
# gcc            : compiles C extensions required by pymodbus
# curl           : used by api healthcheck
# netcat-openbsd : used by modbus healthcheck (nc -z localhost 5020)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        curl \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application source ─────────────────────────────────────────────────────────
COPY src/     /app/src/
COPY web_ui/  /app/web_ui/
COPY config/  /app/config/

# ── Runtime directories ────────────────────────────────────────────────────────
RUN mkdir -p /app/logs

# ── PYTHONPATH ────────────────────────────────────────────────────────────────
# TWO paths are required:
#
#   /app      → resolves "from src.rules import ..."
#               resolves "from src.water_tank import ..."
#               resolves "from web_ui.routers import ..."
#
#   /app/src  → resolves "from rules import ..."  ← this was the crash
#               resolves "from rules.base_rule import ..."
#
# Locally the project uses "pip install -e ." which puts src/ directly on
# sys.path via the editable install. Docker does not run pip install -e .,
# so we replicate the same effect by adding /app/src explicitly.
ENV PYTHONPATH=/app:/app/src \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 5020 4840 8000

# Default command — api service uses this.
# modbus and opcua services override via command: in docker-compose.yml.
CMD ["uvicorn", "web_ui.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--log-level", "info"]
