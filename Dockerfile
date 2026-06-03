# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir build && python -m build --wheel

# ═══════════════════════════════════════════════════════════════════════
FROM python:3.12-slim

WORKDIR /app

# Install ansede-static (the CLI the studio backend calls as a subprocess)
COPY --from=builder /build/dist/*.whl .
RUN pip install --no-cache-dir *.whl && rm -f *.whl

# Install webapp dependencies
COPY webapp/requirements.txt ./webapp/
RUN pip install --no-cache-dir -r webapp/requirements.txt

# Copy webapp (templates, static, Python modules)
COPY webapp/ ./webapp/

# Create persistent volume mount points
RUN mkdir -p /data /tmp/scans
VOLUME ["/data", "/tmp"]

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/data/licenses.db

EXPOSE 8765

# Production entry point — env vars (SECRET_KEY, STRIPE_SECRET, etc.)
# are injected by Render dashboard, NOT from .env files.
CMD ["gunicorn", "webapp.app:app", \
     "--bind", "0.0.0.0:8765", \
     "--workers", "2", \
     "--threads", "4", \
     "--worker-class", "gthread", \
     "--timeout", "60", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
