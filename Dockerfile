# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Install ansede-static from local source (no wheel build needed)
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e . --no-build-isolation

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

# Production entry point — env vars injected by Render dashboard
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
