FROM python:3.12-slim
WORKDIR /app

# Install webapp Python dependencies
COPY webapp/requirements.txt ./webapp/
RUN pip install --no-cache-dir -r webapp/requirements.txt

# Copy the scanner source (used as subprocess via PYTHONPATH)
COPY src/ ./src/

# Copy webapp templates and code
COPY webapp/ ./webapp/

# Allow the CLI subprocess to find guardmarly
ENV PYTHONPATH="/app/src:${PYTHONPATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DB_PATH=/data/licenses.db

RUN mkdir -p /data /tmp/scans
VOLUME ["/data", "/tmp"]

EXPOSE 8765

CMD ["gunicorn", "webapp.app:app", "--bind", "0.0.0.0:8765", "--workers", "2", "--threads", "4", "--worker-class", "gthread", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-"]
