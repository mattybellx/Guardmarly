FROM python:3.12-slim
WORKDIR /app

# Install webapp Python dependencies
COPY webapp/requirements.txt ./webapp/
RUN pip install --no-cache-dir -r webapp/requirements.txt

# Copy the scanner source (used via direct Python import by app.py)
COPY src/ ./src/

# Copy webapp templates, static, and code
COPY webapp/ ./webapp/

ENV PYTHONPATH="/app/src:${PYTHONPATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN mkdir -p /data /tmp/scans
VOLUME ["/data", "/tmp"]

EXPOSE 8765

CMD ["gunicorn", "webapp.app:app", "--bind", "0.0.0.0:8765", "--workers", "2", "--threads", "4", "--worker-class", "gthread", "--timeout", "60", "--access-logfile", "-", "--error-logfile", "-"]
