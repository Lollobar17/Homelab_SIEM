FROM python:3.14-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip --quiet && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.14-slim AS runtime

RUN groupadd -r siem && useradd -r -g siem -d /app -s /sbin/nologin siem

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

COPY app.py simulate_logs.py requirements.txt ./
COPY siem/ ./siem/
COPY azure_siem/ ./azure_siem/
COPY monitoring/ ./monitoring/
COPY templates/ ./templates/

RUN mkdir -p /app/data && chown -R siem:siem /app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_ENV=production \
    SIEM_PORT=5000 \
    SIEM_DB_PATH=/app/data/siem.db

USER siem

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" || exit 1

CMD ["python", "app.py"]
