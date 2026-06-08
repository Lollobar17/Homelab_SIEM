# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# ── Labels ────────────────────────────────────────────────────────────────────
LABEL maintainer="Lorenzo Carta"
LABEL description="HomeLab SIEM — lightweight self-hosted security monitoring"
LABEL version="2.2.0"

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /app

# ── Install dependencies ──────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application code ─────────────────────────────────────────────────────
COPY app.py .
COPY wsgi.py .
COPY simulate_logs.py .
COPY siem/ ./siem/
COPY azure_siem/ ./azure_siem/
COPY templates/ ./templates/

# ── Create runtime directories ────────────────────────────────────────────────
RUN mkdir -p data logs

# ── Expose ports ──────────────────────────────────────────────────────────────
EXPOSE 5000
EXPOSE 5140/udp

# ── Environment variables ─────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV SIEM_DEBUG=0
ENV SIEM_RETENTION_DAYS=30

# ── Entrypoint ────────────────────────────────────────────────────────────────
# Single worker — collectors (syslog UDP, file tailers) run in-process.
# bootstrap_background_services() is invoked from wsgi.py on container start.
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5000", "--timeout", "120", "wsgi:app"]
