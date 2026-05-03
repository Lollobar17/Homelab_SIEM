# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.12-slim

# ── Labels ────────────────────────────────────────────────────────────────────
LABEL maintainer="Lorenzo Carta"
LABEL description="HomeLab SIEM — lightweight self-hosted security monitoring"
LABEL version="1.3.0"

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /app

# ── Install dependencies ──────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Copy application code ─────────────────────────────────────────────────────
COPY app.py .
COPY simulate_logs.py .
COPY siem/ ./siem/
COPY templates/ ./templates/

# ── Create runtime directories ────────────────────────────────────────────────
RUN mkdir -p data logs

# ── Expose ports ──────────────────────────────────────────────────────────────
# Flask web UI
EXPOSE 5000
# UDP syslog receiver
EXPOSE 5140/udp

# ── Environment variables ─────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV SIEM_DEBUG=0

# ── Entrypoint ────────────────────────────────────────────────────────────────
CMD ["python", "app.py"]
