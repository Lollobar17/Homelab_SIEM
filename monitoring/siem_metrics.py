# ──────────────────────────────────────────────────────────────────────────────
#  monitoring/siem_metrics.py
#  Prometheus metrics module for HomeLab SIEM
#
#  Add to requirements.txt:  prometheus-client>=0.20.0
#
#  Add to app.py:
#    from monitoring.siem_metrics import setup_metrics, metrics_bp
#    setup_metrics(app)
#    app.register_blueprint(metrics_bp)
# ──────────────────────────────────────────────────────────────────────────────

from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from flask import Blueprint, Response

# ── Metrics definitions ───────────────────────────────────────────────────────

# Events ingested total
events_total = Counter(
    'siem_events_total',
    'Total number of events ingested',
    ['category', 'source']
)

# Alerts generated total
alerts_total = Counter(
    'siem_alerts_total',
    'Total number of alerts generated',
    ['rule_id', 'severity']
)

# Active alerts currently in DB
active_alerts = Gauge(
    'siem_active_alerts',
    'Number of active alerts (status=New)',
    ['severity']
)

# Detection rules loaded
rules_loaded = Gauge(
    'siem_rules_loaded_total',
    'Total number of detection rules loaded'
)

# HTTP request duration
http_request_duration = Histogram(
    'siem_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint', 'status_code'],
    buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0]
)

# API ingest rate
ingest_requests = Counter(
    'siem_ingest_requests_total',
    'Total number of ingest API requests',
    ['status']
)

# ── Blueprint for /metrics endpoint ──────────────────────────────────────────

metrics_bp = Blueprint('metrics', __name__)

@metrics_bp.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

# ── Setup function ────────────────────────────────────────────────────────────

def setup_metrics(app):
    """Initialize metrics with current state from DB."""
    from siem import storage
    from siem.detector import RULES

    # Set rules loaded gauge
    rules_loaded.set(len(RULES))

    # Middleware to track HTTP request duration
    import time
    from flask import request, g

    @app.before_request
    def before_request():
        g.start_time = time.time()

    @app.after_request
    def after_request(response):
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            endpoint = request.endpoint or 'unknown'
            http_request_duration.labels(
                method=request.method,
                endpoint=endpoint,
                status_code=response.status_code
            ).observe(duration)
        return response

    app.logger.info(f"Prometheus metrics enabled — {len(RULES)} rules loaded")
