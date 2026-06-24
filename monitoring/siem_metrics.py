import time
import logging
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
from flask import Blueprint, Response, request, g

logger = logging.getLogger(__name__)

events_total = Counter(
    'siem_events_total',
    'Total number of events ingested',
    ['category', 'source']
)

alerts_total = Counter(
    'siem_alerts_total',
    'Total number of alerts generated',
    ['rule_id', 'severity']
)

active_alerts = Gauge(
    'siem_active_alerts',
    'Number of active alerts by severity',
    ['severity']
)

rules_loaded = Gauge(
    'siem_rules_loaded_total',
    'Total number of detection rules loaded'
)

http_request_duration = Histogram(
    'siem_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint', 'status_code'],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

ingest_requests = Counter(
    'siem_ingest_requests_total',
    'Total number of ingest API requests',
    ['status']
)

def record_event(category: str = 'unknown', source: str = 'unknown'):
    try:
        events_total.labels(
            category=str(category) if category else 'unknown',
            source=str(source) if source else 'unknown'
        ).inc()
    except Exception as e:
        logger.debug(f"Metrics record_event error: {e}")

def record_alert(rule_id: str = 'unknown', severity: str = 'unknown'):
    try:
        alerts_total.labels(
            rule_id=str(rule_id) if rule_id else 'unknown',
            severity=str(severity) if severity else 'unknown'
        ).inc()
    except Exception as e:
        logger.debug(f"Metrics record_alert error: {e}")

def record_ingest(status: str = 'success'):
    try:
        ingest_requests.labels(status=status).inc()
    except Exception as e:
        logger.debug(f"Metrics record_ingest error: {e}")

def refresh_active_alerts():
    try:
        from siem.storage import get_recent_alerts
        alerts = get_recent_alerts(limit=1000)
        severity_counts = {}
        for alert in alerts:
            sev = alert.get('severity', 'unknown')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for severity, count in severity_counts.items():
            active_alerts.labels(severity=severity).set(count)
    except Exception as e:
        logger.debug(f"Metrics refresh_active_alerts error: {e}")

metrics_bp = Blueprint('metrics', __name__)

@metrics_bp.route('/metrics')
def metrics():
    refresh_active_alerts()
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

def setup_metrics(app):
    from siem.detector import RULES
    rules_loaded.set(len(RULES))

    @app.before_request
    def _before():
        g.start_time = time.time()

    @app.after_request
    def _after(response):
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            endpoint = request.endpoint or 'unknown'
            try:
                http_request_duration.labels(
                    method=request.method,
                    endpoint=endpoint,
                    status_code=str(response.status_code)
                ).observe(duration)
            except Exception:
                pass
        return response

    logger.info(f"Prometheus metrics enabled — {len(RULES)} rules loaded, /metrics active")
