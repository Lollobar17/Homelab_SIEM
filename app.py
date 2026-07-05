"""
app.py — HomeLab SIEM  ·  Flask Web Application
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, jsonify, render_template, request

from siem.collector import start_collectors
from siem.detector import get_rules, analyze_event
from siem.ingress import normalize_event, validate_batch
from siem.storage import (
    TRIAGE_STATUSES,
    RETENTION_DAYS,
    get_recent_alerts,
    get_recent_events,
    get_stats,
    get_rule_stats,
    get_v1_stats,
    prune_old_data,
    store_event,
    update_alert_triage,
)

_MAX_RAW_INGEST = 16384
_PRE_PARSED_REQUIRED = frozenset({"timestamp", "source", "category", "fields", "raw"})


def _bounded_limit(raw, default: int = 200, maximum: int = 1000) -> int:
    try:
        return max(1, min(int(raw), maximum))
    except (TypeError, ValueError):
        return default

# ──────────────────────────────────────────────
#  Logging
# ──────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

# G-05/G-06: Write Flask access log to file for SIEM collector 
os.makedirs("logs", exist_ok=True)
flask_log_handler = logging.FileHandler("logs/flask_access.log")
flask_log_handler.setLevel(logging.INFO)
logging.getLogger("werkzeug").addHandler(flask_log_handler)
logger = logging.getLogger("siem.app")

# ──────────────────────────────────────────────
#  Config (override via config.json)
# ──────────────────────────────────────────────

DEFAULT_CONFIG = {
    "syslog_enabled": True,
    "syslog_host": "0.0.0.0",
    "syslog_port": 5140,
    "watch_files": [
        {"path": "/var/log/auth.log",    "name": "auth"},
        {"path": "/var/log/syslog",      "name": "syslog"},
        {"path": "/var/log/apache2/access.log", "name": "apache"},
        {"path": "/var/log/nginx/access.log",   "name": "nginx"},
        {"path": "logs/flask_access.log", "name": "flask"},
        {"path": "suricata-logs/eve.json", "name": "suricata"}
    ],
    "web_host": "0.0.0.0",
    "web_port": 5000,
    "discord_webhook": "",
}

_config_path = Path("config.json")
if _config_path.exists():
    with open(_config_path) as f:
        user_cfg = json.load(f)
    CONFIG = {**DEFAULT_CONFIG, **user_cfg}
else:
    CONFIG = DEFAULT_CONFIG

# Auto-export Discord webhook to env so detector.py picks it up
if CONFIG.get("discord_webhook"):
    os.environ["DISCORD_WEBHOOK_URL"] = CONFIG["discord_webhook"]
    logger.info("[Config] Discord webhook loaded from config.json")


# ──────────────────────────────────────────────
#  Flask app
# ──────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")

# Prometheus metrics
from monitoring.siem_metrics import setup_metrics, metrics_bp, record_event, record_ingest
setup_metrics(app)
app.register_blueprint(metrics_bp)
# Reject oversized ingress payloads early — protects constrained hosts.
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024  # 512 KB

_boot_lock = threading.Lock()
_booted = False


def bootstrap_background_services():
    """Start collectors and optional DB prune once per process."""
    global _booted
    with _boot_lock:
        if _booted:
            return
        _booted = True
        if RETENTION_DAYS > 0:
            result = prune_old_data()
            if result.get("deleted_events") or result.get("deleted_alerts"):
                logger.info("[DB] Startup prune: %s", result)
        start_collectors(CONFIG)
        logger.info("[Bootstrap] Collectors started")


# ── Dashboard ────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ── Rule Editor ───────────────────────────────

@app.route("/rules")
def rules_editor():
    return render_template("rules.html")


# ── REST API ─────────────────────────────────

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/v1/stats")
def api_v1_stats():
    """Aggregated metrics for client-side Chart.js dashboards."""
    return jsonify(get_v1_stats())


@app.route("/api/events")
def api_events():
    limit    = _bounded_limit(request.args.get("limit", 200))
    category = request.args.get("category")
    source   = request.args.get("source")
    return jsonify(get_recent_events(limit=limit, category=category, source=source))


@app.route("/api/alerts")
def api_alerts():
    limit    = _bounded_limit(request.args.get("limit", 100), default=100)
    severity = request.args.get("severity")
    status   = request.args.get("status")
    return jsonify(get_recent_alerts(limit=limit, severity=severity, status=status))


@app.route("/api/v1/alerts/<int:alert_id>/triage", methods=["PATCH", "POST"])
def api_v1_alert_triage(alert_id: int):
    """
    Update incident triage fields for a single alert.
    Body: {"status": "In Progress", "analyst_notes": "..."}
    """
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    notes = body.get("analyst_notes")

    if status is None and notes is None:
        return jsonify({"error": "provide 'status' and/or 'analyst_notes'"}), 400
    if status is not None and status not in TRIAGE_STATUSES:
        return jsonify({
            "error": f"invalid status; allowed: {sorted(TRIAGE_STATUSES)}",
        }), 400

    if not update_alert_triage(alert_id, status=status, analyst_notes=notes):
        return jsonify({"error": "alert not found or no changes"}), 404

    return jsonify({"ok": True, "alert_id": alert_id})


@app.route("/api/rules")
def api_rules():
    return jsonify(get_rules())


@app.route("/api/rules/stats")
def api_rules_stats():
    """Return detection rule firing statistics."""
    return jsonify(get_rule_stats())


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """
    Manual log ingestion endpoint.
    POST JSON: {"raw": "<log line>", "source": "myapp"}
    Supports "_pre_parsed" field for pre-structured events (e.g. azure_collector.py)
    """
    body = request.get_json(silent=True) or {}
    raw  = str(body.get("raw", ""))[:_MAX_RAW_INGEST]
    if not raw.strip():
        return jsonify({"error": "missing 'raw' field"}), 400

    source = str(body.get("source", "api"))[:128]

    # Use pre-parsed event if available (legacy collectors)
    pre_parsed = body.get("_pre_parsed")
    if pre_parsed and isinstance(pre_parsed, dict) and pre_parsed.get("category"):
        if not _PRE_PARSED_REQUIRED.issubset(pre_parsed.keys()):
            return jsonify({"error": "invalid _pre_parsed schema"}), 400
        event = pre_parsed
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    else:
        from siem.collector import parse_log_line
        event = parse_log_line(raw, source=source)

    alerts = analyze_event(event)
    event["alerts"] = alerts
    record_event(category=event.get("category", "unknown"), source=event.get("source", source))
    record_ingest(status="success")
    eid = store_event(event)
    return jsonify({"event_id": eid, "alerts": len(alerts)}), 201


@app.route("/api/v1/ingress", methods=["POST"])
def api_v1_ingress():
    """
    Structured log ingestion endpoint (v1).

    Single event:
        {"message": "...", "source_ip": "1.2.3.4", "event_type": "auth.login", ...}

    Batch (max 100):
        {"events": [{...}, {...}]}

    Optional: "detect": false skips the rule engine for pure log archival.
    """
    body = request.get_json(silent=True)
    if body is None:
        return jsonify({"error": "invalid or missing JSON body"}), 400

    items, errors = validate_batch(body)
    if errors and not items:
        return jsonify({"error": "validation failed", "details": errors}), 400

    run_detect = body.get("detect", True) if isinstance(body, dict) else True
    default_source = (body.get("source") if isinstance(body, dict) else None) or "ingress"

    results = []
    for i, raw_item in enumerate(items):
        event = normalize_event(raw_item, default_source=default_source)
        if run_detect:
            alerts = analyze_event(event)
            event["alerts"] = alerts
        else:
            event["alerts"] = []
        record_event(category=event.get("category", "unknown"), source=event.get("source", default_source))
        eid = store_event(event)
        results.append({"index": i, "event_id": eid, "alerts": len(event["alerts"])})

    resp = {"ingested": len(results), "results": results}
    if errors:
        resp["validation_errors"] = errors
    record_ingest(status="success" if not errors else "partial_error")
    return jsonify(resp), 201


# ── Health ───────────────────────────────────

@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "time": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
    })


# ── Vulnerable endpoint (intentional — lab demonstration only) ───────────

@app.route("/vulnerable")
def vulnerable_search():
    """
    Intentionally vulnerable to SQL injection.
    For HomeLab SIEM demonstration purposes only.
    """
    import sqlite3

    query = request.args.get("q", "1")

    # Deliberately unsafe — no parameterization (intentional for lab)
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, email TEXT)")
    conn.execute("INSERT INTO users VALUES (1, 'admin', 'admin@lab.local')")
    conn.execute("INSERT INTO users VALUES (2, 'user1', 'user1@lab.local')")

    try:
        cursor = conn.execute(f"SELECT * FROM users WHERE id = {query}")
        rows = cursor.fetchall()
        return jsonify({"results": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


# ──────────────────────────────────────────────
#  Entrypoint
# ──────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("Starting HomeLab SIEM …")
    bootstrap_background_services()
    app.run(
        host=CONFIG["web_host"],
        port=CONFIG["web_port"],
        debug=os.getenv("SIEM_DEBUG", "0") == "1",
        use_reloader=False,
    )
