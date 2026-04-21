"""
app.py — HomeLab SIEM  ·  Flask Web Application
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from siem.collector import start_collectors
from siem.detector import get_rules, analyze_event
from siem.storage import (
    get_recent_alerts,
    get_recent_events,
    get_stats,
    store_event,
)

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
        {"path": "logs/flask_access.log", "name": "flask"}
    ],
    "web_host": "0.0.0.0",
    "web_port": 5000,
}

_config_path = Path("config.json")
if _config_path.exists():
    with open(_config_path) as f:
        user_cfg = json.load(f)
    CONFIG = {**DEFAULT_CONFIG, **user_cfg}
else:
    CONFIG = DEFAULT_CONFIG

# ──────────────────────────────────────────────
#  Flask app
# ──────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")


# ── Dashboard ────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# ── REST API ─────────────────────────────────

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/events")
def api_events():
    limit    = int(request.args.get("limit", 200))
    category = request.args.get("category")
    return jsonify(get_recent_events(limit=limit, category=category))


@app.route("/api/alerts")
def api_alerts():
    limit    = int(request.args.get("limit", 100))
    severity = request.args.get("severity")
    return jsonify(get_recent_alerts(limit=limit, severity=severity))


@app.route("/api/rules")
def api_rules():
    return jsonify(get_rules())


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """
    Manual log ingestion endpoint.
    POST JSON: {"raw": "<log line>", "source": "myapp"}
    """
    body = request.get_json(silent=True) or {}
    raw  = body.get("raw", "")
    if not raw:
        return jsonify({"error": "missing 'raw' field"}), 400

    from siem.collector import parse_log_line
    event  = parse_log_line(raw, source=body.get("source", "api")) or {"fields": {}}
    alerts = analyze_event(event)
    event["alerts"] = alerts
    eid = store_event(event)
    return jsonify({"event_id": eid, "alerts": len(alerts)}), 201


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
    start_collectors(CONFIG)
    app.run(
        host=CONFIG["web_host"],
        port=CONFIG["web_port"],
        debug=os.getenv("SIEM_DEBUG", "0") == "1",
        use_reloader=False,
    )
