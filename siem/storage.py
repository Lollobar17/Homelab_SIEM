"""
storage.py — Event Storage
Persists events and alerts to a local SQLite database.
"""

import json
import sqlite3
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("siem.storage")

_DB_PATH = Path("data/siem.db")
_local = threading.local()   # thread-local connections


def _get_conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _local.conn = conn
        _init_db(conn)
    return _local.conn


def _init_db(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            source    TEXT,
            category  TEXT,
            raw       TEXT,
            fields    TEXT,
            has_alert INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    INTEGER REFERENCES events(id),
            timestamp   TEXT NOT NULL,
            rule_id     TEXT,
            rule_name   TEXT,
            description TEXT,
            severity    TEXT,
            mitre       TEXT,
            source_ip   TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
        CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(timestamp DESC);
    """)
    conn.commit()
    _migrate(conn)


def _migrate(conn: sqlite3.Connection):
    """
    Apply schema migrations for existing databases.
    Safe to run on every startup — skips columns that already exist.
    """
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    # G-03 migration: add source_ip if missing
    if "source_ip" not in existing_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN source_ip TEXT")
        conn.commit()
        logger.info("[DB] Migration applied: added source_ip to alerts table")
    
    if "geo" not in existing_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN geo TEXT")
        conn.commit()
        logger.info("[DB] Migration applied: added geo to alerts table")


# ──────────────────────────────────────────────
#  Write path
# ──────────────────────────────────────────────

def store_event(event: dict) -> int:
    conn = _get_conn()
    alerts = event.get("alerts", [])

    cur = conn.execute(
        """INSERT INTO events (timestamp, source, category, raw, fields, has_alert)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            event.get("timestamp", datetime.now(timezone.utc).isoformat()),
            event.get("source", "unknown"),
            event.get("category", "generic"),
            event.get("raw", ""),
            json.dumps(event.get("fields", {})),
            1 if alerts else 0,
        )
    )
    event_id = cur.lastrowid

    for a in alerts:
        conn.execute(
            """INSERT INTO alerts (event_id, timestamp, rule_id, rule_name, description, severity, mitre, source_ip, geo)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                a.get("timestamp", datetime.now(timezone.utc).isoformat()),
                a.get("rule"),
                a.get("name"),
                a.get("description"),
                a.get("severity"),
                a.get("mitre"),
                a.get("source_ip"),  # G-03 fix
                json.dumps(a.get("geo", {})),  # GeoIP info as JSON string
            )
        )

    conn.commit()
    return event_id


# ──────────────────────────────────────────────
#  Read path
# ──────────────────────────────────────────────

def get_recent_events(limit: int = 200, category: str = None, source: str = None) -> list[dict]:
    conn = _get_conn()
    if category and source:
        rows = conn.execute(
            "SELECT * FROM events WHERE category=? AND lower(source)=lower(?) ORDER BY id DESC LIMIT ?",
            (category, source, limit)
        ).fetchall()
    elif category:
        rows = conn.execute(
            "SELECT * FROM events WHERE category=? ORDER BY id DESC LIMIT ?",
            (category, limit)
        ).fetchall()
    elif source:
        rows = conn.execute(
            "SELECT * FROM events WHERE lower(source)=lower(?) ORDER BY id DESC LIMIT ?",
            (source, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_event(r) for r in rows]


def get_recent_alerts(limit: int = 100, severity: str = None) -> list[dict]:
    conn = _get_conn()
    if severity:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE severity=? ORDER BY id DESC LIMIT ?",
            (severity, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats() -> dict:
    conn = _get_conn()
    total_events  = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts  = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    critical      = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
    high          = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]
    medium        = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='MEDIUM'").fetchone()[0]
    low           = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='LOW'").fetchone()[0]

    # Events per category
    cat_rows = conn.execute(
        "SELECT category, COUNT(*) as cnt FROM events GROUP BY category"
    ).fetchall()
    by_category = {r["category"]: r["cnt"] for r in cat_rows}

    # Events per hour (last 24h)
    hour_rows = conn.execute("""
        SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour, COUNT(*) as cnt
        FROM events
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    by_hour = [{"hour": r["hour"], "count": r["cnt"]} for r in hour_rows]

    # Top source IPs from alerts-related events
    ip_rows = conn.execute("""
        SELECT json_extract(fields, '$.src_ip') as ip, COUNT(*) as cnt
        FROM events
        WHERE json_extract(fields, '$.src_ip') IS NOT NULL
        GROUP BY ip
        ORDER BY cnt DESC
        LIMIT 10
    """).fetchall()
    top_ips = [{"ip": r["ip"], "count": r["cnt"]} for r in ip_rows]

    return {
        "total_events":  total_events,
        "total_alerts":  total_alerts,
        "by_severity":   {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low},
        "by_category":   by_category,
        "events_by_hour": by_hour,
        "top_src_ips":   top_ips,
    }


def _row_to_event(row) -> dict:
    d = dict(row)
    try:
        d["fields"] = json.loads(d.get("fields") or "{}")
    except Exception:
        d["fields"] = {}
    return d


def get_rule_stats() -> list[dict]:
    """
    Return firing statistics for each rule.
    Shows how many times each rule has triggered (for rule effectiveness analysis).
    """
    conn = _get_conn()
    rows = conn.execute("""
        SELECT rule_id, rule_name, severity, COUNT(*) as firing_count
        FROM alerts
        GROUP BY rule_id
        ORDER BY firing_count DESC
        LIMIT 20
    """).fetchall()
    return [
        {
            "rule_id": r["rule_id"],
            "rule_name": r["rule_name"],
            "severity": r["severity"],
            "firing_count": r["firing_count"],
        }
        for r in rows
    ]
