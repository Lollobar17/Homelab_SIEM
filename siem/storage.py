"""
storage.py — Event Storage
Persists events and alerts to a local SQLite database.
"""

import json
import os
import sqlite3
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("siem.storage")

_DB_PATH = Path("data/siem.db")
_local = threading.local()   # thread-local connections
_write_lock = threading.Lock()

# Prune events/alerts older than N days (0 = disabled). Override via env.
RETENTION_DAYS = int(os.getenv("SIEM_RETENTION_DAYS", "30"))


def _ts_expr(column: str) -> str:
    """Normalize ISO-8601 text timestamps for SQLite date functions."""
    return f"replace(replace({column}, 'T', ' '), 'Z', '')"


def _get_conn() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(_DB_PATH), check_same_thread=False, timeout=30.0,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=30000")
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

    # Incident triage workflow
    if "status" not in existing_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'New'")
        conn.commit()
        logger.info("[DB] Migration applied: added status to alerts table")
    if "analyst_notes" not in existing_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN analyst_notes TEXT DEFAULT ''")
        conn.commit()
        logger.info("[DB] Migration applied: added analyst_notes to alerts table")

    # Index for triage filters (created once, IF NOT EXISTS is cheap).
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)"
    )
    conn.commit()


# ──────────────────────────────────────────────
#  Write path
# ──────────────────────────────────────────────

def store_event(event: dict) -> int:
    with _write_lock:
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
                """INSERT INTO alerts
                   (event_id, timestamp, rule_id, rule_name, description,
                    severity, mitre, source_ip, geo, status, analyst_notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'New', '')""",
                (
                    event_id,
                    a.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    a.get("rule"),
                    a.get("name"),
                    a.get("description"),
                    a.get("severity"),
                    a.get("mitre"),
                    a.get("source_ip"),
                    json.dumps(a.get("geo", {})),
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


# Valid triage statuses for incident case management.
TRIAGE_STATUSES = frozenset({
    "New", "In Progress", "Resolved", "False Positive",
})


def get_recent_alerts(
    limit: int = 100,
    severity: str = None,
    status: str = None,
) -> list[dict]:
    conn = _get_conn()
    clauses, params = [], []
    if severity:
        clauses.append("severity=?")
        params.append(severity)
    if status:
        clauses.append("status=?")
        params.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?",
        params,
    ).fetchall()
    return [_row_to_alert(r) for r in rows]


def _row_to_alert(row) -> dict:
    d = dict(row)
    d.setdefault("status", "New")
    d.setdefault("analyst_notes", "")
    return d


def update_alert_triage(
    alert_id: int,
    status: str = None,
    analyst_notes: str = None,
) -> bool:
    """
    Update triage fields on a single alert.  Returns False if alert not found
    or status value is invalid.
    """
    if status is not None and status not in TRIAGE_STATUSES:
        return False

    conn = _get_conn()
    sets, params = [], []
    if status is not None:
        sets.append("status=?")
        params.append(status)
    if analyst_notes is not None:
        # Cap notes length to keep rows small on embedded hardware.
        sets.append("analyst_notes=?")
        params.append(str(analyst_notes)[:8192])
    if not sets:
        return False

    params.append(alert_id)
    cur = conn.execute(
        f"UPDATE alerts SET {', '.join(sets)} WHERE id=?",
        params,
    )
    conn.commit()
    return cur.rowcount > 0


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
    ts = _ts_expr("timestamp")
    hour_rows = conn.execute(f"""
        SELECT strftime('%Y-%m-%dT%H:00:00', {ts}) as hour, COUNT(*) as cnt
        FROM events
        WHERE julianday({ts}) >= julianday('now', '-24 hours')
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

    purple_team = conn.execute(
        "SELECT COUNT(*) FROM events WHERE category='purple_team'"
    ).fetchone()[0]

    return {
        "total_events":  total_events,
        "total_alerts":  total_alerts,
        "by_severity":   {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low},
        "by_category":   by_category,
        "events_by_hour": by_hour,
        "top_src_ips":   top_ips,
        "purple_team_events": purple_team,
    }


def get_v1_stats() -> dict:
    """
    Extended stats for /api/v1/stats — aggregation done in SQLite so the
    browser only receives compact JSON for Chart.js rendering.
    """
    conn = _get_conn()
    base = get_stats()

    # Alert volume per hour (last 24h) — mirrors events_by_hour query.
    ts = _ts_expr("timestamp")
    alert_hour_rows = conn.execute(f"""
        SELECT strftime('%Y-%m-%dT%H:00:00', {ts}) as hour, COUNT(*) as cnt
        FROM alerts
        WHERE julianday({ts}) >= julianday('now', '-24 hours')
        GROUP BY hour
        ORDER BY hour
    """).fetchall()
    alerts_by_hour = [{"hour": r["hour"], "count": r["cnt"]} for r in alert_hour_rows]

    # MITRE ATT&CK tactic distribution (non-null mitre IDs only).
    mitre_rows = conn.execute("""
        SELECT mitre, COUNT(*) as cnt
        FROM alerts
        WHERE mitre IS NOT NULL AND mitre != ''
        GROUP BY mitre
        ORDER BY cnt DESC
        LIMIT 12
    """).fetchall()
    by_mitre = {r["mitre"]: r["cnt"] for r in mitre_rows}

    # Triage status breakdown for open-incident KPIs.
    triage_rows = conn.execute("""
        SELECT COALESCE(status, 'New') as status, COUNT(*) as cnt
        FROM alerts
        GROUP BY status
    """).fetchall()
    by_triage_status = {r["status"]: r["cnt"] for r in triage_rows}

    return {
        **base,
        "alerts_by_hour": alerts_by_hour,
        "by_mitre": by_mitre,
        "by_triage_status": by_triage_status,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "api_version": "v1",
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


def prune_old_data(retention_days: int = None) -> dict:
    """
    Delete events and alerts older than retention_days.
    Returns counts of deleted rows. Set SIEM_RETENTION_DAYS=0 to disable.
    """
    days = RETENTION_DAYS if retention_days is None else retention_days
    if days <= 0:
        return {"deleted_events": 0, "deleted_alerts": 0, "skipped": True}

    ts_events = _ts_expr("timestamp")
    ts_alerts = _ts_expr("timestamp")
    cutoff = f"-{days} days"

    with _write_lock:
        conn = _get_conn()
        alerts_deleted = conn.execute(
            f"""DELETE FROM alerts
                WHERE julianday({ts_alerts}) < julianday('now', ?)""",
            (cutoff,),
        ).rowcount
        events_deleted = conn.execute(
            f"""DELETE FROM events
                WHERE julianday({ts_events}) < julianday('now', ?)""",
            (cutoff,),
        ).rowcount
        conn.commit()

    if events_deleted or alerts_deleted:
        logger.info(
            "[DB] Pruned %d events, %d alerts (retention=%d days)",
            events_deleted, alerts_deleted, days,
        )
    return {
        "deleted_events": events_deleted,
        "deleted_alerts": alerts_deleted,
        "retention_days": days,
    }
