"""
storage.py — Event Storage
Persists events and alerts to SQLite (default, local/dev) or PostgreSQL
(production, enables horizontal scaling across multiple SIEM replicas).

Backend is selected via SIEM_DB_BACKEND env var: "sqlite" (default) or "postgres".
Public function signatures are identical across both backends — callers
(app.py, detector.py) never need to know which one is active.
"""

import json
import os
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("siem.storage")

BACKEND = os.getenv("SIEM_DB_BACKEND", "sqlite").lower()

_DB_PATH = Path(os.getenv("SIEM_DB_PATH", "data/siem.db"))
_local = threading.local()   # thread-local connections
_write_lock = threading.Lock()

# Prune events/alerts older than N days (0 = disabled). Override via env.
RETENTION_DAYS = int(os.getenv("SIEM_RETENTION_DAYS", "30"))

if BACKEND == "postgres":
    import psycopg2
    import psycopg2.extras
    import psycopg2.pool

    _PG_HOST = os.getenv("SIEM_POSTGRES_HOST", "localhost")
    _PG_PORT = int(os.getenv("SIEM_POSTGRES_PORT", "5432"))
    _PG_DB = os.getenv("SIEM_POSTGRES_DB", "siem")
    _PG_USER = os.getenv("SIEM_POSTGRES_USER", "siem")
    _PG_PASSWORD = os.getenv("SIEM_POSTGRES_PASSWORD", "")

    _pg_pool = psycopg2.pool.ThreadedConnectionPool(
        1, 10,
        host=_PG_HOST, port=_PG_PORT, dbname=_PG_DB,
        user=_PG_USER, password=_PG_PASSWORD,
        cursor_factory=psycopg2.extras.RealDictCursor,
    )

    class _PGConnAdapter:
        """
        Thin wrapper so psycopg2 connections support the sqlite3-style
        conn.execute(sql, params) API used throughout this module, instead
        of requiring an explicit cursor at every call site.
        """
        def __init__(self, raw_conn):
            self._conn = raw_conn

        def execute(self, sql, params=()):
            cur = self._conn.cursor()
            cur.execute(sql.replace("?", "%s"), params)
            return cur

        def executescript(self, sql):
            cur = self._conn.cursor()
            cur.execute(sql)
            return cur

        def commit(self):
            self._conn.commit()

        def __getattr__(self, name):
            return getattr(self._conn, name)


def _get_conn():
    if not hasattr(_local, "conn"):
        if BACKEND == "postgres":
            raw = _pg_pool.getconn()
            # Autocommit avoids leaving implicit transactions open after plain
            # SELECTs (psycopg2 defaults to autocommit=False, unlike sqlite3),
            # which would otherwise hold locks and block concurrent DDL
            # (CREATE TABLE/ALTER TABLE) from other threads/pods on startup.
            raw.autocommit = True
            with raw.cursor() as cur:
                cur.execute("SET TIME ZONE 'UTC'")
            conn = _PGConnAdapter(raw)
        else:
            import sqlite3
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


def _ts_expr(column: str) -> str:
    """Normalize ISO-8601 text timestamps for SQLite date functions (SQLite only)."""
    return f"replace(replace({column}, 'T', ' '), 'Z', '')"


# ──────────────────────────────────────────────
#  Schema init
# ──────────────────────────────────────────────

_SQLITE_SCHEMA = """
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
"""

_POSTGRES_SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        id        SERIAL PRIMARY KEY,
        timestamp TIMESTAMPTZ NOT NULL,
        source    TEXT,
        category  TEXT,
        raw       TEXT,
        fields    JSONB,
        has_alert BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS alerts (
        id          SERIAL PRIMARY KEY,
        event_id    INTEGER REFERENCES events(id),
        timestamp   TIMESTAMPTZ NOT NULL,
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
"""


def _init_db(conn):
    if BACKEND == "postgres":
        conn.executescript(_POSTGRES_SCHEMA)
    else:
        conn.executescript(_SQLITE_SCHEMA)
    conn.commit()
    _migrate(conn)


def _migrate(conn):
    """
    Apply schema migrations for existing databases.
    Safe to run on every startup — skips columns that already exist.
    """
    if BACKEND == "postgres":
        # Postgres supports native IF NOT EXISTS on ADD COLUMN — no manual check needed.
        conn.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source_ip TEXT")
        conn.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS geo JSONB")
        conn.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'New'")
        conn.execute("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS analyst_notes TEXT DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        conn.commit()
        return

    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    if "source_ip" not in existing_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN source_ip TEXT")
        conn.commit()
        logger.info("[DB] Migration applied: added source_ip to alerts table")

    if "geo" not in existing_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN geo TEXT")
        conn.commit()
        logger.info("[DB] Migration applied: added geo to alerts table")

    if "status" not in existing_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'New'")
        conn.commit()
        logger.info("[DB] Migration applied: added status to alerts table")
    if "analyst_notes" not in existing_columns:
        conn.execute("ALTER TABLE alerts ADD COLUMN analyst_notes TEXT DEFAULT ''")
        conn.commit()
        logger.info("[DB] Migration applied: added analyst_notes to alerts table")

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
        fields_json = json.dumps(event.get("fields", {}))

        if BACKEND == "postgres":
            cur = conn.execute(
                """INSERT INTO events (timestamp, source, category, raw, fields, has_alert)
                   VALUES (?, ?, ?, ?, ?::jsonb, ?) RETURNING id""",
                (
                    event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    event.get("source", "unknown"),
                    event.get("category", "generic"),
                    event.get("raw", ""),
                    fields_json,
                    bool(alerts),
                )
            )
            event_id = cur.fetchone()["id"]
        else:
            cur = conn.execute(
                """INSERT INTO events (timestamp, source, category, raw, fields, has_alert)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    event.get("source", "unknown"),
                    event.get("category", "generic"),
                    event.get("raw", ""),
                    fields_json,
                    1 if alerts else 0,
                )
            )
            event_id = cur.lastrowid

        try:
            from monitoring.siem_metrics import record_event
            record_event(
                category=event.get('category', 'unknown'),
                source=event.get('source', 'unknown')
            )
        except Exception:
            pass

        for a in alerts:
            geo_json = json.dumps(a.get("geo", {}))
            if BACKEND == "postgres":
                conn.execute(
                    """INSERT INTO alerts
                       (event_id, timestamp, rule_id, rule_name, description,
                        severity, mitre, source_ip, geo, status, analyst_notes)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, 'New', '')""",
                    (
                        event_id,
                        a.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        a.get("rule"),
                        a.get("name"),
                        a.get("description"),
                        a.get("severity"),
                        a.get("mitre"),
                        a.get("source_ip"),
                        geo_json,
                    )
                )
            else:
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
                        geo_json,
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
    if isinstance(d.get("geo"), str):
        try:
            d["geo"] = json.loads(d["geo"]) if d["geo"] else {}
        except Exception:
            d["geo"] = {}
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

    cat_rows = conn.execute(
        "SELECT category, COUNT(*) as cnt FROM events GROUP BY category"
    ).fetchall()
    by_category = {r["category"]: r["cnt"] for r in cat_rows}

    if BACKEND == "postgres":
        hour_rows = conn.execute("""
            SELECT to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD"T"HH24:00:00') as hour,
                   COUNT(*) as cnt
            FROM events
            WHERE timestamp >= now() - interval '24 hours'
            GROUP BY hour
            ORDER BY hour
        """).fetchall()
    else:
        ts = _ts_expr("timestamp")
        hour_rows = conn.execute(f"""
            SELECT strftime('%Y-%m-%dT%H:00:00', {ts}) as hour, COUNT(*) as cnt
            FROM events
            WHERE julianday({ts}) >= julianday('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        """).fetchall()
    by_hour = [{"hour": r["hour"], "count": r["cnt"]} for r in hour_rows]

    if BACKEND == "postgres":
        ip_rows = conn.execute("""
            SELECT fields->>'src_ip' as ip, COUNT(*) as cnt
            FROM events
            WHERE fields->>'src_ip' IS NOT NULL
            GROUP BY ip
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()
    else:
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
    Extended stats for /api/v1/stats — aggregation done in the database so
    the browser only receives compact JSON for Chart.js rendering.
    """
    conn = _get_conn()
    base = get_stats()

    if BACKEND == "postgres":
        alert_hour_rows = conn.execute("""
            SELECT to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD"T"HH24:00:00') as hour,
                   COUNT(*) as cnt
            FROM alerts
            WHERE timestamp >= now() - interval '24 hours'
            GROUP BY hour
            ORDER BY hour
        """).fetchall()
    else:
        ts = _ts_expr("timestamp")
        alert_hour_rows = conn.execute(f"""
            SELECT strftime('%Y-%m-%dT%H:00:00', {ts}) as hour, COUNT(*) as cnt
            FROM alerts
            WHERE julianday({ts}) >= julianday('now', '-24 hours')
            GROUP BY hour
            ORDER BY hour
        """).fetchall()
    alerts_by_hour = [{"hour": r["hour"], "count": r["cnt"]} for r in alert_hour_rows]

    mitre_rows = conn.execute("""
        SELECT mitre, COUNT(*) as cnt
        FROM alerts
        WHERE mitre IS NOT NULL AND mitre != ''
        GROUP BY mitre
        ORDER BY cnt DESC
        LIMIT 12
    """).fetchall()
    by_mitre = {r["mitre"]: r["cnt"] for r in mitre_rows}

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
    if isinstance(d.get("fields"), str):
        try:
            d["fields"] = json.loads(d["fields"] or "{}")
        except Exception:
            d["fields"] = {}
    elif d.get("fields") is None:
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
        GROUP BY rule_id, rule_name, severity
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

    with _write_lock:
        conn = _get_conn()
        if BACKEND == "postgres":
            alerts_deleted = conn.execute(
                "DELETE FROM alerts WHERE timestamp < now() - (?::text || ' days')::interval",
                (str(days),),
            ).rowcount
            events_deleted = conn.execute(
                "DELETE FROM events WHERE timestamp < now() - (?::text || ' days')::interval",
                (str(days),),
            ).rowcount
        else:
            ts_events = _ts_expr("timestamp")
            ts_alerts = _ts_expr("timestamp")
            cutoff = f"-{days} days"
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
            "[DB] Pruned %d events, %d alerts (retention=%d days, backend=%s)",
            events_deleted, alerts_deleted, days, BACKEND,
        )
    return {
        "deleted_events": events_deleted,
        "deleted_alerts": alerts_deleted,
        "retention_days": days,
    }
