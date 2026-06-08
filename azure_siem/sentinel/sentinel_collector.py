"""
sentinel_collector.py — Microsoft Sentinel Collector
Phase 3: Sentinel SecurityAlert + SecurityIncident -> HomeLab SIEM /api/ingest

Queries Azure Log Analytics workspace via REST API using KQL.
Retrieves Sentinel-generated alerts and incidents and forwards
them to the SIEM /api/ingest endpoint.

Dependencies:
    pip install requests msal

Configuration (config.json):
    SENTINEL_TENANT_ID       — Azure tenant ID
    SENTINEL_CLIENT_ID       — App registration client ID
    SENTINEL_CLIENT_SECRET   — App registration client secret
    SENTINEL_WORKSPACE_ID    — Log Analytics workspace ID
    SIEM_INGEST_URL          — http://localhost:5000/api/v1/ingress
"""

import os
import json
import time
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
import msal

from azure_siem.ingest_client import send_events

# ── Config ───────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("sentinel_collector")

_cfg_path = Path("config.json")
_file_cfg = {}
if _cfg_path.exists():
    with open(_cfg_path) as f:
        _file_cfg = json.load(f)

def _cfg(key, default=None):
    return _file_cfg.get(key) or os.environ.get(key) or default

TENANT_ID       = _cfg("SENTINEL_TENANT_ID", "")
CLIENT_ID       = _cfg("SENTINEL_CLIENT_ID", "")
CLIENT_SECRET   = _cfg("SENTINEL_CLIENT_SECRET", "")
WORKSPACE_ID    = _cfg("SENTINEL_WORKSPACE_ID", "")
SIEM_INGEST_URL = _cfg("SIEM_INGEST_URL", "http://localhost:5000/api/v1/ingress")
POLL_INTERVAL   = int(_cfg("SENTINEL_POLL_INTERVAL", 120))
STATE_FILE      = Path(".sentinel_collector_state.json")

# ── State ────────────────────────────────────
def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    # Default: look back 24 hours on first run
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    return {"last_alert_time": since, "last_incident_time": since}

def _save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state))

# ── Authentication ────────────────────────────
_token_cache = {}

def _get_token() -> str:
    """Get OAuth2 token via MSAL client credentials flow."""
    now = time.time()
    if _token_cache.get("token") and _token_cache.get("expires_at", 0) > now + 60:
        return _token_cache["token"]

    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(
        scopes=["https://api.loganalytics.io/.default"]
    )

    if "access_token" not in result:
        raise Exception(f"Auth failed: {result.get('error_description', result)}")

    _token_cache["token"] = result["access_token"]
    _token_cache["expires_at"] = now + result.get("expires_in", 3600)
    return _token_cache["token"]

# ── KQL Query ─────────────────────────────────
def _query_workspace(kql: str) -> list[dict]:
    """Execute a KQL query against the Log Analytics workspace."""
    token = _get_token()
    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    body = {"query": kql}

    resp = requests.post(url, headers=headers, json=body, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    tables = data.get("tables", [])
    if not tables:
        return []

    table = tables[0]
    columns = [c["name"] for c in table.get("columns", [])]
    rows = table.get("rows", [])

    return [dict(zip(columns, row)) for row in rows]

# ── Parsers ───────────────────────────────────

_SEVERITY_MAP = {
    "High":          "HIGH",
    "Medium":        "MEDIUM",
    "Low":           "LOW",
    "Critical":      "CRITICAL",
    "Informational": "LOW",
}


def _parse_security_alert(record: dict) -> dict:
    """Convert a Sentinel SecurityAlert record to SIEM event format."""
    severity = _SEVERITY_MAP.get(record.get("AlertSeverity", ""), "MEDIUM")
    alert_name = record.get("AlertName", "Unknown Alert")
    vendor = record.get("VendorName", "Sentinel")
    tactics = record.get("Tactics", "")
    entities = record.get("Entities", "")
    timestamp = record.get("TimeGenerated", datetime.now(timezone.utc).isoformat())

    # Extract src_ip from entities if available
    src_ip = ""
    try:
        ents = json.loads(entities) if isinstance(entities, str) else entities
        for e in (ents if isinstance(ents, list) else []):
            if e.get("Type") == "ip":
                src_ip = e.get("Address", "")
                break
    except Exception:
        pass

    raw = (
        f"SENTINEL_ALERT severity={severity} name={alert_name} "
        f"vendor={vendor} tactics={tactics}"
        + (f" src_ip={src_ip}" if src_ip else "")
    )

    return {
        "timestamp": timestamp,
        "source":    "azure:sentinel",
        "raw":       raw,
        "category":  "cloud",
        "fields": {
            "event_type":  "SENTINEL_ALERT",
            "alert_name":  alert_name,
            "severity":    severity,
            "vendor":      vendor,
            "tactics":     tactics,
            "src_ip":      src_ip,
            "description": record.get("Description", ""),
            "alert_id":    record.get("SystemAlertId", ""),
        }
    }


def _parse_security_incident(record: dict) -> dict:
    """Convert a Sentinel SecurityIncident record to SIEM event format."""
    severity = _SEVERITY_MAP.get(record.get("Severity", ""), "MEDIUM")
    title = record.get("Title", "Unknown Incident")
    status = record.get("Status", "")
    timestamp = record.get("TimeGenerated", datetime.now(timezone.utc).isoformat())
    incident_number = record.get("IncidentNumber", "")

    raw = (
        f"SENTINEL_INCIDENT severity={severity} title={title} "
        f"status={status} incident_number={incident_number}"
    )

    return {
        "timestamp": timestamp,
        "source":    "azure:sentinel",
        "raw":       raw,
        "category":  "cloud",
        "fields": {
            "event_type":       "SENTINEL_INCIDENT",
            "title":            title,
            "severity":         severity,
            "status":           status,
            "incident_number":  str(incident_number),
            "description":      record.get("Description", ""),
        }
    }

# ── Polling ───────────────────────────────────
def _poll_once(state: dict) -> tuple[int, dict]:
    sent = 0

    # ── SecurityAlert ──────────────────────────
    try:
        since = state["last_alert_time"]
        kql = f"""
SecurityAlert
| where TimeGenerated > datetime('{since}')
| order by TimeGenerated asc
| limit 100
"""
        alerts = _query_workspace(kql)
        logger.info(f"[Sentinel] {len(alerts)} new SecurityAlert(s)")

        events = [_parse_security_alert(r) for r in alerts]
        events = [e for e in events if e]
        if events:
            batch_sent, batch_failed = send_events(events, SIEM_INGEST_URL)
            sent += batch_sent
            if batch_failed == 0:
                for record in alerts:
                    ts = record.get("TimeGenerated", "")
                    if ts and ts > state["last_alert_time"]:
                        state["last_alert_time"] = ts
            else:
                logger.error(
                    "[Sentinel] %d SecurityAlert(s) failed ingest — cursor not advanced",
                    batch_failed,
                )

    except Exception as e:
        logger.error(f"[Sentinel] SecurityAlert query error: {e}")

    # ── SecurityIncident ───────────────────────
    try:
        since = state["last_incident_time"]
        kql = f"""
SecurityIncident
| where TimeGenerated > datetime('{since}')
| order by TimeGenerated asc
| limit 100
"""
        incidents = _query_workspace(kql)
        logger.info(f"[Sentinel] {len(incidents)} new SecurityIncident(s)")

        events = [_parse_security_incident(r) for r in incidents]
        events = [e for e in events if e]
        if events:
            batch_sent, batch_failed = send_events(events, SIEM_INGEST_URL)
            sent += batch_sent
            if batch_failed == 0:
                for record in incidents:
                    ts = record.get("TimeGenerated", "")
                    if ts and ts > state["last_incident_time"]:
                        state["last_incident_time"] = ts
            else:
                logger.error(
                    "[Sentinel] %d SecurityIncident(s) failed ingest — cursor not advanced",
                    batch_failed,
                )

    except Exception as e:
        logger.error(f"[Sentinel] SecurityIncident query error: {e}")

    return sent, state


def run():
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET, WORKSPACE_ID]):
        logger.error(
            "Missing Sentinel configuration. Required in config.json:\n"
            "  SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID,\n"
            "  SENTINEL_CLIENT_SECRET, SENTINEL_WORKSPACE_ID"
        )
        return

    logger.info("=" * 55)
    logger.info("  Microsoft Sentinel Collector — HomeLab SIEM")
    logger.info("=" * 55)
    logger.info(f"  Workspace : {WORKSPACE_ID}")
    logger.info(f"  SIEM      : {SIEM_INGEST_URL}")
    logger.info(f"  Polling   : every {POLL_INTERVAL}s")
    logger.info("=" * 55)

    # Verify auth
    try:
        _get_token()
        logger.info("[Auth] Token acquired successfully.")
    except Exception as e:
        logger.error(f"[Auth] Failed: {e}")
        return

    state = _load_state()
    logger.info(f"[State] Polling alerts since: {state['last_alert_time']}")

    while True:
        try:
            count, state = _poll_once(state)
            _save_state(state)
            if count:
                logger.info(f"[Collector] {count} Sentinel events sent to SIEM.")
        except Exception as e:
            logger.error(f"[Collector] Polling error: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
