"""
azure_activity_collector.py — Azure Activity Log Collector
Phase 2: Azure Activity Log (Blob Storage) -> HomeLab SIEM /api/ingest

Format: NDJSON — one JSON object per line (not a JSON array)

Dependencies:
    pip install azure-storage-blob requests

Configuration (config.json):
    AZURE_STORAGE_CONNECTION_STRING
    SIEM_INGEST_URL  (default: http://localhost:5000/api/v1/ingress)
"""

import os
import io
import gzip
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError

from azure_siem.ingest_client import send_events

# ── Config ───────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("azure_activity_collector")

_cfg_path = Path("config.json")
_file_cfg = {}
if _cfg_path.exists():
    with open(_cfg_path) as f:
        _file_cfg = json.load(f)

def _cfg(key, default=None):
    return _file_cfg.get(key) or os.environ.get(key) or default

CONN_STR        = _cfg("AZURE_STORAGE_CONNECTION_STRING", "")
CONTAINER_NAME  = "insights-activity-logs"
SIEM_INGEST_URL = _cfg("SIEM_INGEST_URL", "http://localhost:5000/api/v1/ingress")
POLL_INTERVAL   = int(_cfg("AZURE_POLL_INTERVAL", 60))
STATE_FILE      = Path(".azure_activity_collector_state.json")

# ── State ────────────────────────────────────
def _load_state():
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text()).get("processed_blobs", []))
        except Exception:
            pass
    return set()

def _save_state(processed):
    STATE_FILE.write_text(json.dumps({"processed_blobs": list(processed)}))

# ── Parser ───────────────────────────────────

_RELEVANT_CATEGORIES = {"Administrative", "Security", "Policy"}

_SECURITY_OPERATIONS = {
    "microsoft.network/networksecuritygroups/securityrules/write":  "NSG_RULE_MODIFIED",
    "microsoft.network/networksecuritygroups/securityrules/delete": "NSG_RULE_DELETED",
    "microsoft.network/networksecuritygroups/write":                "NSG_MODIFIED",
    "microsoft.compute/virtualmachines/deallocate/action":          "VM_STOPPED",
    "microsoft.compute/virtualmachines/start/action":               "VM_STARTED",
    "microsoft.compute/virtualmachines/delete":                     "VM_DELETED",
    "microsoft.storage/storageaccounts/delete":                     "STORAGE_DELETED",
    "microsoft.storage/storageaccounts/listkeys/action":            "STORAGE_KEYS_LISTED",
    "microsoft.authorization/roleassignments/write":                "ROLE_ASSIGNED",
    "microsoft.authorization/roleassignments/delete":               "ROLE_REMOVED",
    "microsoft.insights/diagnosticsettings/delete":                 "DIAGNOSTIC_DELETED",
    "microsoft.insights/diagnosticsettings/write":                  "DIAGNOSTIC_MODIFIED",
}


def _parse_activity_blob(content):
    """
    Parses Azure Activity Log NDJSON blob.
    Each line is a separate JSON object.
    """
    events = []

    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        event = _parse_activity_record(record)
        if event:
            events.append(event)

    return events


def _parse_activity_record(record):
    cat_value  = str(record.get("category", "")).strip()
    if cat_value not in _RELEVANT_CATEGORIES:
        return None

    op_value   = str(record.get("operationName", "")).lower().strip()
    op_label   = record.get("operationName", op_value)
    status_val = str(record.get("resultType", "")).upper().strip()

    # Accept Start, Succeeded, Failed
    if status_val not in ("START", "STARTED", "SUCCESS", "SUCCEEDED", "FAILED", "FAILURE"):
        return None

    timestamp  = record.get("time", datetime.now(timezone.utc).isoformat())
    resource   = str(record.get("resourceId", "")).split("/")[-1]

    # Extract caller from identity or direct field
    identity   = record.get("identity", {})
    if isinstance(identity, dict):
        claims = identity.get("claims", {})
        caller = claims.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                            record.get("callerIpAddress", "unknown"))
    else:
        caller = record.get("callerIpAddress", "unknown")

    event_type = _SECURITY_OPERATIONS.get(op_value, "ACTIVITY_LOG")

    raw = (
        f"ACTIVITY_LOG category={cat_value} operation={op_label} "
        f"resource={resource} caller={caller} status={status_val} "
        f"type={event_type}"
    )

    return {
        "timestamp": timestamp,
        "source":    "azure:activity_log",
        "raw":       raw,
        "category":  "cloud",
        "fields": {
            "event_type":  event_type,
            "operation":   op_value,
            "op_label":    op_label,
            "resource":    resource,
            "caller":      caller,
            "status":      status_val,
            "az_category": cat_value,
        }
    }

# ── Blob reader ──────────────────────────────
def _read_blob(blob_client):
    try:
        data = blob_client.download_blob().readall()
        if data[:2] == b'\x1f\x8b':
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                return gz.read().decode("utf-8", errors="replace")
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        logger.error(f"[Blob] Read error: {e}")
        return ""

# ── Polling ──────────────────────────────────
def _poll_once(service_client, processed):
    sent = 0
    new_blobs = []

    try:
        container_client = service_client.get_container_client(CONTAINER_NAME)
        for blob in container_client.list_blobs():
            if blob.name not in processed:
                new_blobs.append(blob.name)
    except AzureError as e:
        if "ContainerNotFound" in str(e):
            logger.debug("[Collector] Activity log container not yet created.")
        else:
            logger.error(f"[Azure] Blob listing error: {e}")
        return 0

    if not new_blobs:
        logger.debug("[Collector] No new activity log blobs.")
        return 0

    logger.info(f"[Collector] {len(new_blobs)} new blob(s) to process.")

    for blob_name in new_blobs:
        logger.info(f"[Collector] Processing: {blob_name}")
        try:
            blob_client = service_client.get_blob_client(
                container=CONTAINER_NAME, blob=blob_name
            )
            content = _read_blob(blob_client)
            if not content:
                processed.add(blob_name)
                continue

            events = _parse_activity_blob(content)
            logger.info(f"[Collector] Parsed {len(events)} activity events.")

            batch_sent, batch_failed = send_events(events, SIEM_INGEST_URL)
            sent += batch_sent

            if batch_failed == 0:
                processed.add(blob_name)
                _save_state(processed)
                logger.info(f"[Collector] Done: {blob_name} ({batch_sent} events)")
            else:
                logger.error(
                    f"[Collector] {batch_failed}/{len(events)} events failed for "
                    f"{blob_name} — will retry on next poll"
                )

        except Exception as e:
            logger.error(f"[Collector] Error processing {blob_name}: {e}")

    return sent


def run():
    if not CONN_STR:
        logger.error("AZURE_STORAGE_CONNECTION_STRING not configured.")
        return

    logger.info("=" * 55)
    logger.info("  Azure Activity Log Collector — HomeLab SIEM")
    logger.info("=" * 55)
    logger.info(f"  Container : {CONTAINER_NAME}")
    logger.info(f"  SIEM      : {SIEM_INGEST_URL}")
    logger.info(f"  Polling   : every {POLL_INTERVAL}s")
    logger.info("=" * 55)

    try:
        service_client = BlobServiceClient.from_connection_string(CONN_STR)
        list(service_client.list_containers())
        logger.info("[Azure] Connection OK.")
    except Exception as e:
        logger.error(f"[Azure] Connection failed: {e}")
        return

    processed = _load_state()
    logger.info(f"[State] {len(processed)} blobs already processed.")

    while True:
        try:
            count = _poll_once(service_client, processed)
            if count:
                logger.info(f"[Collector] {count} activity events sent to SIEM.")
        except Exception as e:
            logger.error(f"[Collector] Polling error: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
