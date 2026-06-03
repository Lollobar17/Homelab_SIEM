"""
azure_collector.py — Azure VNet Flow Logs Collector (flowLogVersion 4)
Phase 1: Azure Blob Storage -> HomeLab SIEM /api/ingest

Format: flowRecords -> flows -> flowGroups -> flowTuples
Tuple:  timestamp,src_ip,dst_ip,src_port,dst_port,proto,direction,action,state,
        packets_in,bytes_in,packets_out,bytes_out

Action values: D=Deny, E=End(Accept), B=Begin(Accept)

Dependencies:
    pip install azure-storage-blob requests

Configuration (config.json):
    AZURE_STORAGE_CONNECTION_STRING
    AZURE_STORAGE_CONTAINER  (default: insights-logs-flowlogflowevent)
    SIEM_INGEST_URL          (default: http://localhost:5000/api/ingest)
"""

import os
import io
import gzip
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

import requests
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import AzureError

# ── Config ───────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("azure_collector")

_cfg_path = Path("config.json")
_file_cfg = {}
if _cfg_path.exists():
    with open(_cfg_path) as f:
        _file_cfg = json.load(f)

def _cfg(key, default=None):
    return _file_cfg.get(key) or os.environ.get(key) or default

CONN_STR        = _cfg("AZURE_STORAGE_CONNECTION_STRING", "")
CONTAINER_NAME  = _cfg("AZURE_STORAGE_CONTAINER", "insights-logs-flowlogflowevent")
SIEM_INGEST_URL = _cfg("SIEM_INGEST_URL", "http://localhost:5000/api/ingest")
POLL_INTERVAL   = int(_cfg("AZURE_POLL_INTERVAL", 60))
STATE_FILE      = Path(_cfg("AZURE_STATE_FILE", ".azure_collector_state.json"))

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
_PROTO_MAP = {"6": "TCP", "17": "UDP", "1": "ICMP"}
_DIR_MAP   = {"I": "INBOUND", "O": "OUTBOUND"}

def _parse_flow_blob(content):
    """
    Parses Azure VNet Flow Log v4 JSON blob.
    Structure: records -> flowRecords -> flows -> flowGroups -> flowTuples
    """
    events = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        logger.error(f"[Parser] Invalid JSON: {e}")
        return events

    for record in data.get("records", []):
        record_time = record.get("time", datetime.now(timezone.utc).isoformat())
        flow_records = record.get("flowRecords", {})

        for flow in flow_records.get("flows", []):
            acl_id = flow.get("aclID", "")
            # Extract NSG name from aclID if it's a full resource ID
            if "/" in acl_id:
                nsg_name = acl_id.split("/")[-1]
            else:
                nsg_name = "PlatformRule" if acl_id == "00000000-0000-0000-0000-000000000000" else acl_id

            for flow_group in flow.get("flowGroups", []):
                rule = flow_group.get("rule", "unknown-rule")

                for tuple_str in flow_group.get("flowTuples", []):
                    event = _parse_tuple(tuple_str, record_time, nsg_name, rule)
                    if event:
                        events.append(event)

    return events


def _parse_tuple(tuple_str, timestamp, nsg, rule):
    """
    Parses a v4 flow tuple:
    timestamp,src_ip,dst_ip,src_port,dst_port,proto,direction,action,state,
    packets_in,bytes_in,packets_out,bytes_out
    """
    parts = tuple_str.split(",")
    if len(parts) < 8:
        return None

    try:
        ts = datetime.fromtimestamp(int(parts[0]) / 1000 if int(parts[0]) > 9999999999 else int(parts[0]),
                                     tz=timezone.utc).isoformat()
    except (ValueError, IndexError):
        ts = timestamp

    src_ip    = parts[1]
    dst_ip    = parts[2]
    src_port  = _safe_int(parts[3])
    dst_port  = _safe_int(parts[4])
    protocol  = _PROTO_MAP.get(parts[5], parts[5])
    direction = _DIR_MAP.get(parts[6].upper(), parts[6])

    # Action: D=Deny/REJECT, E=End(established)=ACCEPT, B=Begin=ACCEPT
    raw_action = parts[7].upper()
    action = "REJECT" if raw_action == "D" else "ACCEPT"

    # Optional fields (v4)
    packets_in  = _safe_int(parts[9])  if len(parts) > 9  else 0
    bytes_in    = _safe_int(parts[10]) if len(parts) > 10 else 0
    packets_out = _safe_int(parts[11]) if len(parts) > 11 else 0
    bytes_out   = _safe_int(parts[12]) if len(parts) > 12 else 0
    total_bytes = bytes_in + bytes_out

    raw = (
        f"FLOW_LOG action={action} src={src_ip}:{src_port} "
        f"dst={dst_ip}:{dst_port} proto={protocol} "
        f"direction={direction} nsg={nsg} rule={rule} "
        f"bytes={total_bytes}"
    )

    return {
        "timestamp": ts,
        "source":    "azure:nsg_flow_logs",
        "raw":       raw,
        "category":  "cloud",
        "fields": {
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "src_port":  src_port,
            "dst_port":  dst_port,
            "protocol":  protocol,
            "action":    action,
            "direction": direction,
            "nsg":       nsg,
            "rule":      rule,
            "bytes":     total_bytes,
            "bytes_in":  bytes_in,
            "bytes_out": bytes_out,
        }
    }


def _safe_int(val):
    try:
        return int(val)
    except (ValueError, TypeError):
        return 0

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

# ── Ingest ───────────────────────────────────
_SESSION = requests.Session()

def _send_to_siem(event):
    try:
        resp = _SESSION.post(
            SIEM_INGEST_URL,
            json={"raw": event["raw"], "source": event["source"], "_pre_parsed": event},
            timeout=5,
        )
        return resp.status_code == 201
    except Exception as e:
        logger.error(f"[Ingest] Error: {e}")
        return False

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
        logger.error(f"[Azure] Blob listing error: {e}")
        return 0

    if not new_blobs:
        logger.debug("[Collector] No new blobs.")
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

            events = _parse_flow_blob(content)
            logger.info(f"[Collector] Parsed {len(events)} events.")

            for event in events:
                if _send_to_siem(event):
                    sent += 1

            processed.add(blob_name)
            _save_state(processed)
            logger.info(f"[Collector] Done: {blob_name} ({sent} events sent so far)")

        except Exception as e:
            logger.error(f"[Collector] Error processing {blob_name}: {e}")

    return sent


def run():
    if not CONN_STR:
        logger.error("AZURE_STORAGE_CONNECTION_STRING not configured.")
        return

    logger.info("=" * 55)
    logger.info("  Azure Flow Logs Collector — HomeLab SIEM")
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
                logger.info(f"[Collector] {count} total events sent to SIEM.")
        except Exception as e:
            logger.error(f"[Collector] Polling error: {e}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    run()
