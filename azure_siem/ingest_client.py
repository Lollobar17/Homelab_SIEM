"""
ingest_client.py — Shared batch ingest helper for Azure/Sentinel collectors.

Posts structured events to POST /api/v1/ingress in batches of up to 100.
Falls back to legacy /api/ingest when v1 URL is not configured.
"""

import logging
from typing import Any

import requests

logger = logging.getLogger("azure_siem.ingest")

_SESSION = requests.Session()
_BATCH_SIZE = 100


def _event_to_ingress_payload(event: dict) -> dict:
    fields = event.get("fields") or {}
    return {
        "message": event.get("raw", ""),
        "source": event.get("source", "azure"),
        "source_ip": fields.get("src_ip"),
        "destination_ip": fields.get("dst_ip"),
        "event_type": fields.get("event_type", "azure.event"),
        "timestamp": event.get("timestamp"),
        "category": event.get("category", "cloud"),
        "fields": fields,
    }


def _legacy_ingest_url(url: str) -> str:
    if url.rstrip("/").endswith("/api/v1/ingress"):
        return url.replace("/api/v1/ingress", "/api/ingest")
    return url


def send_events(
    events: list[dict],
    ingest_url: str,
    *,
    detect: bool = True,
    timeout: int = 30,
) -> tuple[int, int]:
    """
    Send events to the SIEM. Returns (sent_count, failed_count).
  Uses batch v1 ingress when URL points at /api/v1/ingress (default).
    """
    if not events:
        return 0, 0

    use_v1 = ingest_url.rstrip("/").endswith("/api/v1/ingress")
    sent = 0
    failed = 0

    if use_v1:
        for i in range(0, len(events), _BATCH_SIZE):
            chunk = events[i : i + _BATCH_SIZE]
            payload: dict[str, Any] = {
                "events": [_event_to_ingress_payload(ev) for ev in chunk],
                "detect": detect,
            }
            try:
                resp = _SESSION.post(ingest_url, json=payload, timeout=timeout)
                if resp.status_code == 201:
                    sent += len(chunk)
                else:
                    failed += len(chunk)
                    logger.error(
                        "[Ingest] Batch rejected HTTP %s: %s",
                        resp.status_code,
                        resp.text[:200],
                    )
            except Exception as exc:
                failed += len(chunk)
                logger.error("[Ingest] Batch error: %s", exc)
        return sent, failed

    legacy_url = _legacy_ingest_url(ingest_url)
    for event in events:
        try:
            resp = _SESSION.post(
                legacy_url,
                json={
                    "raw": event["raw"],
                    "source": event["source"],
                    "_pre_parsed": event,
                },
                timeout=5,
            )
            if resp.status_code == 201:
                sent += 1
            else:
                failed += 1
        except Exception as exc:
            failed += 1
            logger.error("[Ingest] Error: %s", exc)
    return sent, failed
