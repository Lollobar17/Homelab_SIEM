#!/usr/bin/env python3
"""
caldera_collector.py — Lightweight MITRE Caldera → HomeLab SIEM bridge

Resource-conscious defaults:
  - Idle: one GET /api/v2/operations per poll cycle
  - Running ops polled first; recently finished ops get one tail fetch
  - Bounded 500-ID dedup cache, batch v1 ingress, exponential backoff on errors
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from azure_siem.ingest_client import send_events  # noqa: E402
from siem.caldera_parser import event_id, parse_caldera_record  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("caldera_collector")

_cfg_path = ROOT / "config.json"
_file_cfg: dict = {}
if _cfg_path.exists():
    with open(_cfg_path, encoding="utf-8") as f:
        _file_cfg = json.load(f)


def _cfg(key: str, default=None):
    return _file_cfg.get(key) or os.environ.get(key) or default


CALDERA_URL = _cfg("CALDERA_URL", "http://127.0.0.1:8888").rstrip("/")
API_KEY = _cfg("CALDERA_API_KEY", "")
POLL_INTERVAL = int(_cfg("CALDERA_POLL_INTERVAL", 120))
MAX_OPS = int(_cfg("CALDERA_MAX_OPS", 2))
MAX_EVENTS = int(_cfg("CALDERA_MAX_EVENTS", 25))
SEEN_MAX = int(_cfg("CALDERA_SEEN_MAX", 500))
FINISHED_GRACE = int(_cfg("CALDERA_FINISHED_GRACE", 600))
RUN_DETECT = str(_cfg("CALDERA_DETECT", "true")).lower() not in ("0", "false", "no")
SIEM_INGEST_URL = _cfg("SIEM_INGEST_URL", "http://localhost:5000/api/v1/ingress")
STATE_FILE = Path(_cfg("CALDERA_STATE_FILE", str(ROOT / ".caldera_collector_state.json")))

_SESSION = requests.Session()
_SESSION.headers.update({"KEY": API_KEY})
_backoff = POLL_INTERVAL


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seen_ids": [], "stats": {"polls": 0, "ingested": 0}}


def _save_state(state: dict) -> None:
    state["seen_ids"] = state.get("seen_ids", [])[-SEEN_MAX:]
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(STATE_FILE)


def _get(path: str):
    resp = _SESSION.get(f"{CALDERA_URL}{path}", timeout=10)
    resp.raise_for_status()
    return resp.json()


def _parse_finish_ts(op: dict) -> float | None:
    raw = op.get("finish") or op.get("end") or op.get("updated") or ""
    if not raw:
        return None
    try:
        if isinstance(raw, (int, float)):
            return float(raw)
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError, OSError):
        return None


def _select_operations(operations: list) -> list:
    """Prioritize running ops; fill spare slots with recently finished ops."""
    if not isinstance(operations, list):
        return []

    running = [o for o in operations if o.get("state") == "running"]
    now = time.time()
    finished = []
    for o in operations:
        if o.get("state") not in ("finished", "complete", "run_finished"):
            continue
        fts = _parse_finish_ts(o)
        if fts is not None and now - fts <= FINISHED_GRACE:
            finished.append((fts, o))

    finished.sort(key=lambda x: x[0], reverse=True)
    selected = running[:MAX_OPS]
    spare = MAX_OPS - len(selected)
    if spare > 0:
        selected.extend(o for _, o in finished[:spare])
    return selected[:MAX_OPS]


def _poll_once(state: dict) -> tuple[int, dict]:
    seen: list[str] = state.get("seen_ids", [])
    seen_set = set(seen)
    pending: list[tuple[str, dict]] = []

    try:
        operations = _get("/api/v2/operations")
        global _backoff
        _backoff = POLL_INTERVAL
    except Exception as exc:
        logger.error("[Caldera] operations list failed: %s", exc)
        _backoff = min(_backoff * 2, 600)
        return 0, state

    targets = _select_operations(operations)
    if not targets:
        logger.debug("[Caldera] No active/recent operations — idle.")
        return 0, state

    for op in targets:
        op_id = op.get("id", "")
        if not op_id:
            continue
        try:
            events = _get(f"/api/v2/operations/{op_id}/events")
        except Exception as exc:
            logger.warning("[Caldera] events for op %s failed: %s", op_id, exc)
            continue

        if not isinstance(events, list):
            continue

        for record in events[-MAX_EVENTS:]:
            eid = event_id(record, op_id)
            if eid in seen_set:
                continue
            parsed = parse_caldera_record(record, op)
            if not parsed:
                continue
            pending.append((eid, parsed))
            seen_set.add(eid)

    if not pending:
        return 0, state

    sent, failed = send_events(
        [ev for _, ev in pending],
        SIEM_INGEST_URL,
        detect=RUN_DETECT,
        timeout=30,
    )
    if failed:
        logger.error("[Caldera] %d/%d failed ingest — will retry", failed, len(pending))
        return 0, state

    for eid, _ in pending:
        seen.append(eid)
    seen = seen[-SEEN_MAX:]
    stats = state.get("stats", {})
    stats["polls"] = stats.get("polls", 0) + 1
    stats["ingested"] = stats.get("ingested", 0) + sent
    stats["last_ingest"] = datetime.now(timezone.utc).isoformat()
    state["seen_ids"] = seen
    state["stats"] = stats
    logger.info("[Caldera] Ingested %d event(s) (total %d)", sent, stats["ingested"])
    return sent, state


def run() -> None:
    if not API_KEY:
        logger.error("CALDERA_API_KEY not configured (config.json or env).")
        return

    logger.info("=" * 55)
    logger.info("  Caldera Collector — HomeLab SIEM (lightweight)")
    logger.info("=" * 55)
    logger.info("  Caldera   : %s", CALDERA_URL)
    logger.info("  SIEM      : %s", SIEM_INGEST_URL)
    logger.info("  Poll      : %ds | ops≤%d | events/op≤%d | detect=%s",
                POLL_INTERVAL, MAX_OPS, MAX_EVENTS, RUN_DETECT)
    logger.info("=" * 55)

    try:
        _get("/api/v2/operations")
        logger.info("[Caldera] API connection OK.")
    except Exception as exc:
        logger.error("[Caldera] Connection failed: %s", exc)
        return

    state = _load_state()
    logger.info("[State] %d dedup ID(s), %d total ingested.",
                len(state.get("seen_ids", [])), state.get("stats", {}).get("ingested", 0))

    while True:
        try:
            sent, state = _poll_once(state)
            if sent:
                _save_state(state)
        except Exception as exc:
            logger.error("[Caldera] Poll error: %s", exc)
        time.sleep(_backoff)


if __name__ == "__main__":
    run()
