"""
ingress.py — REST API log ingestion (v1)

Validates and normalizes structured JSON log events for passive, low-CPU
insertion into SQLite.  Designed for remote agents and homelab integrations
that already emit structured telemetry.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("siem.ingress")

# Field length caps — keeps SQLite rows bounded on constrained hardware.
_MAX_STR = 4096
_MAX_RAW = 16384

# Severity values accepted in ingress payloads (stored in fields, not alerts).
_VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})

# Loose ISO-8601 check (avoid dateutil dependency).
_ISO_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
)

# Private / loopback ranges — cheap prefix check, no ipaddress module overhead.
_PRIVATE_IP_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                        "172.29.", "172.30.", "172.31.", "::1", "fe80:")


def _clip(value: Any, limit: int = _MAX_STR) -> str:
    """Coerce to str and truncate — prevents oversized payloads."""
    if value is None:
        return ""
    s = str(value)
    return s[:limit] if len(s) > limit else s


def _normalize_ip(value: Any) -> str:
    """Basic IP validation: alphanumeric, dots, colons only."""
    ip = _clip(value, 45)
    if not ip:
        return ""
    if not re.match(r"^[\d.a-fA-F:]+$", ip):
        return ""
    return ip


def _normalize_timestamp(value: Any) -> str:
    """Return ISO-8601 UTC timestamp; fall back to now on bad input."""
    if not value:
        return datetime.now(timezone.utc).isoformat()
    ts = _clip(value, 64)
    if _ISO_TS_RE.match(ts):
        # Normalise space separator to T for consistent storage.
        return ts.replace(" ", "T", 1)
    try:
        # Accept Unix epoch (int/float/str).
        epoch = float(ts)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        pass
    return datetime.now(timezone.utc).isoformat()


def _infer_category(event_type: str) -> str:
    """Map event_type hint to existing SIEM category labels."""
    et = event_type.lower()
    if any(k in et for k in ("auth", "login", "ssh", "sudo")):
        return "auth"
    if any(k in et for k in ("http", "web", "apache", "nginx")):
        return "web"
    if any(k in et for k in ("kernel", "dmesg")):
        return "kernel"
    if any(k in et for k in ("dns", "flow", "net", "suricata", "firewall")):
        return "suricata" if "suricata" in et else "syslog"
    if any(k in et for k in ("azure", "cloud", "aws", "gcp")):
        return "cloud"
    if "caldera" in et or "purple" in et:
        return "purple_team"
    return "generic"


def normalize_event(payload: dict, default_source: str = "ingress") -> dict:
    """
    Transform a v1 ingress JSON object into the internal event dict
    consumed by analyze_event() and store_event().

    Expected keys (all optional except message OR event_type):
        timestamp, source_ip, destination_ip, event_type, severity, message, source
    """
    message = _clip(payload.get("message"), _MAX_RAW)
    event_type = _clip(payload.get("event_type"), 128)
    source = _clip(payload.get("source") or default_source, 128)

    src_ip = _normalize_ip(payload.get("source_ip"))
    dst_ip = _normalize_ip(payload.get("destination_ip"))
    severity = _clip(payload.get("severity"), 16).upper()
    if severity and severity not in _VALID_SEVERITIES:
        severity = "INFO"

    timestamp = _normalize_timestamp(payload.get("timestamp"))
    category = _clip(payload.get("category"), 64) or _infer_category(event_type)

    # Build fields blob — preserve any extra keys the sender included.
    fields: dict[str, Any] = dict(payload.get("fields") or {})
    if src_ip:
        fields["src_ip"] = src_ip
    if dst_ip:
        fields["dst_ip"] = dst_ip
    if event_type:
        fields["event_type"] = event_type
    if severity:
        fields["severity"] = severity
    if message:
        fields["message"] = message

    # Raw line: message preferred, else compact JSON summary for search.
    raw = message or f"{event_type} src={src_ip} dst={dst_ip}".strip()

    return {
        "timestamp": timestamp,
        "source": source,
        "category": category,
        "raw": raw,
        "fields": fields,
    }


def validate_payload(payload: dict) -> str | None:
    """
    Return an error string if the payload is invalid, else None.
    At least one of message or event_type must be present.
    """
    if not isinstance(payload, dict):
        return "payload must be a JSON object"
    if not payload.get("message") and not payload.get("event_type"):
        return "missing required field: 'message' or 'event_type'"
    return None


def validate_batch(body: dict) -> tuple[list[dict], list[dict]]:
    """
    Parse request body into a list of normalised-ready payloads.
    Supports single-event body or {"events": [...]} batch (max 100).
    Returns (items, errors).
    """
    if not isinstance(body, dict):
        return [], [{"index": None, "error": "body must be a JSON object"}]

    if "events" in body:
        events = body["events"]
        if not isinstance(events, list):
            return [], [{"index": None, "error": "'events' must be an array"}]
        if len(events) > 100:
            return [], [{"index": None, "error": "batch limit is 100 events"}]
        items, errors = [], []
        for i, ev in enumerate(events):
            err = validate_payload(ev)
            if err:
                errors.append({"index": i, "error": err})
            else:
                items.append(ev)
        return items, errors

    err = validate_payload(body)
    if err:
        return [], [{"index": 0, "error": err}]
    return [body], []
