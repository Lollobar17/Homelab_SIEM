"""
notifier.py — Alert Notifications
Sends SIEM alerts to Discord via webhook.
Supports severity filtering and rich embed formatting.
"""

import json
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger("siem.notifier")

# ──────────────────────────────────────────────
#  Severity color map for Discord embeds
# ──────────────────────────────────────────────

SEVERITY_COLORS = {
    "CRITICAL": 0xFF0000,  # Red
    "HIGH":     0xFF6600,  # Orange
    "MEDIUM":   0xFFAA00,  # Yellow
    "LOW":      0x00AA00,  # Green
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


# ──────────────────────────────────────────────
#  Main notification function
# ──────────────────────────────────────────────

def send_alert(alert: dict, webhook_url: str, min_severity: str = "HIGH") -> bool:
    """
    Send an alert to Discord via webhook.

    Parameters:
        alert       — alert dict from detector.py
        webhook_url — Discord webhook URL from config
        min_severity — minimum severity to notify (LOW/MEDIUM/HIGH/CRITICAL)

    Returns True on success, False on failure.
    """
    if not webhook_url:
        return False

    severity = alert.get("severity", "LOW")
    if not _should_notify(severity, min_severity):
        return False

    payload = _build_payload(alert)

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=5
        )
        if response.status_code == 204:
            logger.info(f"[Discord] Alert sent: {alert.get('rule')} — {severity}")
            return True
        else:
            logger.warning(f"[Discord] Unexpected status: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"[Discord] Failed to send alert: {e}")
        return False


def _should_notify(severity: str, min_severity: str) -> bool:
    """Return True if severity meets the minimum threshold."""
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    try:
        return order.index(severity) >= order.index(min_severity)
    except ValueError:
        return False


def _build_payload(alert: dict) -> dict:
    """Build a Discord webhook payload with rich embed formatting."""
    severity  = alert.get("severity", "LOW")
    color     = SEVERITY_COLORS.get(severity, 0x888888)
    emoji     = SEVERITY_EMOJI.get(severity, "⚪")
    source_ip = alert.get("source_ip") or "Unknown"
    geo       = alert.get("geo") or {}

    # Parse geo if stored as JSON string
    if isinstance(geo, str):
        try:
            geo = json.loads(geo)
        except Exception:
            geo = {}

    # Build location string
    location_parts = [
        geo.get("city", ""),
        geo.get("region", ""),
        geo.get("country", "")
    ]
    location = ", ".join(p for p in location_parts if p) or "Unknown"
    isp = geo.get("isp", "Unknown")

    fields = [
        {"name": "Rule", "value": f"`{alert.get('rule', 'N/A')}`", "inline": True},
        {"name": "Severity", "value": f"{emoji} {severity}", "inline": True},
        {"name": "MITRE", "value": f"`{alert.get('mitre') or 'N/A'}`", "inline": True},
        {"name": "Source IP", "value": f"`{source_ip}`", "inline": True},
        {"name": "Location", "value": location, "inline": True},
        {"name": "ISP", "value": isp, "inline": True},
    ]

    return {
        "embeds": [{
            "title": f"{emoji} SIEM Alert — {alert.get('name', 'Unknown')}",
            "description": alert.get("description", ""),
            "color": color,
            "fields": fields,
            "footer": {
                "text": f"HomeLab SIEM • {alert.get('timestamp', datetime.now(timezone.utc).isoformat())}"
            }
        }]
    }
