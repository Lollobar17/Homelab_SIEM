"""
test_discord.py — Discord Webhook Diagnostic & Full Test
Quick test (default): sends 1 test alert to verify webhook
Full test (--full): sends all severity levels with different GeoIP locations
"""

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from siem.notifier import send_alert

# ── Single quick-test alert ──────────────────────────────────────────────

QUICK_ALERT = {
    "rule": "TEST-001",
    "name": "Discord Webhook Test",
    "description": "This is a test alert to verify your Discord webhook is configured correctly.",
    "severity": "HIGH",
    "mitre": "T1190",
    "source_ip": "203.0.113.42",
    "geo": {
        "country": "United States",
        "region": "California",
        "city": "Fremont",
        "isp": "Test ISP",
    },
    "timestamp": "2026-04-27T12:00:00+00:00",
}

# ── Full multi-alert suite ───────────────────────────────────────────────

FULL_ALERTS = [
    {
        "rule": "WEB-003",
        "name": "SQL Injection Attempt",
        "severity": "HIGH",
        "description": "SQL injection patterns detected in URI",
        "source_ip": "45.33.32.156",
        "geo": {"country": "United States", "region": "California", "city": "Fremont", "isp": "Linode"},
        "mitre": "T1190",
        "timestamp": "2026-04-27T15:00:00+00:00",
    },
    {
        "rule": "AUTH-005",
        "name": "SSH Brute Force — High Volume",
        "severity": "CRITICAL",
        "description": "More than 10 failed SSH login attempts from same IP in 60 seconds",
        "source_ip": "185.220.101.5",
        "geo": {"country": "Russia", "region": "Moscow", "city": "Moscow", "isp": "Rostelecom"},
        "mitre": "T1110",
        "timestamp": "2026-04-27T15:05:00+00:00",
    },
    {
        "rule": "WEB-001",
        "name": "HTTP Scanner / Directory Traversal",
        "severity": "MEDIUM",
        "description": "Request path contains traversal patterns",
        "source_ip": "80.241.220.1",
        "geo": {"country": "Germany", "region": "Hesse", "city": "Frankfurt", "isp": "Hetzner"},
        "mitre": "T1083",
        "timestamp": "2026-04-27T15:10:00+00:00",
    },
    {
        "rule": "SYS-002",
        "name": "Segmentation Fault",
        "severity": "LOW",
        "description": "A process crashed with a segfault",
        "source_ip": "192.168.1.25",
        "geo": {"country": "Internal", "city": "Private Network", "isp": "N/A"},
        "mitre": None,
        "timestamp": "2026-04-27T15:15:00+00:00",
    },
    {
        "rule": "AUTH-002",
        "name": "Root Login Attempt",
        "severity": "HIGH",
        "description": "Someone tried to log in as root via SSH",
        "source_ip": "51.15.1.1",
        "geo": {"country": "France", "region": "Île-de-France", "city": "Paris", "isp": "Scaleway"},
        "mitre": "T1110",
        "timestamp": "2026-04-27T15:20:00+00:00",
    },
    {
        "rule": "AUTH-004",
        "name": "Sudo Privilege Escalation",
        "severity": "MEDIUM",
        "description": "A user ran a command with sudo",
        "source_ip": "133.1.1.1",
        "geo": {"country": "Japan", "region": "Tokyo", "city": "Tokyo", "isp": "NTT Communications"},
        "mitre": "T1548.003",
        "timestamp": "2026-04-27T15:25:00+00:00",
    },
]

# ── Helper ───────────────────────────────────────────────────────────────

def _resolve_webhook(cli_url: str | None) -> str | None:
    """Return webhook URL from CLI arg, env var, or config.json (in that order)."""
    if cli_url:
        return cli_url

    env_url = os.getenv("DISCORD_WEBHOOK_URL", "")
    if env_url:
        return env_url

    cfg_path = Path("config.json")
    if cfg_path.exists():
        try:
            with open(cfg_path) as f:
                cfg = json.load(f)
            url = cfg.get("discord_webhook", "")
            if url:
                return url
        except Exception:
            pass

    return None


def _banner(title: str):
    print("=" * 60)
    print(title)
    print("=" * 60)


def run_quick_test(webhook: str):
    _banner("Discord Webhook — Quick Test")
    print(f"URL: {webhook[:50]}...")
    print("\nSending single HIGH severity test alert …")

    ok = send_alert(QUICK_ALERT, webhook_url=webhook, min_severity="LOW")

    if ok:
        print("[PASS] Message sent successfully! Check your Discord channel.")
    else:
        print("[FAIL] Message failed to send.")
        print("\nCommon causes:")
        print("  - Wrong webhook URL")
        print("  - Webhook was deleted in Discord")
        print("  - Discord rate limit (wait a few seconds)")
        print("  - Network/firewall blocking requests")


def run_full_test(webhook: str):
    _banner("Discord Webhook — Full Multi-Alert Test")
    print(f"URL: {webhook[:50]}...")
    print("\nSending alerts with every severity level + GeoIP variants …\n")

    passed = 0
    for i, alert in enumerate(FULL_ALERTS, 1):
        print(f"[{i}/{len(FULL_ALERTS)}] {alert['severity']:8s} | {alert['name']:35s} | {alert['source_ip']}")
        ok = send_alert(alert, webhook_url=webhook, min_severity="LOW")
        status = "[PASS]" if ok else "[FAIL]"
        print(f"         {status}")
        if ok:
            passed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed}/{len(FULL_ALERTS)} alerts sent successfully")
    print("Expected embeds in Discord:")
    for a in FULL_ALERTS:
        g = a['geo']
        print(f"  [{a['severity']:8s}] {a['name']:35s} | {g['country']}, {g['city']}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Discord Webhook Tester")
    parser.add_argument("url", nargs="?", help="Discord webhook URL (optional)")
    parser.add_argument("--full", action="store_true", help="Run full multi-alert test instead of quick test")
    args = parser.parse_args()

    webhook = _resolve_webhook(args.url)

    if not webhook:
        print("=" * 60)
        print("Discord Webhook Diagnostic")
        print("=" * 60)
        print("\nNo webhook URL found.")
        print("\nSources checked (in order):")
        print("  1. Command-line argument:  python test_discord.py <URL>")
        print("  2. Environment variable:   $env:DISCORD_WEBHOOK_URL = '...'")
        print("  3. config.json field:      {'discord_webhook': '...'}")
        print("\nTo fix, run one of:")
        print('  python test_discord.py https://discord.com/api/webhooks/...')
        print("  (or set env var / config.json and retry)")
        sys.exit(1)

    if args.full:
        run_full_test(webhook)
    else:
        run_quick_test(webhook)


if __name__ == "__main__":
    main()
