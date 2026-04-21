#!/usr/bin/env python3
"""
simulate_logs.py — Demo Log Simulator
Sends realistic fake log lines to the SIEM /api/ingest endpoint.
Useful for testing the dashboard without a real Linux system.

Usage:
    python simulate_logs.py [--host http://localhost:5000] [--rate 1.5]
    python simulate_logs.py --stress-test          # test AUTH-005 and WEB-004 thresholds
    python simulate_logs.py --stress-test --ip 10.0.0.1  # custom attacker IP
"""

import argparse
import random
import time
import requests
from datetime import datetime

FAKE_IPS = [
    "192.168.1.101", "10.0.0.55", "203.0.113.42", "198.51.100.7",
    "45.33.32.156",  "185.220.101.5", "91.108.4.0", "172.16.0.99",
]
FAKE_USERS = ["root", "admin", "ubuntu", "pi", "vagrant", "test", "deploy"]
FAKE_PATHS = [
    "/index.html", "/admin", "/wp-login.php", "/login",
    "/../../../etc/passwd", "/api/v1/users", "/phpmyadmin",
    "/search?q=1%27+OR+%271%27%3D%271",
]
FAKE_METHODS = ["GET", "POST", "PUT", "DELETE"]
FAKE_STATUSES = [200, 200, 200, 301, 302, 400, 401, 403, 404, 404, 500]

def rand_ip():   return random.choice(FAKE_IPS)
def rand_user(): return random.choice(FAKE_USERS)
def rand_path(): return random.choice(FAKE_PATHS)
def rand_dt():
    return datetime.utcnow().strftime("%d/%b/%Y:%H:%M:%S +0000")

LOG_GENERATORS = [
    # SSH failed password
    lambda: {
        "raw": f"Mar 15 12:{random.randint(10,59)}:{random.randint(10,59)} homelab sshd[{random.randint(1000,9999)}]: Failed password for {rand_user()} from {rand_ip()} port {random.randint(1024,65535)} ssh2",
        "source": "auth"
    },
    # SSH accepted
    lambda: {
        "raw": f"Mar 15 12:{random.randint(10,59)}:{random.randint(10,59)} homelab sshd[{random.randint(1000,9999)}]: Accepted publickey for ubuntu from {rand_ip()} port {random.randint(1024,65535)} ssh2",
        "source": "auth"
    },
    # Root login attempt
    lambda: {
        "raw": f"Mar 15 12:{random.randint(10,59)}:{random.randint(10,59)} homelab sshd[{random.randint(1000,9999)}]: Invalid user root from {rand_ip()}",
        "source": "auth"
    },
    # Sudo
    lambda: {
        "raw": f"Mar 15 12:{random.randint(10,59)}:{random.randint(10,59)} homelab sudo[{random.randint(1000,9999)}]: ubuntu : command=/usr/bin/apt-get update",
        "source": "auth"
    },
    # Apache access
    lambda: {
        "raw": f'{rand_ip()} - - [{rand_dt()}] "{random.choice(FAKE_METHODS)} {rand_path()} HTTP/1.1" {random.choice(FAKE_STATUSES)} {random.randint(200,8000)}',
        "source": "apache"
    },
    # Kernel OOM
    lambda: {
        "raw": f"[{random.randint(10000,99999)}.{random.randint(100,999)}] Out of memory: Kill process {random.randint(100,999)} (python3) score {random.randint(100,999)} or sacrifice child",
        "source": "kernel"
    },
    # Kernel segfault
    lambda: {
        "raw": f"[{random.randint(10000,99999)}.{random.randint(100,999)}] node[{random.randint(100,999)}]: segfault at 0 ip 00007f rsp 00007f error 4 in libc.so",
        "source": "kernel"
    },
    # Generic syslog
    lambda: {
        "raw": f"Mar 15 12:{random.randint(10,59)}:{random.randint(10,59)} homelab systemd[1]: Started Daily apt download activities.",
        "source": "syslog"
    },
]


def stress_test(host: str, attacker_ip: str):
    """
    Stress test mode — fires AUTH-005 and WEB-004 thresholds
    by sending bursts of events from a single fixed IP.
    """
    url = f"{host}/api/ingest"
    print(f"\n[Stress Test] Attacker IP: {attacker_ip}")
    print("[Stress Test] Phase 1 — SSH brute force burst (triggers AUTH-005)")

    # Phase 1: 12 SSH failed logins from same IP → triggers AUTH-005 (threshold: 10)
    for i in range(12):
        entry = {
            "raw": f"Mar 15 12:00:{i:02d} homelab sshd[1234]: Failed password for root from {attacker_ip} port 22 ssh2",
            "source": "auth"
        }
        try:
            r = requests.post(url, json=entry, timeout=3)
            data = r.json()
            alerts = data.get("alerts", 0)
            flag = "[ALERT]" if alerts > 0 else "      "
            print(f"  {flag}  [{i+1:>3}/12] SSH fail from {attacker_ip} | alerts: {alerts}")
        except Exception as e:
            print(f"  [!] Error: {e}")
        time.sleep(0.1)

    print("\n[Stress Test] Phase 2 — Web 4xx flood (triggers WEB-004)")

    # Phase 2: 55 web 4xx responses from same IP → triggers WEB-004 (threshold: 50)
    for i in range(55):
        entry = {
            "raw": f'{attacker_ip} - - [{rand_dt()}] "GET /admin HTTP/1.1" 404 512',
            "source": "apache"
        }
        try:
            r = requests.post(url, json=entry, timeout=3)
            data = r.json()
            alerts = data.get("alerts", 0)
            flag = "[ALERT]" if alerts > 0 else "      "
            print(f"  {flag}  [{i+1:>3}/55] Web 404 from {attacker_ip} | alerts: {alerts}")
        except Exception as e:
            print(f"  [!] Error: {e}")
        time.sleep(0.05)

    print("\n[Stress Test] Phase 3 — Successful login after failures (triggers AUTH-006)")

    # Phase 3: successful login from same IP after brute force → triggers AUTH-006
    entry = {
        "raw": f"Mar 15 12:01:00 homelab sshd[1234]: Accepted password for root from {attacker_ip} port 22 ssh2",
        "source": "auth"
    }
    try:
        r = requests.post(url, json=entry, timeout=3)
        data = r.json()
        alerts = data.get("alerts", 0)
        flag = "[ALERT]" if alerts > 0 else "      "
        print(f"  {flag}  Successful login from {attacker_ip} | alerts: {alerts}")
    except Exception as e:
        print(f"  [!] Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="HomeLab SIEM Log Simulator")
    parser.add_argument("--host", default="http://localhost:5000", help="SIEM base URL")
    parser.add_argument("--rate", type=float, default=1.5, help="Average logs per second")
    parser.add_argument("--stress-test", action="store_true", help="Run threshold stress test")
    parser.add_argument("--sqli-test", action="store_true", help="Test WEB-003 SQLi detection")
    parser.add_argument("--ip", default="10.10.10.10", help="Attacker IP for stress test")
    args = parser.parse_args()

    if args.sqli_test:
        sqli_test(args.host, args.ip)
        return
    if args.stress_test:
        stress_test(args.host, args.ip)
        return

    url = f"{args.host}/api/ingest"
    print(f"[Simulator] Sending logs to {url}  ({args.rate:.1f} logs/s)")
    print("[Simulator] Press Ctrl+C to stop\n")

    sent = 0
    while True:
        gen   = random.choice(LOG_GENERATORS)
        entry = gen()
        try:
            r = requests.post(url, json=entry, timeout=3)
            data = r.json()
            flag = "[ALERT]" if data.get("alerts", 0) > 0 else "      "
            print(f"  {flag}  [{sent:>5}] {entry['source']:8s} | {entry['raw'][:90]}")
            sent += 1
        except Exception as e:
            print(f"  [!] Error: {e}")

        delay = random.expovariate(args.rate)
        time.sleep(min(delay, 5.0))

def sqli_test(host: str, attacker_ip: str):
    """
    SQLi test — sends common sqlmap payloads to trigger WEB-003.
    """
    url = f"{host}/api/ingest"
    print(f"\n[SQLi Test] Attacker IP: {attacker_ip}")
    payloads = [
        f'{attacker_ip} - - [01/Jan/2024:12:00:00] "GET /search?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 -',  # Boolean blind
        f'{attacker_ip} - - [01/Jan/2024:12:00:01] "GET /?q=1+AND+1=1 HTTP/1.1" 200 -',  # AND 1=1
        f'{attacker_ip} - - [01/Jan/2024:12:00:02] "POST /login HTTP/1.1" 200 -',  # UNION (body not in access log)
        f'{attacker_ip} - - [01/Jan/2024:12:00:03] "GET /vuln.php?id=1; DROP TABLE users--" 404 -',  # DROP
        f'{attacker_ip} - - [01/Jan/2024:12:00:04] "GET /api/users?filter=1%20OR%20SLEEP(5)-- HTTP/1.1" 200 -',  # Time blind
    ]
    for i, raw_log in enumerate(payloads, 1):
        entry = {"raw": raw_log, "source": "flask"}
        try:
            r = requests.post(url, json=entry, timeout=3)

            data = r.json()
            alerts = data.get("alerts", 0)
            flag = "[WEB-003!]" if alerts > 0 else "[no alert]"
            print(f"  {flag:>10} [{i}/5] {raw_log[-60:]} | alerts: {alerts}")
        except Exception as e:
            print(f"  [!] Error: {e}")
        time.sleep(0.5)

if __name__ == "__main__":
    main()
