#!/usr/bin/env python3
"""
simulate_logs.py — Demo Log Simulator
Sends realistic fake log lines to the SIEM /api/ingest endpoint.
Useful for testing the dashboard without a real Linux system.

Usage:
    python simulate_logs.py [--host http://localhost:5000] [--rate 1.5]
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

def main():
    parser = argparse.ArgumentParser(description="HomeLab SIEM Log Simulator")
    parser.add_argument("--host", default="http://localhost:5000", help="SIEM base URL")
    parser.add_argument("--rate", type=float, default=1.5, help="Average logs per second")
    args = parser.parse_args()

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

if __name__ == "__main__":
    main()
