# HomeLab SIEM

A lightweight, self-hosted **Security Information & Event Management** system built in pure Python.
Designed to learn cybersecurity concepts hands-on — log collection, threat detection, and a live dashboard.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat&logo=flask)
![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?style=flat&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Detection Rules](#detection-rules)
- [Backup and Recovery](#backup-and-recovery)
- [Security Assessment](#security-assessment)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| Feature | Details |
|---|---|
| **Log Collection** | Tails local files + listens on UDP syslog (port 5140) |
| **Log Parsing** | SSH/auth, Apache/Nginx access logs, kernel/dmesg, syslog |
| **Threat Detection** | Rule engine with 8 built-in rules (SSH brute force, SQLi, traversal) |
| **MITRE ATT&CK** | Every rule is mapped to a MITRE technique ID |
| **Dashboard** | Live web UI — KPIs, timeline chart, alert table, event stream |
| **REST API** | /api/events, /api/alerts, /api/stats, /api/ingest (supports source/category filters) |
| **Demo Simulator** | Generate realistic fake logs without a real Linux system |
| **Network Monitoring** | Suricata IDS integration with live `eve.json` ingestion |
| **GeoIP Enrichment** | Adds geolocation metadata for alert source IPs |
| **Discord Alerts** | Webhook notifications for HIGH/CRITICAL alerts |
| **Docker Compose** | SIEM + Suricata multi-container deployment |

---

## Quick Start

> [!TIP]
> The data/siem.db SQLite database is created automatically on first run.
> The dashboard is optimized for Full HD (1920x1080) displays or higher.

1. Clone the repository

`git clone https://github.com/Lollobar17/Homelab_SIEM.git`

2. Install dependencies (Python 3.10+)

`pip install -r requirements.txt`

3. Run the SIEM

`python app.py`

4. Open dashboard at `http://localhost:5000`

5. Optional — feed demo logs in a second terminal

`python simulate_logs.py`

---

## Architecture

The SIEM is composed of four layers:

- **Collectors** — file tailers and UDP syslog receiver feed raw log lines into the pipeline
- **Parser** — collector.py normalizes each line into a structured event object
- **Rule Engine** — detector.py evaluates each event against the detection ruleset and generates alerts
- **Storage + API** — storage.py persists events and alerts to SQLite, app.py exposes them via REST API and dashboard

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | /api/stats | KPIs, timeline, top IPs |
| GET | /api/events?limit=N&category=auth | Recent events |
| GET | /api/alerts?limit=N&severity=HIGH | Recent alerts |
| GET | /api/rules | All detection rules |
| POST | /api/ingest | Manually ingest a log line |
| GET | /api/health | Health check |

Ingest example: `curl -X POST http://localhost:5000/api/ingest -H "Content-Type: application/json" -d '{"raw": "Failed password for root from 1.2.3.4 port 22 ssh2", "source": "myserver"}'`

---

## Detection Rules

> [!IMPORTANT]
> All rules are mapped to MITRE ATT&CK techniques. Rule AUTH-002 was
> updated in v1.1.0 following a structured penetration testing assessment
> — see the Security Assessment section for details.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| AUTH-001 | SSH Brute Force | HIGH | T1110 |
| AUTH-002 | Root Login Attempt | HIGH | T1110 |
| AUTH-003 | Successful Root Login | CRITICAL | T1078.003 |
| AUTH-004 | Sudo Privilege Escalation | MEDIUM | T1548.003 |
| WEB-001 | Directory Traversal | MEDIUM | T1083 |
| WEB-002 | Web Brute Force (4xx flood) | MEDIUM | T1110 |
| WEB-003 | SQL Injection Attempt | HIGH | T1190 |
| SYS-001 | OOM Killer Activated | MEDIUM | — |

> [!TIP]
> To add a custom rule, open siem/detector.py and add an entry to the
> RULES list with id, name, severity, category, mitre, match and threshold fields.

---

## Backup and Recovery

Create a backup:

`python scripts/backup_db.py`

Restore a backup:

`python scripts/restore_db.py --from backups/siem-YYYYMMDD-HHMMSS.db --force`

Full operations guide:

`docs/BACKUP_AND_RECOVERY.md`

---

## Security Assessment

> [!IMPORTANT]
> This SIEM was subjected to a structured penetration testing assessment
> using Nmap, Hydra, SQLmap and manual path traversal testing.
> The assessment identified 7 detection gaps and directly informed
> the improvements released in v1.1.0.

| Scenario | Tool | MITRE | Detection Result |
|---|---|---|---|
| Network Scanning | Nmap | T1046 | Not detected |
| SSH Brute Force | Hydra | T1110 | Partial — 3 HIGH alerts |
| SQL Injection | SQLmap | T1190 | Not detected |
| Path Traversal | Manual | T1083 | Not detected |

**Overall detection rate: 25% — improvement in progress**

> [!NOTE]
> Full assessment documentation, gap analysis and final security report
> are available in the
> [Network Security Monitoring Lab](https://github.com/Lollobar17/Network_Security_Lab)
> repository.

---

## Configuration

Edit config.json to customize log sources and ports:

`syslog_enabled` — enable/disable UDP syslog listener

`syslog_port` — default 5140

`watch_files` — list of log files to tail with source name

`web_port` — default 5000

Send syslog from another host: `logger -n 127.0.0.1 -P 5140 --udp "test message"`

---

## Project Structure

```
Homelab_SIEM/
├── app.py               # Flask app + API routes
├── config.json          # User configuration
├── requirements.txt
├── simulate_logs.py     # Demo log generator
├── CHANGELOG.md         # Version history
├── siem/
│   ├── collector.py     # File tailer + UDP syslog + parser
│   ├── detector.py      # Detection rule engine
│   └── storage.py       # SQLite persistence layer
├── templates/
│   └── dashboard.html   # Single-page web dashboard
└── data/
    └── siem.db          # Auto-created SQLite database
```

---

## Roadmap

- [x] Core SIEM — log collection, detection, dashboard
- [x] 8 built-in detection rules with MITRE ATT&CK mapping
- [x] REST API
- [x] Demo simulator
- [x] Security assessment via Network Security Monitoring Lab
- [x] Fix AUTH-002 MITRE classification (G-02)
- [x] Add source_ip to alert schema (G-03)
- [x] Brute force volume correlation rule — T1110 (G-04)
- [x] Flask access log parsing — web layer visibility (G-05, G-06)
- [x] CRITICAL severity thresholds (G-07)
- [x] Network monitoring layer — Suricata integration (G-01)
- [x] GeoIP lookup for source IPs
- [x] Discord webhook notifications
- [x] Docker Compose setup
- [X] Rule editor in dashboard UI

---

## Learning Resources

- [MITRE ATT&CK](https://attack.mitre.org) — adversary tactics and techniques
- [TryHackMe](https://tryhackme.com) — hands-on labs
- [The Elastic SIEM Guide](https://www.elastic.co/what-is/siem)

---

## License

MIT — use freely, learn a lot.
