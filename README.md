# HomeLab SIEM

A lightweight, self-hosted **Security Information & Event Management** system built in pure Python.
Designed to learn cybersecurity concepts hands-on — log collection, threat detection, and a live dashboard.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat&logo=flask)
![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?style=flat&logo=sqlite)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Detection Rules](#detection-rules)
- [Security Assessment](#security-assessment)
- [Configuration](#configuration)
- [Backup and Recovery](#backup-and-recovery)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [License](#license)

---

## Features

| Feature | Details |
|---|---|
| **Log Collection** | Tails local files + listens on UDP syslog (port 5140) |
| **Log Parsing** | SSH/auth, Apache/Nginx, Flask/Werkzeug, kernel/dmesg, syslog |
| **Threat Detection** | Rule engine with 11 built-in rules mapped to MITRE ATT&CK |
| **MITRE ATT&CK** | Every rule mapped to a technique ID |
| **Dashboard** | Live web UI — KPIs, timeline, alert table, event stream, rule stats |
| **Rule Editor** | Web UI at /rules — toggle, edit and filter rules without touching code |
| **REST API** | /api/events, /api/alerts, /api/stats, /api/rules, /api/rules/stats, /api/ingest |
| **Network Monitoring** | Suricata IDS integration via live eve.json ingestion — closes G-01 |
| **GeoIP Enrichment** | Geographic metadata for every alert source IP via ip-api.com |
| **Discord Alerts** | Webhook notifications for HIGH and CRITICAL alerts with rich embeds |
| **Docker Compose** | Single-command deployment with persistent volumes and health check |
| **Backup & Recovery** | Automated database backup and restore scripts |
| **Demo Simulator** | Generates realistic fake logs with --stress-test mode for threshold validation |

---

## Quick Start

> [!TIP]
> The data/siem.db SQLite database is created automatically on first run.
> The dashboard is optimized for Full HD (1920x1080) displays or higher.

**Option A — Local Python**

1. Clone the repository

`git clone https://github.com/Lollobar17/Homelab_SIEM.git`

2. Install dependencies (Python 3.10+)

`pip install -r requirements.txt`

3. Run the SIEM

`python app.py`

4. Open dashboard at `http://localhost:5000`

5. Optional — feed demo logs in a second terminal

`python simulate_logs.py`

**Option B — Docker Compose**

`docker-compose up -d`

The SIEM will be available at `http://localhost:5000`.

---

## Architecture

The SIEM is composed of four layers:

- **Collectors** — file tailers, UDP syslog receiver and Suricata eve.json watcher feed raw events into the pipeline
- **Parser** — collector.py normalizes each line into a structured event object with ANSI stripping
- **Rule Engine** — detector.py evaluates each event against the detection ruleset, generates alerts with GeoIP enrichment and sends Discord notifications
- **Storage + API** — storage.py persists events and alerts to SQLite with automatic schema migration, app.py exposes them via REST API and dashboard

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | /api/stats | KPIs, timeline, top IPs |
| GET | /api/events?limit=N&category=auth&source=flask | Recent events with optional filters |
| GET | /api/alerts?limit=N&severity=HIGH | Recent alerts |
| GET | /api/rules | All detection rules |
| GET | /api/rules/stats | Rule effectiveness statistics by category and severity |
| GET | /api/health | Health check |
| POST | /api/ingest | Manually ingest a log line |
| GET | /rules | Rule Editor web UI |

Ingest example: `curl -X POST http://localhost:5000/api/ingest -H "Content-Type: application/json" -d '{"raw": "Failed password for root from 1.2.3.4 port 22 ssh2", "source": "auth"}'`

---

## Detection Rules

> [!IMPORTANT]
> All rules are mapped to MITRE ATT&CK techniques. Rules can be toggled,
> filtered and edited via the Rule Editor at /rules without touching code.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| AUTH-001 | SSH Brute Force | HIGH | T1110 |
| AUTH-002 | Root Login Attempt | HIGH | T1110 |
| AUTH-003 | Successful Root Login | CRITICAL | T1078.003 |
| AUTH-004 | Sudo Privilege Escalation | MEDIUM | T1548.003 |
| AUTH-005 | SSH Brute Force — High Volume | CRITICAL | T1110 |
| AUTH-006 | Successful Login After Failures | CRITICAL | T1110 |
| WEB-001 | HTTP Scanner / Directory Traversal | MEDIUM | T1083 |
| WEB-002 | Web Brute Force (4xx Flood) | MEDIUM | T1110 |
| WEB-003 | SQL Injection Attempt | HIGH | T1190 |
| WEB-004 | Web Brute Force — High Volume | CRITICAL | T1110 |
| SYS-001 | OOM Killer Activated | MEDIUM | — |
| SYS-002 | Segmentation Fault | LOW | — |

> [!TIP]
> To add a custom rule, open siem/detector.py and add an entry to the
> RULES list with id, name, severity, category, mitre, match and threshold fields.

---

## Security Assessment

> [!IMPORTANT]
> This SIEM was subjected to a structured penetration testing assessment
> using Nmap, Hydra, SQLmap and manual path traversal testing.
> The assessment identified 7 detection gaps — all resolved across v1.1.0 through v1.5.0.

### Initial Assessment (v1.0.0)

| Scenario | Tool | MITRE | Detection |
|---|---|---|---|
| Network Scanning | Nmap | T1046 | Not detected |
| SSH Brute Force | Hydra | T1110 | Partial |
| SQL Injection | SQLmap | T1190 | Not detected |
| Path Traversal | Manual | T1083 | Not detected |

**Detection Rate: 25%**

### Post-Remediation (v1.5.0)

| Scenario | Tool | MITRE | Detection | Severity |
|---|---|---|---|---|
| Network Scanning | Nmap/Suricata | T1046 | Detected | HIGH |
| SSH Brute Force | Hydra | T1110 | Detected | CRITICAL |
| SQL Injection | SQLmap | T1190 | Detected | HIGH |
| Path Traversal | Manual | T1083 | Detected | MEDIUM |

**Detection Rate: 100%**

> [!NOTE]
> Full assessment documentation, gap analysis and final security report
> are available in the
> [Network Security Monitoring Lab](https://github.com/Lollobar17/Network_Security_Lab)
> repository.

---

## Configuration

Edit config.json to customize log sources and ports:

`syslog_enabled` — enable/disable UDP syslog listener (default: true)

`syslog_port` — default 5140

`watch_files` — list of log files to tail with source name

`web_port` — default 5000

`discord_webhook` — Discord webhook URL for alert notifications

`discord_min_severity` — minimum severity for Discord notifications (default: HIGH)

> [!IMPORTANT]
> config.json is excluded from version control via .gitignore.
> Never commit sensitive values like webhook URLs to the repository.

---

## Backup and Recovery

Create a backup:

`python scripts/backup_db.py`

Restore a backup:

`python scripts/restore_db.py --from backups/siem-YYYYMMDD-HHMMSS.db --force`

Full operations guide: `docs/BACKUP_AND_RECOVERY.md`

---

## Project Structure

```text
Homelab_SIEM/
├── app.py                     # Flask app + API routes
├── config.json                # User configuration (excluded from git)
├── requirements.txt
├── simulate_logs.py           # Demo log generator with --stress-test mode
├── suricata.yaml              # Suricata configuration
├── Dockerfile                 # Container image definition
├── docker-compose.yml         # Multi-container deployment
├── dockerignore               # Docker build exclusions
├── CHANGELOG.md               # Version history
├── siem/
│   ├── collector.py           # File tailer + UDP syslog + Flask log parser
│   ├── detector.py            # Detection rule engine + GeoIP + Discord notify
│   ├── storage.py             # SQLite persistence + auto-migration
│   ├── geoip.py               # GeoIP lookup via ip-api.com with lru_cache
│   ├── notifier.py            # Discord webhook notifications
│   └── test_discord.py        # Discord webhook test utility
├── suricata-logs/             # Suricata eve.json output directory
├── suricata-rules/            # Custom Suricata detection rules
├── templates/
│   ├── dashboard.html         # Single-page web dashboard
│   └── rules.html             # Rule Editor web UI
├── docs/
│   ├── BACKUP_AND_RECOVERY.md # Backup and restore guide
│   ├── DISCORD_GUIDE.md       # Discord webhook setup guide
│   ├── GEOIP_GUIDE.md         # GeoIP configuration guide
│   ├── RULESTATS_GUIDE.md     # Rule statistics guide
│   ├── SURICATA_SETUP.md      # Suricata integration setup guide
│   └── SYSLOG_GUIDE.md        # Syslog integration guide
├── scripts/
│   ├── backup_db.py           # Database backup script
│   └── restore_db.py          # Database restore script
└── data/
    └── siem.db                # Auto-created SQLite database

```

## Roadmap

- [x] Core SIEM — log collection, detection, dashboard
- [x] 11 built-in detection rules with MITRE ATT&CK mapping
- [x] REST API with source and category filters
- [x] Demo simulator with --stress-test mode
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
- [x] Rule editor in dashboard UI
- [x] Backup and recovery scripts
- [x] Rate limiting on log ingestion
- [x] WSL2 migration — resolved VirtualBox/Hyper-V conflict

---

## Learning Resources

- [MITRE ATT&CK](https://attack.mitre.org) — adversary tactics and techniques
- [TryHackMe](https://tryhackme.com) — hands-on labs
- [Suricata Documentation](https://suricata.readthedocs.io) — network IDS
- [The Elastic SIEM Guide](https://www.elastic.co/what-is/siem)

---

## License

MIT — use freely, learn a lot.
