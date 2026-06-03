# HomeLab SIEM

A lightweight, self-hosted **Security Information & Event Management** system built in pure Python.
Designed to learn cybersecurity concepts hands-on — log collection, threat detection, and a live dashboard.
Now extended with **Azure Cloud Integration** for hybrid on-premise + cloud security monitoring.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat&logo=flask)
![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?style=flat&logo=sqlite)
![Azure](https://img.shields.io/badge/Azure-Cloud-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Azure Cloud Integration](#azure-cloud-integration)
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
| **Threat Detection** | Rule engine with 26 built-in rules mapped to MITRE ATT&CK |
| **Cloud Detection** | Azure VNet Flow Logs + Activity Log monitoring (14 cloud rules) |
| **MITRE ATT&CK** | Every rule mapped to a technique ID |
| **Dashboard** | Live web UI — KPIs, charts, alert table, event stream, rule stats |
| **Event Modal** | Click any event to view full raw log, parsed fields and GeoIP |
| **Alert Deduplication** | Identical alerts grouped with occurrence counter |
| **Export CSV** | One-click export of filtered events and alerts |
| **GeoIP Enrichment** | Geographic metadata for every source IP via ip-api.com |
| **Discord Alerts** | Webhook notifications for HIGH and CRITICAL alerts |
| **Docker Compose** | Single-command deployment with persistent volumes |
| **Bash Automation** | start/stop/health-check/log-rotation scripts for WSL2 and Linux |
| **Backup & Recovery** | Automated SQLite backup and restore scripts |

---

## Quick Start

**Option A — Local Python**

```bash
git clone https://github.com/Lollobar17/Homelab_SIEM.git
cd Homelab_SIEM
pip install -r requirements.txt
python app.py
```

Open dashboard at `http://localhost:5000`

**Option B — Bash script (WSL2 / Linux)**

```bash
bash scripts/bash/start_siem.sh --no-azure
```

**Option C — Docker Compose**

```bash
docker-compose up -d
```

---

## Architecture

```
[Local Logs]          [Azure VNet]         [Azure Activity Log]
     ↓                     ↓                       ↓
[collector.py]    [azure_collector.py]  [azure_activity_collector.py]
     ↓                     ↓                       ↓
     └─────────────────────┴───────────────────────┘
                           ↓
                   POST /api/ingest
                           ↓
               [detector.py — 26 rules]
                           ↓
              [storage.py — SQLite + API]
                           ↓
              [Dashboard + Discord + CSV]
```

- **Collectors** — file tailers, UDP syslog, Suricata eve.json, Azure Blob Storage pollers
- **Parser** — normalizes raw lines into structured event objects
- **Rule Engine** — evaluates events against 26 detection rules with GeoIP and Discord notify
- **Storage + API** — SQLite persistence, REST API, live dashboard

---

## Azure Cloud Integration

Phase 1 and Phase 2 of the cloud integration are fully operational.

### Infrastructure

| Resource | Name | Type |
|---|---|---|
| Resource Group | homelab-siem-rg | Azure container |
| Virtual Machine | homelab-vm | Ubuntu 24.04, D2s_v6, West Europe |
| Storage Account | homelabsiemflow | LRS, West Europe |
| Flow Log | homelab-vm-vnet-flowlog | VNet Flow Logs v4 |
| Log Analytics | homelab-siem-workspace | Traffic Analytics |
| Diagnostic Setting | homelab-activity-logs | Admin + Security + Policy |

### Setup

```bash
# Install Azure dependency
pip install azure-storage-blob

# Add to config.json
{
  "AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;...",
  "AZURE_STORAGE_CONTAINER": "insights-logs-flowlogflowevent",
  "SIEM_INGEST_URL": "http://localhost:5000/api/ingest"
}

# Start collectors
python azure_collector.py
python azure_activity_collector.py
```

Full setup guide: `azure_siem/docs/AZURE_INTEGRATION.md`

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | /api/stats | KPIs, timeline, top IPs |
| GET | /api/events?limit=N&category=cloud | Recent events with filters |
| GET | /api/alerts?limit=N&severity=HIGH | Recent alerts |
| GET | /api/rules | All detection rules |
| GET | /api/rules/stats | Rule effectiveness statistics |
| GET | /api/health | Health check |
| POST | /api/ingest | Manually ingest a log line |
| GET | /rules | Rule Editor web UI |

---

## Detection Rules

### On-Premise Rules (12)

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

### Cloud Rules — Azure VNet Flow Logs (7)

| ID | Name | Severity | MITRE |
|---|---|---|---|
| CLOUD-001 | NSG: SSH REJECT from external IP | HIGH | T1110 |
| CLOUD-002 | NSG: SSH Brute Force (10+ in 5min) | CRITICAL | T1110 |
| CLOUD-003 | NSG: RDP Traffic Detected | HIGH | T1021.001 |
| CLOUD-004 | NSG: Port Scan Detected | HIGH | T1046 |
| CLOUD-005 | NSG: Database Port Exposed | CRITICAL | T1190 |
| CLOUD-006 | NSG: Anomalous Outbound Volume | HIGH | T1048 |
| CLOUD-007 | NSG: Unexpected Inbound Port | MEDIUM | T1133 |

### Cloud Rules — Azure Activity Log (7)

| ID | Name | Severity | MITRE |
|---|---|---|---|
| CLOUD-008 | Activity: NSG Rule Modified | HIGH | T1562.007 |
| CLOUD-009 | Activity: Storage Keys Listed | HIGH | T1552.005 |
| CLOUD-010 | Activity: Diagnostic Setting Deleted | CRITICAL | T1562.008 |
| CLOUD-011 | Activity: New Role Assignment | CRITICAL | T1098.003 |
| CLOUD-012 | Activity: VM Deleted | CRITICAL | T1485 |
| CLOUD-013 | Activity: VM Started | MEDIUM | T1078.004 |
| CLOUD-014 | Activity: API Brute Force | HIGH | T1110 |

---

## Security Assessment

The SIEM was subjected to a structured penetration testing assessment using Nmap, Hydra, SQLmap and manual path traversal. All 7 detection gaps identified were resolved across v1.1.0 through v1.5.0.

**Detection Rate: 100%** (post-remediation)

Full assessment: [Network Security Monitoring Lab](https://github.com/Lollobar17/Network_Security_Lab)

---

## Configuration

Edit `config.json`:

| Key | Default | Description |
|---|---|---|
| `syslog_enabled` | true | Enable UDP syslog listener |
| `syslog_port` | 5140 | UDP syslog port |
| `web_port` | 5000 | Dashboard port |
| `discord_webhook` | — | Discord webhook URL |
| `AZURE_STORAGE_CONNECTION_STRING` | — | Azure storage credentials |
| `AZURE_STORAGE_CONTAINER` | insights-logs-flowlogflowevent | Flow logs container |
| `SIEM_INGEST_URL` | http://localhost:5000/api/ingest | SIEM ingest endpoint |

> config.json is excluded from version control via .gitignore. Never commit credentials.

---

## Backup and Recovery

```bash
# Create backup
python scripts/backup_db.py

# Restore backup
python scripts/restore_db.py --from backups/siem-YYYYMMDD-HHMMSS.db --force
```

Full guide: `docs/BACKUP_AND_RECOVERY.md`

---

## Project Structure

```text
Homelab_SIEM/
├── app.py                          # Flask app + API routes
├── azure_collector.py              # Azure VNet Flow Logs collector
├── azure_activity_collector.py     # Azure Activity Log collector
├── config.json                     # User configuration (git-ignored)
├── requirements.txt
├── simulate_logs.py
├── suricata.yaml
├── Dockerfile
├── docker-compose.yml
├── CHANGELOG.md
├── siem/
│   ├── collector.py                # File tailer + UDP syslog
│   ├── detector.py                 # Detection rule engine
│   ├── storage.py                  # SQLite persistence
│   ├── geoip.py                    # GeoIP lookup
│   └── notifier.py                 # Discord notifications
├── azure_siem/
│   ├── __init__.py
│   ├── azure_rules.py              # CLOUD-001..007 (Flow Logs)
│   ├── azure_activity_rules.py     # CLOUD-008..014 (Activity Log)
│   └── docs/
│       └── AZURE_INTEGRATION.md
├── scripts/
│   ├── backup_db.py
│   ├── restore_db.py
│   └── bash/
│       ├── start_siem.sh
│       ├── stop_siem.sh
│       ├── start_azure_collector.sh
│       ├── health_check.sh
│       └── log_rotation.sh
├── templates/
│   ├── dashboard.html
│   └── rules.html
├── docs/
│   ├── BACKUP_AND_RECOVERY.md
│   ├── DISCORD_GUIDE.md
│   ├── GEOIP_GUIDE.md
│   ├── RULESTATS_GUIDE.md
│   ├── SURICATA_SETUP.md
│   └── SYSLOG_GUIDE.md
├── suricata-logs/
├── suricata-rules/
└── data/
    └── siem.db
```

---

## Roadmap

- [x] Core SIEM — log collection, detection, dashboard
- [x] 12 on-premise detection rules with MITRE ATT&CK mapping
- [x] Security assessment — 100% detection rate post-remediation
- [x] GeoIP enrichment + Discord notifications
- [x] Docker Compose deployment
- [x] Rule editor + backup/recovery scripts
- [x] Azure VNet Flow Logs integration (Phase 1)
- [x] Azure Activity Log integration (Phase 2)
- [x] 14 cloud detection rules (CLOUD-001..014)
- [x] Dashboard v2.0 — modals, GeoIP, dedup, CSV export, dark mode
- [x] Bash automation scripts (WSL2 compatible)
- [ ] Microsoft Defender for Cloud integration (Phase 3)
- [ ] Kubernetes cluster monitoring (future)

---

## Learning Resources

- [MITRE ATT&CK](https://attack.mitre.org)
- [TryHackMe](https://tryhackme.com)
- [Suricata Documentation](https://suricata.readthedocs.io)
- [Azure Network Watcher](https://learn.microsoft.com/en-us/azure/network-watcher/)

---

## License

MIT — use freely, learn a lot.
