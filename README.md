# HomeLab SIEM

A lightweight, self-hosted **Security Information & Event Management** system built in pure Python.
Designed to learn cybersecurity concepts hands-on — log collection, threat detection, and a live dashboard.
Extended with full **Azure Cloud Integration** for hybrid on-premise + cloud security monitoring,
and **Kubernetes deployment** with automated CI/CD pipeline.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat&logo=flask)
![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?style=flat&logo=sqlite)
![Azure](https://img.shields.io/badge/Azure-Cloud-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Sentinel](https://img.shields.io/badge/Microsoft-Sentinel-0078D4?style=flat&logo=microsoftazure&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Multi--stage-2496ED?style=flat&logo=docker&logoColor=white)
![Kubernetes](https://img.shields.io/badge/Kubernetes-k3d-326CE5?style=flat&logo=kubernetes&logoColor=white)
![CI/CD](https://github.com/Lollobar17/Homelab_SIEM/actions/workflows/ci-cd.yml/badge.svg)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

-----

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Azure Cloud Integration](#azure-cloud-integration)
- [API Reference](#api-reference)
- [Detection Rules](#detection-rules)
- [Security Assessment](#security-assessment)
- [Configuration](#configuration)
- [Backup and Recovery](#backup-and-recovery)
- [Project Structure](#project-structure)
- [Roadmap](#roadmap)
- [License](#license)

-----

## Features

|Feature                |Details                                                                  |
|-----------------------|-------------------------------------------------------------------------|
|**Log Collection**     |Tails local files + listens on UDP syslog (port 5140)                    |
|**Log Parsing**        |SSH/auth, Apache/Nginx, Flask/Werkzeug, kernel/dmesg, syslog             |
|**Threat Detection**   |Rule engine with 41 built-in rules mapped to MITRE ATT&CK                |
|**Caldera Purple Team**|Optional sidecar — 5 rules, tactic inference, `simulate_caldera.py` tester |
|**Cloud Detection**    |Azure VNet Flow Logs + Activity Log + Microsoft Sentinel (21 cloud rules)|
|**MITRE ATT&CK**       |Every rule mapped to a technique ID                                      |
|**Dashboard**          |Live web UI — KPIs, charts, alert table, event stream, rule stats        |
|**Event Modal**        |Click any event to view full raw log, parsed fields and GeoIP            |
|**Alert Deduplication**|Grouped by rule + source IP; Discord webhook cooldown (5 min)            |
|**SQLite WAL Mode**    |Concurrent ingest without `database is locked` errors                    |
|**DB Retention**       |Auto-prune events/alerts (30-day default, configurable)                  |
|**Export CSV**         |One-click export of filtered events and alerts                           |
|**GeoIP Enrichment**   |Geographic metadata for every source IP via ip-api.com                   |
|**Discord Alerts**     |Webhook notifications for HIGH and CRITICAL alerts                       |
|**Kubernetes**         |k3d deployment with NetworkPolicy, PVC, HPA, liveness/readiness probes  |
|**CI/CD Pipeline**     |GitHub Actions — lint → build → push → rolling update → health check    |
|**Docker Multi-stage** |Non-root container, read-only filesystem, dropped capabilities           |
|**Bash Automation**    |start/stop/health-check/log-rotation scripts for WSL2 and Linux          |
|**Backup & Recovery**  |Automated SQLite backup and restore scripts                              |
|**REST API v1 Ingress**|`POST /api/v1/ingress` — structured JSON ingestion with batch support    |
|**Incident Triage**    |Alert status workflow (New → In Progress → Resolved) with analyst notes  |
|**Client-Side Charts** |`GET /api/v1/stats` + Chart.js — log volume and alert severity dashboards|

-----

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

**Option D — Kubernetes (k3d)**

```bash
k3d cluster create homelab-siem --port "30500:30500@loadbalancer"
./k8s/deploy.sh all
```

Open dashboard at `http://localhost:30500`

-----

## Architecture

```
[Local Logs]  [Azure Cloud]  [Sentinel]      [Caldera :8888]
     ↓              ↓              ↓            ↓
[collector]    [azure_*]    [sentinel_col]  [caldera_collector]
     ↓              ↓              ↓            ↓
     └──────────────┴──────────────┴────────────┘
                         ↓
           POST /api/v1/ingress (batch)  |  legacy /api/ingest
                         ↓
             [detector.py — 41 rules]
                         ↓
           [storage.py — SQLite + API]
                         ↓
           [Dashboard + Discord + CSV]
```

-----

## Kubernetes Deployment

The SIEM runs fully containerized on a k3d cluster with enterprise-grade security hardening.

### Security features

- Non-root container (UID 1000) with read-only root filesystem
- All Linux capabilities dropped (`CAP_ALL`)
- NetworkPolicy: default-deny-all, Zero Trust model
- Resource limits (CPU 500m / RAM 512Mi)
- Liveness, readiness and startup probes

### Quick deploy

```bash
# Create cluster
k3d cluster create homelab-siem \
  --port "30500:30500@loadbalancer" \
  --port "30514:30514@loadbalancer" \
  --agents 1

# Build, push and deploy
./k8s/deploy.sh all

# Check status
./k8s/deploy.sh status
```

### CI/CD pipeline

Every `git push` to `main` triggers automatically:

```
Lint + Test → Docker Build → Push Docker Hub → Rolling Update K8s → Health Check
                                                      ↓ (on failure)
                                               Auto Rollback
```

Full setup guide: `k8s/README-K8s.md`

-----

## Azure Cloud Integration

All three phases are fully operational.

### Infrastructure

|Resource          |Name                   |Type                             |
|------------------|-----------------------|---------------------------------|
|Resource Group    |homelab-siem-rg        |Azure container                  |
|Virtual Machine   |homelab-vm             |Ubuntu 24.04, D2s_v6, West Europe|
|Storage Account   |homelabsiemflow        |LRS, West Europe                 |
|Flow Log          |homelab-vm-vnet-flowlog|VNet Flow Logs v4                |
|Log Analytics     |homelab-siem-workspace |Traffic Analytics + Sentinel     |
|Diagnostic Setting|homelab-activity-logs  |Admin + Security + Policy        |
|Sentinel Workspace|homelab-siem-workspace |Connected to Defender portal     |
|Service Principal |siem-sentinel-reader   |Log Analytics Reader             |
|Sentinel Rule     |homelab-vm-start       |Scheduled KQL rule               |

### Phase 1 — VNet Flow Logs

```bash
python azure_collector.py
```

### Phase 2 — Activity Logs

```bash
python azure_activity_collector.py
```

### Phase 3 — Microsoft Sentinel

```bash
pip install msal
python sentinel_collector.py
```

Add to `config.json`:

```json
{
  "AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;...",
  "SENTINEL_TENANT_ID": "<tenant-id>",
  "SENTINEL_CLIENT_ID": "<client-id>",
  "SENTINEL_CLIENT_SECRET": "<client-secret>",
  "SENTINEL_WORKSPACE_ID": "30d15ecc-8789-401c-a9bf-4a490e22b33d"
}
```

Full setup guide: `azure_siem/docs/AZURE_INTEGRATION.md`

-----

## API Reference

|Method|Endpoint                                    |Description                                |
|------|--------------------------------------------|-------------------------------------------|
|GET   |/api/stats                                  |KPIs, timeline, top IPs (legacy)           |
|GET   |/api/v1/stats                               |Extended metrics for Chart.js dashboards   |
|GET   |/api/events?limit=N&category=cloud          |Recent events with filters                 |
|GET   |/api/alerts?limit=N&severity=HIGH&status=New|Recent alerts with triage filter           |
|PATCH |/api/v1/alerts/<id>/triage                  |Update alert status and analyst notes      |
|GET   |/api/rules                                  |All detection rules                        |
|GET   |/api/rules/stats                            |Rule effectiveness statistics              |
|GET   |/api/health                                 |Health check                               |
|POST  |/api/ingest                                 |Ingest raw log line (legacy)               |
|POST  |/api/v1/ingress                             |Structured JSON ingestion (single or batch)|
|GET   |/rules                                      |Rule Editor web UI                         |

Full walkthrough: `docs/API_V1_GUIDE.md`

-----

## Detection Rules

### On-Premise Rules (12)

|ID      |Name                              |Severity|MITRE    |
|--------|----------------------------------|--------|---------|
|AUTH-001|SSH Brute Force                   |HIGH    |T1110    |
|AUTH-002|Root Login Attempt                |HIGH    |T1110    |
|AUTH-003|Successful Root Login             |CRITICAL|T1078.003|
|AUTH-004|Sudo Privilege Escalation         |MEDIUM  |T1548.003|
|AUTH-005|SSH Brute Force — High Volume     |CRITICAL|T1110    |
|AUTH-006|Successful Login After Failures   |CRITICAL|T1110    |
|WEB-001 |HTTP Scanner / Directory Traversal|MEDIUM  |T1083    |
|WEB-002 |Web Brute Force (4xx Flood)       |MEDIUM  |T1110    |
|WEB-003 |SQL Injection Attempt             |HIGH    |T1190    |
|WEB-004 |Web Brute Force — High Volume     |CRITICAL|T1110    |
|G-001   |Generic Error Spike               |LOW     |T1499    |
|G-002   |Repeated Failed Commands          |MEDIUM  |T1059    |

### Caldera Purple Team Rules (5)

|ID    |Name                        |Severity|MITRE |
|------|----------------------------|--------|------|
|CAL-001|Caldera Operation Started  |MEDIUM  |T1059 |
|CAL-002|Lateral Movement Detected  |HIGH    |T1021 |
|CAL-003|Persistence Tactic         |HIGH    |T1098 |
|CAL-004|Command Execution          |MEDIUM  |T1059 |
|CAL-005|Exfiltration Detected      |HIGH    |T1048 |

### Cloud Rules — Azure VNet Flow Logs (7)

|ID       |Name                              |Severity|MITRE    |
|---------|----------------------------------|--------|---------|
|CLOUD-001|NSG: SSH REJECT from external IP  |HIGH    |T1110    |
|CLOUD-002|NSG: SSH Brute Force (10+ in 5min)|CRITICAL|T1110    |
|CLOUD-003|NSG: RDP Traffic Detected         |HIGH    |T1021.001|
|CLOUD-004|NSG: Port Scan Detected           |HIGH    |T1046    |
|CLOUD-005|NSG: Database Port Exposed        |CRITICAL|T1190    |
|CLOUD-006|NSG: Anomalous Outbound Volume    |HIGH    |T1048    |
|CLOUD-007|NSG: Unexpected Inbound Port      |MEDIUM  |T1133    |

### Cloud Rules — Azure Activity Log (7)

|ID       |Name                                |Severity|MITRE    |
|---------|------------------------------------|--------|---------|
|CLOUD-008|Activity: NSG Rule Modified         |HIGH    |T1562.007|
|CLOUD-009|Activity: Storage Keys Listed       |HIGH    |T1552.005|
|CLOUD-010|Activity: Diagnostic Setting Deleted|CRITICAL|T1562.008|
|CLOUD-011|Activity: New Role Assignment       |CRITICAL|T1098.003|
|CLOUD-012|Activity: VM Deleted                |CRITICAL|T1485    |
|CLOUD-013|Activity: VM Started                |MEDIUM  |T1078.004|
|CLOUD-014|Activity: API Brute Force           |HIGH    |T1110    |

### Cloud Rules — Microsoft Sentinel (7)

|ID      |Name                                  |Severity|MITRE    |
|--------|--------------------------------------|--------|---------|
|SENT-001|Sentinel: High/Critical Security Alert|HIGH    |T1078    |
|SENT-002|Sentinel: Critical Security Alert     |CRITICAL|T1078    |
|SENT-003|Sentinel: Security Incident Created   |HIGH    |T1078.004|
|SENT-004|Sentinel: Lateral Movement Detected   |CRITICAL|T1021    |
|SENT-005|Sentinel: Persistence Tactic Detected |CRITICAL|T1098    |
|SENT-006|Sentinel: Exfiltration Tactic Detected|CRITICAL|T1048    |
|SENT-007|Sentinel: Alert Storm (5+ in 5min)    |CRITICAL|T1110    |

-----

## Security Assessment

The SIEM was subjected to a structured penetration testing assessment using Nmap, Hydra, SQLmap and manual path traversal. All 7 detection gaps identified were resolved across v1.1.0 through v1.5.0.

**Detection Rate: 100%** (post-remediation)

Full assessment: [Network Security Monitoring Lab](https://github.com/Lollobar17/Network_Security_Lab)

-----

## Configuration

Edit `config.json`:

|Key                              |Default                           |Description                |
|---------------------------------|----------------------------------|---------------------------|
|`syslog_enabled`                 |true                              |Enable UDP syslog listener |
|`syslog_port`                    |5140                              |UDP syslog port            |
|`web_port`                       |5000                              |Dashboard port             |
|`discord_webhook`                |—                                 |Discord webhook URL        |
|`AZURE_STORAGE_CONNECTION_STRING`|—                                 |Azure storage credentials  |
|`AZURE_STORAGE_CONTAINER`        |insights-logs-flowlogflowevent    |Flow logs container        |
|`SIEM_INGEST_URL`                |http://localhost:5000/api/v1/ingress|SIEM batch ingest endpoint|
|`SIEM_RETENTION_DAYS`            |30                                |Auto-prune DB age (0=off)  |
|`CALDERA_URL`                    |http://127.0.0.1:8888             |Caldera REST API           |
|`CALDERA_API_KEY`                |—                                 |Caldera API key (optional) |
|`CALDERA_POLL_INTERVAL`          |120                               |Collector poll seconds     |
|`SENTINEL_TENANT_ID`             |—                                 |Azure tenant ID            |
|`SENTINEL_CLIENT_ID`             |—                                 |Service Principal client ID|
|`SENTINEL_CLIENT_SECRET`         |—                                 |Service Principal secret   |
|`SENTINEL_WORKSPACE_ID`          |—                                 |Log Analytics workspace ID |

> config.json is excluded from version control via .gitignore. Never commit credentials.

-----

## Backup and Recovery

```bash
python scripts/backup_db.py
python scripts/restore_db.py --from backups/siem-YYYYMMDD-HHMMSS.db --force
python scripts/prune_db.py              # manual retention prune
python scripts/prune_db.py --days 14    # custom retention window
```

Full guide: `docs/BACKUP_AND_RECOVERY.md`

-----

## Project Structure

```text
Homelab_SIEM/
├── app.py
├── wsgi.py                         (Gunicorn entrypoint)
├── config.json                     (git-ignored)
├── requirements.txt
├── simulate_logs.py
├── simulate_caldera.py
├── CHANGELOG.md
├── k8s/
│   ├── Dockerfile                  (multi-stage, non-root)
│   ├── docker-compose.yml          (local dev stack)
│   ├── deploy.sh                   (cluster automation)
│   ├── README-K8s.md
│   └── manifests/
│       ├── namespace.yaml
│       ├── configmap.yaml
│       ├── pvc.yaml
│       ├── deployment.yaml
│       ├── service.yaml
│       ├── networkpolicy.yaml
│       └── hpa.yaml
├── .github/
│   └── workflows/
│       ├── ci-cd.yml               (build → push → deploy)
│       └── pr-check.yml            (lint + test on PR)
├── siem/
│   ├── collector.py
│   ├── detector.py
│   ├── ingress.py
│   ├── storage.py
│   ├── geoip.py
│   ├── caldera_rules.py
│   ├── caldera_parser.py
│   └── notifier.py
├── azure_siem/
│   ├── __init__.py
│   ├── ingest_client.py
│   ├── azure_collector.py
│   ├── azure_activity_collector.py
│   ├── azure_rules.py
│   ├── azure_activity_rules.py
│   ├── sentinel/
│   │   ├── __init__.py
│   │   ├── sentinel_collector.py
│   │   └── sentinel_rules.py
│   └── docs/
│       └── AZURE_INTEGRATION.md
├── scripts/
│   ├── backup_db.py
│   ├── restore_db.py
│   ├── prune_db.py
│   ├── caldera_collector.py
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
│   ├── API_V1_GUIDE.md
│   ├── BACKUP_AND_RECOVERY.md
│   ├── DISCORD_GUIDE.md
│   ├── GEOIP_GUIDE.md
│   ├── CALDERA_INTEGRATION.md
│   ├── RULESTATS_GUIDE.md
│   ├── SETUP-CICD.md
│   ├── SURICATA_SETUP.md
│   └── SYSLOG_GUIDE.md
└── data/
    └── siem.db
```

-----

## Roadmap

- [x] Core SIEM — log collection, detection, dashboard
- [x] 12 on-premise detection rules with MITRE ATT&CK mapping
- [x] Security assessment — 100% detection rate post-remediation
- [x] GeoIP enrichment + Discord notifications
- [x] Docker Compose deployment
- [x] Rule editor + backup/recovery scripts
- [x] Azure VNet Flow Logs integration (Phase 1)
- [x] Azure Activity Log integration (Phase 2)
- [x] Microsoft Sentinel integration (Phase 3)
- [x] Dashboard v2.0/v2.1 — modals, GeoIP, dedup, CSV export, dark mode, Chart.js
- [x] REST API v1 — structured ingress, triage workflow, extended stats
- [x] Bash automation scripts (WSL2 compatible)
- [x] v2.2.0 reliability hardening (SQLite WAL, batch ingest, retention)
- [x] MITRE Caldera integration — lightweight sidecar
- [x] Kubernetes deployment — k3d, NetworkPolicy, PVC, HPA, probes
- [x] CI/CD pipeline — GitHub Actions, Docker Hub, rolling update, auto-rollback
- [ ] Collector status indicator in dashboard topbar
- [ ] Migrate SQLite → PostgreSQL (enables horizontal scaling)
- [ ] Helm chart for parametrized distribution
- [ ] Prometheus + Grafana sidecar for K8s-native metrics

-----

## Learning Resources

- [MITRE ATT&CK](https://attack.mitre.org)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Azure Network Watcher](https://learn.microsoft.com/en-us/azure/network-watcher/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [TryHackMe](https://tryhackme.com)
- [Suricata Documentation](https://suricata.readthedocs.io)

-----

## License

MIT — use freely, learn a lot.
