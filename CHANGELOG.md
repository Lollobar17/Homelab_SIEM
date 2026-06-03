# Changelog

All notable changes to HomeLab SIEM are documented in this file.
This project follows [Keep a Changelog](https://keepachangelog.com) conventions.

---

## [2.0.0] - 2026-06-02

> [!IMPORTANT]
> This release introduces full Azure Cloud Integration (Phase 1 & 2),
> extending the HomeLab SIEM from a local-only system to a hybrid
> on-premise + cloud security monitoring platform.

### Added

- **Azure VNet Flow Logs collector** (`azure_collector.py`) — polls Azure Blob Storage
  every 60 seconds for NSG/VNet Flow Log blobs (flowLogVersion 4) and forwards
  structured events to `/api/ingest`. Supports both ACCEPT and REJECT flows with
  INBOUND/OUTBOUND direction tracking.

- **Azure Activity Log collector** (`azure_activity_collector.py`) — polls
  `insights-activity-logs` container for NDJSON activity records. Parses
  Administrative, Security and Policy categories with caller identity extraction.

- **7 Cloud detection rules** (`azure_siem/azure_rules.py`) — CLOUD-001 through
  CLOUD-007 covering SSH brute force, RDP exposure, port scanning, database port
  exposure, anomalous outbound volume and unexpected inbound ports.

- **7 Activity Log detection rules** (`azure_siem/azure_activity_rules.py`) —
  CLOUD-008 through CLOUD-014 covering NSG modifications, storage key access,
  diagnostic log tampering, role assignment, VM deletion, VM start and API brute force.

- **`azure_siem/` package** — dedicated package for all Azure cloud integration
  components: collectors, rules and documentation.

- **`/api/ingest` patch** — added `_pre_parsed` field support to bypass re-parsing
  for pre-structured events from cloud collectors.

- **Bash automation scripts** (`scripts/bash/`) — `start_siem.sh`, `stop_siem.sh`,
  `health_check.sh`, `log_rotation.sh`, `start_azure_collector.sh`.
  All scripts support WSL2, Linux and Windows Git Bash environments.

- **Dashboard v2.0** — major UI update:
  - Click-to-expand event modal with full raw log, parsed fields and GeoIP
  - Click-to-expand alert modal with rule description and MITRE ATT&CK
  - GeoIP enrichment inline in event modal (country flag, city, ISP, org)
  - Alert deduplication — identical rule alerts grouped with `×N` badge
  - Alert timeline chart (line graph, last 24h)
  - Export to CSV for both Events and Alerts
  - Search bar with real-time filtering in Events and Alerts
  - Cloud category filter button in Events tab
  - Dark/Light mode toggle with localStorage persistence
  - Copy Raw button in event modal

- **Azure VM** (`homelab-vm`) — Standard_D2s_v6, Ubuntu 24.04, West Europe.
  Used as traffic target for realistic NSG Flow Log generation.

- **Azure Storage Account** (`homelabsiemflow`) — LRS, West Europe.
  Destination for VNet Flow Logs and Activity Logs.

- **Azure Network Watcher Flow Log** — VNet-level flow logging with
  Traffic Analytics enabled via `homelab-siem-workspace` Log Analytics workspace.

- **Azure Diagnostic Setting** (`homelab-activity-logs`) — exports Administrative,
  Security and Policy activity logs to storage account.

### Changed

- **`siem/detector.py`** — appends `AZURE_RULES` and `AZURE_ACTIVITY_RULES`
  to the main `RULES` list at startup.

- **`requirements.txt`** — added `azure-storage-blob>=12.0`.

### Detection Rules — v2.0.0

| ID | Name | Severity | MITRE | Source |
|---|---|---|---|---|
| AUTH-001 | SSH Brute Force | HIGH | T1110 | auth.log |
| AUTH-002 | Root Login Attempt | HIGH | T1110 | auth.log |
| AUTH-003 | Successful Root Login | CRITICAL | T1078.003 | auth.log |
| AUTH-004 | Sudo Privilege Escalation | MEDIUM | T1548.003 | auth.log |
| AUTH-005 | SSH Brute Force High Volume | CRITICAL | T1110 | auth.log |
| AUTH-006 | Successful Login After Failures | CRITICAL | T1110 | auth.log |
| WEB-001 | HTTP Scanner / Directory Traversal | MEDIUM | T1083 | access.log |
| WEB-002 | Web Brute Force (4xx Flood) | MEDIUM | T1110 | access.log |
| WEB-003 | SQL Injection Attempt | HIGH | T1190 | access.log |
| WEB-004 | Web Brute Force High Volume | CRITICAL | T1110 | access.log |
| SYS-001 | OOM Killer Activated | MEDIUM | — | kernel |
| SYS-002 | Segmentation Fault | LOW | — | kernel |
| CLOUD-001 | VPC: SSH REJECT from external IP | HIGH | T1110 | Azure VNet |
| CLOUD-002 | VPC: SSH Brute Force (10+ in 5min) | CRITICAL | T1110 | Azure VNet |
| CLOUD-003 | VPC: RDP Traffic Detected | HIGH | T1021.001 | Azure VNet |
| CLOUD-004 | VPC: Port Scan Detected | HIGH | T1046 | Azure VNet |
| CLOUD-005 | VPC: Database Port Exposed | CRITICAL | T1190 | Azure VNet |
| CLOUD-006 | VPC: Anomalous Outbound Volume | HIGH | T1048 | Azure VNet |
| CLOUD-007 | VPC: Unexpected Inbound Port | MEDIUM | T1133 | Azure VNet |
| CLOUD-008 | Activity: NSG Rule Modified | HIGH | T1562.007 | Activity Log |
| CLOUD-009 | Activity: Storage Keys Listed | HIGH | T1552.005 | Activity Log |
| CLOUD-010 | Activity: Diagnostic Setting Deleted | CRITICAL | T1562.008 | Activity Log |
| CLOUD-011 | Activity: New Role Assignment | CRITICAL | T1098.003 | Activity Log |
| CLOUD-012 | Activity: VM Deleted | CRITICAL | T1485 | Activity Log |
| CLOUD-013 | Activity: VM Started | MEDIUM | T1078.004 | Activity Log |
| CLOUD-014 | Activity: API Brute Force | HIGH | T1110 | Activity Log |

---

## [1.5.0] - 2026-05-03

> [!IMPORTANT]
> This release completes the HomeLab SIEM feature roadmap.
> All 7 detection gaps from the penetration testing assessment are now resolved.

### Added

- **Suricata integration** — live eve.json ingestion via suricata-logs/ directory
- **Rate limiting** on log ingestion
- **Backup and recovery scripts** — scripts/backup_db.py and scripts/restore_db.py
- **docs/BACKUP_AND_RECOVERY.md**, **docs/SURICATA_SETUP.md**, **docs/RULESTATS_GUIDE.md**

### Changed

- **/api/ingest** — updated to support filtering by source parameter
- **Lab environment** migrated from VirtualBox to WSL2 + Docker

---

## [1.4.0] - 2026-04-30

### Added

- **Rule Editor** — web UI at /rules
- **/api/rules/stats** endpoint
- **Dockerfile** and **docker-compose.yml**
- **docs/DISCORD_GUIDE.md**, **docs/GEOIP_GUIDE.md**, **docs/SYSLOG_GUIDE.md**

---

## [1.3.0] - 2026-04-24

### Added

- **siem/geoip.py** — GeoIP lookup via ip-api.com with lru_cache
- **siem/notifier.py** — Discord webhook notifications with rich embeds
- **geo field** added to all alerts

---

## [1.2.0] - 2026-03-28

### Added

- AUTH-005, AUTH-006, WEB-004 detection rules
- Flask/Werkzeug access log parser
- ANSI escape code stripping

### Changed

- source_ip added to all generated alerts
- Database auto-migration on startup

---

## [1.1.0] - 2026-03-26

### Added

- CHANGELOG.md
- Security Assessment section in README

### Changed

- AUTH-002 MITRE classification updated to T1110

---

## [1.0.0] - 2026-03-01

### Added

- Log collection via file tailers and UDP syslog
- Rule engine with 8 detection rules mapped to MITRE ATT&CK
- Live web dashboard
- REST API
- SQLite persistence

---

## Versioning

- MAJOR — breaking changes to API or architecture
- MINOR — new features or detection rules
- PATCH — bug fixes and minor improvements
