# Changelog

All notable changes to HomeLab SIEM are documented in this file.
This project follows [Keep a Changelog](https://keepachangelog.com) conventions.

-----

## [2.3.1] - 2026-06-08

> Caldera integration refinements — smarter parsing, five rules, CPU savings,
> dashboard purple filters, and offline simulator.

### Added

- **`siem/caldera_parser.py`** — shared normalizer with tactic inference from
  technique IDs and ability names; skips empty heartbeat records.
- **`simulate_caldera.py`** — test all CAL-* rules without a live Caldera server.
- **CAL-004** (command execution) and **CAL-005** (exfiltration) rules.
- **Dashboard** — Purple filter buttons on Events and Alerts tabs.
- **`purple_team_events`** counter in `GET /api/stats`.

### Changed

- **`detector.py`** — Caldera rules evaluated only for Caldera events (saves CPU
  on auth/web traffic); dynamic MITRE on CAL-001; no GeoIP/Discord for purple team.
- **`caldera_collector.py`** — polls recently finished ops (10 min grace), atomic
  state writes, exponential backoff, `CALDERA_DETECT` toggle, ingest stats.
- **Health check** — probes Caldera API when `CALDERA_API_KEY` is configured.

-----

## [2.3.0] - 2026-06-08

> Lightweight MITRE Caldera purple-team integration — sidecar collector,
> three detection rules, no extra dependencies or Docker services.

### Added

- **`scripts/caldera_collector.py`** — minimal poll bridge to Caldera REST API.
  Polls only `running` operations, bounded 500-ID dedup cache, batch v1 ingress.
  Defaults: 120s interval, max 2 ops × 25 events per cycle.
- **`siem/caldera_rules.py`** — CAL-001 (MEDIUM), CAL-002 lateral (HIGH),
  CAL-003 persistence (HIGH). String checks only — no counters or regex.
- **`--with-caldera` / `--no-caldera`** flags in `start_siem.sh`; auto-start
  when `CALDERA_API_KEY` is present in `config.json`.
- **`docs/CALDERA_INTEGRATION.md`** — lightweight setup and tuning guide.

### Changed

- **`siem/detector.py`** — appends `CALDERA_RULES` (39 total rules).
- **`siem/ingress.py`** — infers `purple_team` category from Caldera event types.
- **Bash scripts** — `stop_siem.sh` and `health_check.sh` include Caldera PID.

### Configuration

```json
{
  "CALDERA_URL": "http://127.0.0.1:8888",
  "CALDERA_API_KEY": "<from conf/local.yml>",
  "CALDERA_POLL_INTERVAL": 120
}
```

-----

## [2.2.0] - 2026-06-08

> [!IMPORTANT]
> Reliability and performance hardening release. Addresses SQLite concurrency,
> Azure ingest data loss, detection-engine accuracy, and Docker deployment gaps.
> Default cloud collector ingest endpoint is now `/api/v1/ingress` (batch).

### Fixed — P0 Critical

- **SQLite write contention** — `siem/storage.py` enables WAL mode,
  `busy_timeout=30000`, and a process-wide write lock. Prevents
  `database is locked` under concurrent syslog + API ingestion.
- **Docker image missing Azure package** — `Dockerfile` now copies
  `azure_siem/` and uses Gunicorn via `wsgi.py` (single worker so in-process
  collectors remain safe).
- **Azure blob partial-failure data loss** — flow and activity collectors only
  mark blobs as processed when **all** events ingest successfully; failed
  blobs are retried on the next poll.

### Fixed — P1 High

- **24-hour chart queries** — `get_stats()` / `get_v1_stats()` normalize ISO
  timestamps before `julianday()` comparison so Chart.js hourly buckets are accurate.
- **WEB-002 / WEB-004 double counting** — rate counters record each event once
  per `analyze_event()` pass (shared `_recorded_keys` set).
- **GeoIP pipeline blocking** — lookups run only when a rule fires; rate-limited
  to ~40 req/min (under ip-api.com free tier).
- **Discord notification storm** — 5-minute dedup cache per `(rule_id, source_ip)`.

### Fixed — P2 Medium

- **Azure batch ingest** — new `azure_siem/ingest_client.py` posts up to 100
  events per request to `/api/v1/ingress`. Applied to flow, activity, and
  Sentinel collectors.
- **Bash collector paths** — `start_siem.sh` and `start_azure_collector.sh`
  reference `azure_siem/` module paths correctly.
- **Log rotation blind spot** — `LogFileTailer` detects file truncation and
  re-seeks to offset 0 after `log_rotation.sh`.
- **Counter memory leak** — empty sliding-window keys are removed from
  `_counters` and `_azure_counters`.

### Fixed — P3 Low

- **Unbounded API `limit`** — `/api/events` and `/api/alerts` clamp to 1000 max.
- **Database retention** — `prune_old_data()` deletes rows older than
  `SIEM_RETENTION_DAYS` (default 30). Runs on startup; `scripts/prune_db.py`
  for cron.
- **Dashboard dedup key** — alerts grouped by `rule_id|source_ip` (was rule-only).
- **`/api/ingest` validation** — `raw` capped at 16 KB; `_pre_parsed` schema checked.

### Added

- **`wsgi.py`** — Gunicorn entrypoint with `bootstrap_background_services()`.
- **`scripts/prune_db.py`** — standalone retention prune for cron.
- **`docs/CALDERA_INTEGRATION.md`** — MITRE Caldera purple-team integration guide.

### Changed

- Default `SIEM_INGEST_URL` for Azure/Sentinel collectors:
  `http://localhost:5000/api/v1/ingress`
- `Dockerfile` version label → 2.2.0; `SIEM_RETENTION_DAYS=30` env default.

### Configuration

| Key / Env | Default | Description |
|-----------|---------|-------------|
| `SIEM_RETENTION_DAYS` | `30` | Auto-prune events/alerts on startup (`0` = disable) |
| `SIEM_INGEST_URL` | `/api/v1/ingress` | Batch endpoint for cloud collectors |

-----

## [2.1.0] - 2026-06-07

> [!IMPORTANT]
> This release completes the Azure Cloud Integration with Phase 3 (Microsoft Sentinel)
> and introduces a versioned REST API v1 with structured log ingestion,
> incident triage workflow, and client-side Chart.js dashboards.

### Added — Phase 3: Microsoft Sentinel

- **Microsoft Sentinel collector** (`sentinel_collector.py`) — queries the
  Log Analytics workspace via REST API using KQL. Retrieves SecurityAlert
  and SecurityIncident tables and forwards structured events to `/api/ingest`.
  Authentication via MSAL client credentials flow (Service Principal).
- **7 Sentinel detection rules** (`azure_siem/sentinel/sentinel_rules.py`) —
  SENT-001 through SENT-007 covering HIGH/CRITICAL alerts, incidents,
  lateral movement, persistence, exfiltration tactics and alert storms.
- **`azure_siem/sentinel/` subpackage** — dedicated module for all
  Sentinel integration components.
- **Sentinel scheduled rule** (`homelab-vm-start`) — KQL scheduled analytics
  rule in Sentinel detecting VM start events from AzureActivity logs.
  Created via Azure REST API using PowerShell.
- **Service Principal** (`siem-sentinel-reader`) — Azure App Registration
  with Log Analytics Reader role on the workspace.

### Added — REST API v1

- **`POST /api/v1/ingress`** — structured JSON log ingestion with field validation
  and normalization (`timestamp`, `source_ip`, `destination_ip`, `event_type`,
  `severity`, `message`). Supports single events and batch payloads (max 100).
  Optional `"detect": false` skips the rule engine for archival-only ingestion.
- **`siem/ingress.py`** — dedicated ingress module for payload validation,
  IP/timestamp normalization and category inference before SQLite insert.
- **Incident case management (triage)** — `status` and `analyst_notes` columns
  on the `alerts` table (auto-migrated on startup). Valid statuses:
  New, In Progress, Resolved, False Positive.
- **`PATCH /api/v1/alerts/<id>/triage`** — update triage fields via AJAX
  without page reload. Dashboard alert modal includes status dropdown,
  notes textarea and save button.
- **`GET /api/v1/stats`** — extended aggregated metrics: log volume by hour,
  alert distribution by severity, MITRE ATT&CK counts, triage status breakdown.
- **Dashboard charts (v2.1)** — overview line chart for log volume (last 24h)
  and doughnut chart for alert severity distribution rendered via Chart.js.
- **`docs/API_V1_GUIDE.md`** — full setup and usage guide for ingress,
  triage and stats APIs.

### Changed

- **`siem/detector.py`** — appends `SENTINEL_RULES` to the main `RULES` list.
- **`GET /api/alerts`** — added optional `?status=` filter for triage workflow.
- **`siem/storage.py`** — `get_v1_stats()`, `update_alert_triage()`, indexed `alerts.status`.
- **`app.py`** — `MAX_CONTENT_LENGTH` set to 512 KB on ingress payloads.
- **`requirements.txt`** — added `msal>=1.0`.
- **Bash scripts** — `start_siem.sh`, `stop_siem.sh`, `health_check.sh` updated
  for Sentinel collector PID management.

### Sentinel configuration

Add to `config.json`:

```json
{
  "SENTINEL_TENANT_ID": "<your-tenant-id>",
  "SENTINEL_CLIENT_ID": "<app-registration-client-id>",
  "SENTINEL_CLIENT_SECRET": "<client-secret-value>",
  "SENTINEL_WORKSPACE_ID": "30d15ecc-8789-401c-a9bf-4a490e22b33d"
}
```

### Detection Rules — v2.1.0 additions

|ID      |Name                                  |Severity|MITRE    |Source  |
|--------|--------------------------------------|--------|---------|--------|
|SENT-001|Sentinel: High/Critical Security Alert|HIGH    |T1078    |Sentinel|
|SENT-002|Sentinel: Critical Security Alert     |CRITICAL|T1078    |Sentinel|
|SENT-003|Sentinel: Security Incident Created   |HIGH    |T1078.004|Sentinel|
|SENT-004|Sentinel: Lateral Movement Detected   |CRITICAL|T1021    |Sentinel|
|SENT-005|Sentinel: Persistence Tactic Detected |CRITICAL|T1098    |Sentinel|
|SENT-006|Sentinel: Exfiltration Tactic Detected|CRITICAL|T1048    |Sentinel|
|SENT-007|Sentinel: Alert Storm (5+ in 5min)    |CRITICAL|T1110    |Sentinel|

-----

## [2.0.0] - 2026-06-02

> [!IMPORTANT]
> This release introduces full Azure Cloud Integration (Phase 1 & 2),
> extending the HomeLab SIEM from a local-only system to a hybrid
> on-premise + cloud security monitoring platform.

### Added

- **Azure VNet Flow Logs collector** (`azure_collector.py`) — polls Azure Blob Storage
  every 60 seconds for NSG/VNet Flow Log blobs (flowLogVersion 4).
- **Azure Activity Log collector** (`azure_activity_collector.py`) — polls
  `insights-activity-logs` container for NDJSON activity records.
- **7 Cloud detection rules** (`azure_siem/azure_rules.py`) — CLOUD-001 through CLOUD-007.
- **7 Activity Log detection rules** (`azure_siem/azure_activity_rules.py`) — CLOUD-008 through CLOUD-014.
- **`azure_siem/` package** — dedicated Azure integration package.
- **`/api/ingest` patch** — `_pre_parsed` field support.
- **Bash automation scripts** (`scripts/bash/`) — WSL2 compatible.
- **Dashboard v2.0** — event/alert modals, GeoIP, dedup, CSV export, dark mode.
- **Azure VM** `homelab-vm`, **Storage Account** `homelabsiemflow`,
  **VNet Flow Log**, **Diagnostic Setting** `homelab-activity-logs`.

### Changed

- `siem/detector.py` — appends AZURE_RULES and AZURE_ACTIVITY_RULES.
- `requirements.txt` — added `azure-storage-blob>=12.0`.

-----

## [1.5.0] - 2026-05-03

### Added

- Suricata integration — live eve.json ingestion
- Rate limiting on log ingestion
- Backup and recovery scripts
- docs/BACKUP_AND_RECOVERY.md, docs/SURICATA_SETUP.md, docs/RULESTATS_GUIDE.md

### Changed

- Lab environment migrated from VirtualBox to WSL2 + Docker

-----

## [1.4.0] - 2026-04-30

### Added

- Rule Editor web UI at /rules
- /api/rules/stats endpoint
- Dockerfile and docker-compose.yml
- docs/DISCORD_GUIDE.md, docs/GEOIP_GUIDE.md, docs/SYSLOG_GUIDE.md

-----

## [1.3.0] - 2026-04-24

### Added

- siem/geoip.py — GeoIP lookup via ip-api.com with lru_cache
- siem/notifier.py — Discord webhook notifications
- geo field added to all alerts

-----

## [1.2.0] - 2026-03-28

### Added

- AUTH-005, AUTH-006, WEB-004 detection rules
- Flask/Werkzeug access log parser
- ANSI escape code stripping

### Changed

- source_ip added to all generated alerts
- Database auto-migration on startup

-----

## [1.1.0] - 2026-03-26

### Changed

- AUTH-002 MITRE classification updated to T1110
- CHANGELOG.md added

-----

## [1.0.0] - 2026-03-01

### Added

- Log collection via file tailers and UDP syslog
- Rule engine with 8 detection rules mapped to MITRE ATT&CK
- Live web dashboard
- REST API
- SQLite persistence

-----

## Versioning

- MAJOR — breaking changes to API or architecture
- MINOR — new features or detection rules
- PATCH — bug fixes and minor improvements