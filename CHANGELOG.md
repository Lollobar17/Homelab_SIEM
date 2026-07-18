# Changelog

All notable changes to HomeLab SIEM are documented in this file.
This project follows [Keep a Changelog](https://keepachangelog.com) conventions.

-----

## [3.1.0] - 2026-07-18

> Adds a didactic purple-team lab built around two lightweight telemetry agents —
> a Go agent for real host process monitoring, and a modular Nim project for
> fully synthetic, controlled detection-engineering scenarios — plus a dedicated
> correlation engine, CI job, and several CI reliability fixes.

### Added — Purple Team Lab (Go Agent & Structured Nim Lab)

- **Go telemetry agent** (`agent/`) — polls `/proc` on Linux, diffs known PIDs on
  every tick, and emits structured process-creation events (parent/child, command
  line, executable path). HTTP delivery with exponential backoff on `5xx`, no retry
  on `4xx`, matching the ingest client conventions already used elsewhere in this
  project.
- **Structured Nim lab** (`purple-team/nim/`) — a modular Nimble package (11
  single-responsibility modules: `models`, `telemetry`, `sender`, `scenarios`,
  `transform_lab`, `artifact_analysis`, `system_event_lab`, `behavior_lab`,
  `correlation_lab`, `signal_coverage`, `main`) generating fully synthetic,
  deterministic telemetry for studying detection-engineering concepts in
  isolation. 81 unit and integration tests, including two real compiled fixture
  binaries used to validate static-string analysis.
- **`purple-team/nim-loaders/loader.nim`** — a standalone single-file Nim script
  demonstrating the underlying concept behind the lab's `transform_lab`/
  `artifact_analysis` modules: an innocuous command (`uname -a`) is XOR-obfuscated
  at compile time and decoded only at runtime, illustrating the gap between static
  and behavioral analysis that the detection rules below are built to close.
- **`siem/process_rules.py`** — `PROC-001`/`PROC-002`, detecting a system
  discovery utility spawned by an unwhitelisted vs. an expected parent process
  (Go agent telemetry).
- **`siem/nim_lab_rules.py`** — `NIM-BEHAVIOR-001`/`NIM-BEHAVIOR-002`, the same
  concept adapted to the wire schema produced by the Nim lab's `behavior_lab`/
  `correlation_lab` modules. Deliberately **no** rule exists for
  `transform`/`lifecycle`/`artifact` category events — representing or
  transforming test data in bytes is not, by itself, a detection signal.
- **`siem/correlation_rules.py`** — a deliberately separate detection engine
  (not appended to `detector.py`'s per-event `RULES`) evaluating **sequences**
  of related events rather than isolated ones. `CORR-001` fires only when an
  unknown-parent process spawn is followed, within a bounded time window, by a
  discovery utility spawned from that same process — the signal comes from the
  chain, not from either event alone.
- **`integrate_purple_team_lab.sh`** — idempotent bash integrator for the entire
  lab: creates/patches the Go agent, the Nim loader, the structured Nim project,
  the three new SIEM rule modules, their tests, and the two new CI jobs below.
  Safe to re-run — every write is either a full idempotent regeneration of a
  lab-owned file, or a guarded patch that checks for an existing marker before
  touching a shared file (`detector.py`, `app.py`, the CI workflow).
- **Two new CI/CD jobs** in `ci-cd-helm.yml`:
  - `Purple Team Lab — Build & Behavioral Test` — compiles the single-file
    XOR loader and verifies, in CI, that the obfuscated string is absent from a
    static `strings` scan but present in the loader's actual runtime output.
  - `Nim Purple Team Lab — Build, Test & SIEM Integration` — `nimble build` +
    the full 81-test suite, plus a real HTTP round-trip against a mock SIEM
    ingress server to validate the agent-to-detection pipeline end-to-end.

### Fixed

- **`ModuleNotFoundError: No module named 'siem'` in CI** — bare `pytest` (as
  invoked by several CI jobs, unlike a local `python3 -m pytest`) does not add
  the repository root to `sys.path`, so `tests/*.py` could not import sibling
  packages like `siem/`. Added `pytest.ini` with `pythonpath = .` at the repo
  root, fixing every CI job's test collection uniformly regardless of how each
  one invokes `pytest`.
- **Compiled Nim binaries accidentally committed to git** — `nimble build`/
  `nimble test` produce platform-specific executables alongside their `.nim`
  sources (`purple-team/nim/main`, `purple-team/nim/tests/test_*`,
  `purple-team/nim/tests/fixtures/{plaintext,obfuscated}_sample`); a blanket
  `git add -A` picked these up before a `.gitignore` rule existed for them.
  Removed from tracking and excluded going forward.
- **`NIM-BEHAVIOR-001` never firing in practice** — the Nim lab runner
  (`main.nim`) originally sent only the aggregated `correlation.sequence_observed`
  event to the SIEM, never the individual `behavior`-category sub-events that
  the per-event rule actually matches against. `main.nim` now also emits each
  sequence sub-event standalone, in addition to the aggregated sequence,
  mirroring how the Go agent emits individual process events.

### Changed

- **Dependabot switched from a weekly to a monthly schedule** across all five
  configured ecosystems (`github-actions`, `pip`, the three `docker` directories,
  `gomod`) to reduce pull request noise on a low-traffic personal repo.
- Confirmed (via GitHub's own supported-ecosystems documentation) that
  Dependabot has **no Nim/Nimble ecosystem support** — the lab currently has no
  external Nimble dependencies (standard library only), but this is a known
  limitation to keep in mind if any are added later.

### Documentation

- **README** — new [Purple Team Lab](README.md#purple-team-lab--go-agent--structured-nim-lab)
  section with two Mermaid diagrams (agent-to-detection data pipeline, and the
  lab-specific CI/CD jobs), a dedicated detection-rules table, updated
  `Architecture` ASCII diagram, `Project Structure` tree, and five new
  `Troubleshooting` entries.

-----

## [3.0.0] - 2026-07-10

> [!IMPORTANT]
> Major infrastructure migration: from a local k3d cluster to a real cloud-native
> deployment on Oracle Cloud Infrastructure (OCI), with a parametrized Helm chart,
> runtime security monitoring via Falco, a decentralized C2 emulator (ArachneC2)
> for purple-team testing, a finalized Prometheus + Grafana observability stack,
> and an optional PostgreSQL backend for horizontal scaling.

### Added — Cloud Infrastructure & CI/CD

- **Oracle Cloud VM Provisioner** (`.github/workflows/oracle-vm-provisioner.yml`) —
  idempotent GitHub Actions workflow that provisions and maintains an OCI Always
  Free ARM instance (`VM.Standard.A1.Flex`). Falls back to `VM.Standard.A2.Flex`
  and downgrades in place when A1 capacity is exhausted region-wide, with
  automatic retry (handles transient 409 conflicts during the downgrade) and an
  idempotency check so the hourly cron never creates duplicate instances once
  provisioning has succeeded.
- **k3s** installed natively on the OCI VM (replacing k3d-in-Docker) — no nested
  virtualization, resolving the WSL2 stability issues that affected the previous
  local cluster.
- **CI/CD pipeline rebuilt** (`ci-cd.yml`) — GitHub-hosted runners (previously
  self-hosted, unsuitable for a public repo) connect to the VM over SSH using a
  dedicated deploy key; `environment: production` requires manual approval before
  every deploy; automatic rollback via `helm rollback` on failure; smart Docker
  tagging (branch/semver/sha) via `docker/metadata-action`.
- **Parametrized Helm chart** (`k8s/homelab-siem-chart/`) replacing static
  manifests — SIEM, Falco collector, optional PostgreSQL, `ServiceMonitor` and
  Grafana dashboard all templated behind a single `values.yaml`. Legacy static
  manifests preserved under `k8s/legacy-manifests/` for historical reference.

### Added — Runtime Security (Falco)

- **Falco** (eBPF, modern probe) deployed via Helm for kernel-level runtime
  security monitoring across all containers on the node.
- **`scripts/falco_collector.py`** — lightweight webhook bridge that normalizes
  Falco JSON alerts, maps them to MITRE ATT&CK techniques, and batches them into
  `/api/v1/ingress`.
- Custom Falco rules for ArachneC2 beacon and lateral-movement network patterns,
  complementing the SIEM-side `ARC-*` detection rules at the kernel/syscall layer.

### Added — ArachneC2 Purple Team Simulator

- **`arachne/`** — a decentralized C2 implant simulator written in Go, using
  libp2p for peer-to-peer communication: Kademlia DHT peer discovery, GossipSub
  message propagation, NAT hole-punching and circuit relay. Simulates beaconing,
  lateral movement, and chunked data exfiltration for detection-engineering
  practice against non-trivial, decentralized C2 infrastructure (not just a
  classic client-server beacon).
- **`siem/arachne_rules.py`** — 14 detection rules (ARC-001 through ARC-014)
  covering C2 beaconing, domain fronting/Host header spoofing, encrypted and
  signed channels (NaCl/Ed25519), DHT discovery, GossipSub propagation, NAT
  traversal and relay usage, P2P heartbeats, lateral movement, and chunked/
  encrypted exfiltration.
- **`scripts/arachne_collector.py`** — JSONL log tailer that normalizes
  ArachneC2 events by type (beacon, peer communication, exfiltration) and
  batches them into `/api/v1/ingress`.

### Added — Observability

- **Prometheus + Grafana finalized** via the `kube-prometheus-stack` Helm chart,
  superseding the earlier Docker Compose monitoring stack (retained only as
  historical reference under `monitoring/`).
- **`ServiceMonitor`** for automatic discovery of the SIEM `/metrics` endpoint
  across namespaces.
- **Dedicated Grafana dashboard** ("HomeLab SIEM — Overview") provisioned
  automatically via a labeled ConfigMap (sidecar auto-discovery, no manual
  import) — events ingested, alerts by severity/rule ID, HTTP latency (p95),
  pod CPU/memory.
- **Fixed**: `siem_events_total` and `siem_ingest_requests_total` Prometheus
  counters were defined but never incremented anywhere in `app.py`; wired into
  both the legacy `/api/ingest` and the `/api/v1/ingress` endpoints.
- **Collector status indicator** in the dashboard topbar — new
  `/api/v1/collectors/status` endpoint reports per-collector health (file
  tailers, syslog listener); topbar badge turns green/yellow/red based on
  live status, with a per-collector tooltip.

### Added — PostgreSQL Support (opt-in, not active in production by default)

- **`siem/storage.py` rewritten** for dual-backend support — selected via
  `SIEM_DB_BACKEND=sqlite` (default) or `postgres`. Public function signatures
  are identical across both backends; no changes required in `app.py` or
  `detector.py`.
- PostgreSQL deployable directly via the Helm chart (`postgres.enabled=true`) —
  Deployment, PVC, Secret and the required NetworkPolicy rules are all templated.
- Enables genuine horizontal scaling (`HorizontalPodAutoscaler` up to 3 replicas)
  once activated. **SQLite remains the default and is not safe to scale beyond
  1 replica** — multiple pods writing to the same `ReadWriteOnce` PVC file risks
  database corruption, not just a handled error. This constraint is documented
  directly in `values.yaml`.

### Fixed

- **Postgres idle-in-transaction lock pileup** — psycopg2 connections now use
  `autocommit=True`. Previously, every plain `SELECT` left an implicit
  transaction open (psycopg2 defaults to `autocommit=False`, unlike `sqlite3`),
  which held locks and blocked concurrent `CREATE TABLE`/`ALTER TABLE` statements
  from other threads or pods during startup.
- **Postgres startup race condition** — the connection pool is now created
  lazily on first real use, with retry/backoff (up to 60s), instead of
  connecting eagerly at module import time. Previously, if the SIEM pod started
  before Postgres was accepting connections, the entire process crashed at
  import instead of waiting.
- **`RealDictCursor` incompatibility** — `get_stats()` used positional row
  indexing (`fetchone()[0]`), which fails against
  `psycopg2.extras.RealDictCursor` (`KeyError: 0`); switched to named-column
  access (`fetchone()["cnt"]`), compatible with both backends.
- **OCI provisioning workflow** — fixed missing `fingerprint` in the OCI CLI
  config (caused silent authentication failures), SSH key format validation
  (embedded newlines from copy-paste broke the OCI API's strict format check),
  and a transient `409 Conflict` during the A2→A1 shape downgrade (now retried
  automatically with backoff).
- **Falco custom rules** — `fd.sip`/`fd.dport` were semantically incorrect for
  CIDR-range and server-port matching; corrected to `fd.snet` (subnet-type
  field, required for matching against CIDR lists) and `fd.sport` (Falco's
  "server port" convention, which for outbound connections *is* the
  destination port — not a source-port bug as initially assumed).
- **Falco driver deprecation** — `driver.kind: ebpf` (legacy probe) was removed
  in recent Falco Helm chart versions; migrated to `driver.kind: modern_ebpf`.

### Changed

- Quick Start "Option D — Kubernetes" now documents the Helm chart deployment
  path against the OCI/k3s cluster instead of local k3d.
- Roadmap updated: collector status indicator, Helm chart, and Prometheus/
  Grafana sidecar are now marked complete; PostgreSQL migration marked
  complete-but-opt-in (see above).

### Infrastructure

| Component | Before (v2.4.0) | Now (v3.0.0) |
|---|---|---|
| Cluster | k3d on WSL2 (local) | k3s on Oracle Cloud (OCI, ARM64, Always Free) |
| Deploy mechanism | Self-hosted runner, direct `kubectl` | GitHub-hosted runner via SSH + Helm |
| Manifests | Static YAML | Parametrized Helm chart |
| Database | SQLite only | SQLite (default) or PostgreSQL (opt-in) |
| Runtime security | — | Falco (eBPF) |
| Purple team | Caldera only | Caldera + ArachneC2 (decentralized C2 emulator) |
| Observability | Manual Docker Compose stack | `kube-prometheus-stack` (Helm), auto-discovered dashboards |

-----

## [2.4.0] - 2026-06-10

> Kubernetes deployment and CI/CD pipeline — the SIEM is now fully containerized
> and deployable on a k3d cluster with automated build, push, and rolling update
> via GitHub Actions.

### Added

- **Multi-stage Dockerfile** (`k8s/Dockerfile`) — builder + runtime stages;
  non-root user (`siem:siem`, UID 1000); `readOnlyRootFilesystem`; drops all
  Linux capabilities. Final image ~63 MB.
- **K8s manifests** (`k8s/manifests/`) — full namespace-isolated deployment:
  - `namespace.yaml` — dedicated `homelab-siem` namespace.
  - `configmap.yaml` — runtime config and env injection.
  - `pvc.yaml` — 1 Gi `ReadWriteOnce` PersistentVolumeClaim for SQLite.
  - `deployment.yaml` — liveness, readiness and startup probes; emptyDir
    volumes for `/app/logs` and `/tmp`; resource requests/limits.
  - `service.yaml` — NodePort `:30500` (HTTP) and `:30514` (syslog UDP).
  - `networkpolicy.yaml` — default-deny-all + minimal allow rules (Zero Trust).
  - `hpa.yaml` — HorizontalPodAutoscaler (min 1, max 3 replicas; ready for
    PostgreSQL migration).
- **`k8s/deploy.sh`** — automation script: `build`, `deploy`, `all`, `status`,
  `logs`, `teardown`. Auto-detects k3s / k3d / minikube / kind.
- **`k8s/docker-compose.yml`** — local dev stack for pre-K8s testing.
- **CI/CD pipeline** (`.github/workflows/ci-cd.yml`) — three-job cascade:
  1. Lint (flake8) + smoke test on every push.
  2. Docker multi-arch build (amd64 + arm64) + push to Docker Hub on `main`/tag.
  3. `kubectl set image` rolling update + health check + auto-rollback on failure.
- **PR check workflow** (`.github/workflows/pr-check.yml`) — lint + test +
  Docker build (no push) on every pull request to `main`.
- **`k8s/README-K8s.md`** — full setup and operations guide for the K8s deployment.

### Security

- Container runs as non-root with read-only root filesystem.
- NetworkPolicy enforces Zero Trust: all traffic denied by default,
  only HTTP `:5000` and syslog UDP `:5140` explicitly allowed.
- All Linux capabilities dropped (`CAP_ALL`).
- Docker Hub credentials stored as GitHub Secrets (Access Token, not password).

### Infrastructure

| Component | Technology |
|---|---|
| Container runtime | Docker (multi-stage) |
| Orchestration | Kubernetes via k3d (WSL2) |
| Image registry | Docker Hub (`lollobar17/homelab-siem`) |
| CI/CD | GitHub Actions |
| Persistence | PVC → SQLite (1 Gi) |

### Tested on

- k3d v5.x on WSL2 (Ubuntu, kernel 6.6.114 Microsoft Standard)
- Self-healing verified: pod deletion → automatic restart → dashboard recovery

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
  and normalization. Supports single events and batch payloads (max 100).
- **`siem/ingress.py`** — dedicated ingress module for payload validation,
  IP/timestamp normalization and category inference before SQLite insert.
- **Incident case management (triage)** — `status` and `analyst_notes` columns
  on the `alerts` table (auto-migrated on startup).
- **`PATCH /api/v1/alerts/<id>/triage`** — update triage fields via AJAX.
- **`GET /api/v1/stats`** — extended aggregated metrics.
- **Dashboard charts (v2.1)** — Chart.js line and doughnut charts.

### Changed

- **`siem/detector.py`** — appends `SENTINEL_RULES` to the main `RULES` list.
- **`requirements.txt`** — added `msal>=1.0`.

-----

## [2.0.0] - 2026-06-02

> [!IMPORTANT]
> This release introduces full Azure Cloud Integration (Phase 1 & 2),
> extending the HomeLab SIEM from a local-only system to a hybrid
> on-premise + cloud security monitoring platform.

### Added

- **Azure VNet Flow Logs collector** (`azure_collector.py`)
- **Azure Activity Log collector** (`azure_activity_collector.py`)
- **7 Cloud detection rules** (`azure_siem/azure_rules.py`) — CLOUD-001 through CLOUD-007.
- **7 Activity Log detection rules** (`azure_siem/azure_activity_rules.py`) — CLOUD-008 through CLOUD-014.
- **`azure_siem/` package** — dedicated Azure integration package.
- **Bash automation scripts** (`scripts/bash/`) — WSL2 compatible.
- **Dashboard v2.0** — event/alert modals, GeoIP, dedup, CSV export, dark mode.

-----

## [1.5.0] - 2026-05-03

### Added

- Suricata integration — live eve.json ingestion
- Rate limiting on log ingestion
- Backup and recovery scripts

### Changed

- Lab environment migrated from VirtualBox to WSL2 + Docker

-----

## [1.4.0] - 2026-04-30

### Added

- Rule Editor web UI at /rules
- /api/rules/stats endpoint
- Dockerfile and docker-compose.yml

-----

## [1.3.0] - 2026-04-24

### Added

- siem/geoip.py — GeoIP lookup via ip-api.com with lru_cache
- siem/notifier.py — Discord webhook notifications

-----

## [1.2.0] - 2026-03-28

### Added

- AUTH-005, AUTH-006, WEB-004 detection rules
- Flask/Werkzeug access log parser

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
