# MITRE Caldera Integration (Lightweight)

Purple-team bridge optimized for **low CPU, RAM, and network** on homelab hardware.

## Architecture

```
[Caldera :8888]  ← external (not bundled in SIEM Docker)
       │  poll every 120s (idle = 1 HTTP GET)
       ▼
[caldera_collector.py] ──batch──► POST /api/v1/ingress
       ▼
[caldera_parser.py]  normalize + infer tactics
       ▼
[caldera_rules.py]   CAL-001…005 (only if source=caldera)
```

## Quick Start

### 1. Configure

```json
{
  "CALDERA_URL": "http://127.0.0.1:8888",
  "CALDERA_API_KEY": "ADMIN123",
  "CALDERA_POLL_INTERVAL": 120,
  "CALDERA_DETECT": true,
  "SIEM_INGEST_URL": "http://localhost:5000/api/v1/ingress"
}
```

| Key | Default | Purpose |
|-----|---------|---------|
| `CALDERA_POLL_INTERVAL` | `120` | Seconds between polls |
| `CALDERA_MAX_OPS` | `2` | Max operations per cycle |
| `CALDERA_MAX_EVENTS` | `25` | Events fetched per operation |
| `CALDERA_FINISHED_GRACE` | `600` | Seconds to tail finished ops |
| `CALDERA_DETECT` | `true` | `false` = archive only, skip rules |
| `CALDERA_SEEN_MAX` | `500` | Dedup cache size |

### 2. Start

```bash
bash scripts/bash/start_siem.sh --with-caldera
# or manual:
python scripts/caldera_collector.py
```

### 3. Test without Caldera

```bash
python simulate_caldera.py --scenario full
python simulate_caldera.py --scenario lateral
```

## Detection Rules (5)

| ID | Name | Severity | MITRE | Discord |
|----|------|----------|-------|---------|
| CAL-001 | Ability executed | MEDIUM | from event | No |
| CAL-002 | Lateral movement | HIGH | T1021 | No |
| CAL-003 | Persistence | HIGH | T1098 | No |
| CAL-004 | Command execution | MEDIUM | T1059 | No |
| CAL-005 | Exfiltration | HIGH | T1048 | No |

Purple-team alerts are **dashboard-only** (no Discord spam during exercises).

## Performance Features

| Feature | Benefit |
|---------|---------|
| Rules skip non-Caldera events | No CPU cost on auth/web logs |
| No GeoIP on purple team | Skips HTTP lookups for lab IPs |
| Idle polling | 1 API call when no ops active |
| Finished-op grace window | Catches tail events without 24/7 polling |
| Exponential backoff | Caldera down → backs off to 10 min |
| Batch ingest | Up to 100 events per SQLite write cycle |

## Dashboard

- **Events → Purple** filter shows `purple_team` category
- **Alerts → Purple** filter shows `CAL-*` rules
- `GET /api/stats` includes `purple_team_events` count

## Weak Hardware Tuning

```json
{
  "CALDERA_POLL_INTERVAL": 300,
  "CALDERA_MAX_OPS": 1,
  "CALDERA_MAX_EVENTS": 15,
  "CALDERA_DETECT": false
}
```

Set `CALDERA_DETECT: false` to archive Caldera logs without generating alerts.

## Why Caldera Stays External

The official Caldera image uses significant RAM. The SIEM only runs a ~15 MB
sidecar when you need purple-team visibility.
