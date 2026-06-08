# REST API v1 — Ingress, Triage & Dashboard Stats

This guide covers the three v1 API features added in HomeLab SIEM **v2.1.0**:

| Feature | Endpoint | Purpose |
|---------|----------|---------|
| Structured log ingestion | `POST /api/v1/ingress` | Accept JSON log events from agents and integrations |
| Incident triage | `PATCH /api/v1/alerts/<id>/triage` | Track alert status and analyst notes |
| Dashboard metrics | `GET /api/v1/stats` | Feed Chart.js with pre-aggregated JSON |

All endpoints are designed for **low CPU usage** on resource-constrained homelab hardware: validation is lightweight, aggregation runs in SQLite, and chart rendering happens entirely in the browser.

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [1. Structured Log Ingestion](#1-structured-log-ingestion)
- [2. Incident Case Management (Triage)](#2-incident-case-management-triage)
- [3. Dashboard Stats & Charts](#3-dashboard-stats--charts)
- [Quick Reference](#quick-reference)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

- HomeLab SIEM v2.1.0+ running (`python app.py`)
- Dashboard available at `http://localhost:5000`
- For remote agents: network access to the SIEM host on port 5000 (or your configured `web_port`)

Restart the SIEM after upgrading so database migrations apply (`status` and `analyst_notes` columns on the `alerts` table).

---

## 1. Structured Log Ingestion

### What it does

`POST /api/v1/ingress` accepts **structured JSON** log events — no raw log line parsing required. The server:

1. Validates the JSON structure
2. Normalizes fields (`timestamp`, `source_ip`, `destination_ip`, `event_type`, `severity`, `message`)
3. Optionally runs the detection rule engine
4. Inserts the event (and any generated alerts) into SQLite

This is ideal for custom scripts, homelab agents, IoT devices, or any source that already emits JSON telemetry.

### Single event

**Minimum requirement:** at least one of `message` or `event_type`.

```bash
curl -X POST http://localhost:5000/api/v1/ingress \
  -H "Content-Type: application/json" \
  -d '{
    "message": "SSH brute-force attempt detected",
    "source_ip": "203.0.113.10",
    "destination_ip": "192.168.1.1",
    "event_type": "auth.login.failed",
    "severity": "HIGH",
    "source": "my-agent",
    "timestamp": "2026-06-07T12:00:00"
  }'
```

**Response (201):**

```json
{
  "ingested": 1,
  "results": [
    { "index": 0, "event_id": 47672, "alerts": 1 }
  ]
}
```

### Batch ingestion (max 100 events)

```bash
curl -X POST http://localhost:5000/api/v1/ingress \
  -H "Content-Type: application/json" \
  -d '{
    "source": "fleet-agent",
    "events": [
      { "message": "Web request blocked", "event_type": "web.request", "source_ip": "10.0.0.5" },
      { "message": "DNS query to suspicious domain", "event_type": "dns.query", "severity": "MEDIUM" }
    ]
  }'
```

### Field reference

| Field | Required | Description |
|-------|----------|-------------|
| `message` | * | Human-readable log message (stored in `raw` and `fields.message`) |
| `event_type` | * | Event classifier — used for category inference if `category` is omitted |
| `timestamp` | No | ISO-8601 UTC string or Unix epoch; defaults to now |
| `source_ip` | No | Normalized to `fields.src_ip` |
| `destination_ip` | No | Normalized to `fields.dst_ip` |
| `severity` | No | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` (stored in fields) |
| `source` | No | Event source label (default: `ingress`) |
| `category` | No | Override auto-inferred category (`auth`, `web`, `cloud`, etc.) |
| `fields` | No | Extra key/value pairs merged into the stored fields blob |
| `detect` | No | `true` (default) runs rule engine; `false` skips detection (lower CPU) |

\* At least one of `message` or `event_type` is required.

### Category inference

If you omit `category`, the ingress module infers it from `event_type`:

| `event_type` contains | Category |
|-----------------------|----------|
| auth, login, ssh, sudo | `auth` |
| http, web, apache, nginx | `web` |
| kernel, dmesg | `kernel` |
| azure, cloud, aws, gcp | `cloud` |
| dns, flow, net, firewall | `syslog` |
| suricata | `suricata` |
| (other) | `generic` |

### Skip detection (archival mode)

For high-volume, low-value telemetry where you only need storage:

```json
{
  "detect": false,
  "message": "Heartbeat OK",
  "event_type": "agent.heartbeat",
  "source": "monitoring-agent"
}
```

### PowerShell example

```powershell
$body = @{
    message    = "Failed login from external IP"
    source_ip  = "203.0.113.10"
    event_type = "auth.login.failed"
    severity   = "HIGH"
    source     = "windows-agent"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/v1/ingress" `
  -Method Post -ContentType "application/json" -Body $body
```

### Python example

```python
import requests

payload = {
    "message": "Port scan detected on eth0",
    "source_ip": "198.51.100.42",
    "event_type": "net.portscan",
    "severity": "HIGH",
    "source": "suricata-agent",
}

r = requests.post("http://localhost:5000/api/v1/ingress", json=payload, timeout=5)
print(r.status_code, r.json())
```

### Limits and security

| Limit | Value |
|-------|-------|
| Max request body | 512 KB |
| Max batch size | 100 events |
| Max string field | 4 096 chars |
| Max message/raw | 16 384 chars |

All database writes use **parameterized queries**. Invalid IPs and timestamps are sanitized or replaced with safe defaults.

### Legacy endpoint

`POST /api/ingest` remains available for raw log lines and Azure collectors using `_pre_parsed`. New integrations should prefer `/api/v1/ingress`.

---

## 2. Incident Case Management (Triage)

### What it does

Alerts now support a lightweight SOC triage workflow directly in the dashboard:

| Status | Meaning |
|--------|---------|
| **New** | Unreviewed alert (default for all new alerts) |
| **In Progress** | Analyst is actively investigating |
| **Resolved** | Incident closed — true positive handled |
| **False Positive** | Benign activity — rule tuning candidate |

Each alert also has an **analyst notes** text field for investigation context (IOCs, actions taken, etc.).

### Database schema

Columns are added automatically on startup via migration:

```sql
ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'New';
ALTER TABLE alerts ADD COLUMN analyst_notes TEXT DEFAULT '';
```

### Update triage via API

```bash
curl -X PATCH http://localhost:5000/api/v1/alerts/3485/triage \
  -H "Content-Type: application/json" \
  -d '{
    "status": "In Progress",
    "analyst_notes": "Correlated with auth.log. Blocking 203.0.113.10 at firewall."
  }'
```

**Response (200):**

```json
{ "ok": true, "alert_id": 3485 }
```

You can update `status` and `analyst_notes` independently — send only the fields you want to change. `POST` is also accepted.

### Filter alerts by status

```bash
curl "http://localhost:5000/api/alerts?limit=50&status=New"
curl "http://localhost:5000/api/alerts?limit=50&status=In%20Progress"
```

Combine with severity: `?severity=HIGH&status=New`

### Dashboard usage

1. Open `http://localhost:5000` and go to the **Alerts** tab
2. Click any alert row to open the detail modal
3. Scroll to the **Incident Triage** panel:
   - Select a **Status** from the dropdown
   - Enter **Analyst notes** in the textarea
   - Click **Save triage** — updates via `fetch()` with no page reload
4. Use the **New** / **In Progress** filter buttons above the alerts table

The alerts table shows a color-coded status badge for each row. CSV export now includes `status` and `analyst_notes` columns.

### PowerShell example

```powershell
$body = @{
    status        = "Resolved"
    analyst_notes = "Confirmed pentest activity. No further action."
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/v1/alerts/3485/triage" `
  -Method Patch -ContentType "application/json" -Body $body
```

---

## 3. Dashboard Stats & Charts

### What it does

`GET /api/v1/stats` returns pre-aggregated metrics from SQLite. The dashboard fetches this JSON every 10 seconds and renders charts **entirely in the browser** using Chart.js — zero server-side rendering.

### Request

```bash
curl http://localhost:5000/api/v1/stats
```

### Response shape

```json
{
  "api_version": "v1",
  "generated_at": "2026-06-07T10:52:18.123456+00:00",
  "total_events": 47672,
  "total_alerts": 3485,
  "by_severity": {
    "CRITICAL": 12,
    "HIGH": 89,
    "MEDIUM": 201,
    "LOW": 45
  },
  "by_category": {
    "auth": 1200,
    "web": 3400,
    "cloud": 890
  },
  "events_by_hour": [
    { "hour": "2026-06-07T08:00:00", "count": 142 },
    { "hour": "2026-06-07T09:00:00", "count": 198 }
  ],
  "alerts_by_hour": [
    { "hour": "2026-06-07T08:00:00", "count": 3 }
  ],
  "by_mitre": {
    "T1110": 45,
    "T1190": 12
  },
  "by_triage_status": {
    "New": 3000,
    "In Progress": 12,
    "Resolved": 400
  },
  "top_src_ips": [
    { "ip": "203.0.113.10", "count": 87 }
  ]
}
```

### Dashboard charts (Overview tab)

| Chart | Type | Data source | Description |
|-------|------|-------------|-------------|
| Log volume — last 24h | Line | `events_by_hour` | Hourly event ingestion trend |
| Alert distribution by severity | Doughnut | `by_severity` | CRITICAL / HIGH / MEDIUM / LOW breakdown |

Charts update in-place with `chart.update('none')` to avoid animation overhead on each poll.

### Building your own charts

Minimal JavaScript example using the same API:

```html
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<canvas id="volumeChart" height="120"></canvas>

<script>
async function renderCharts() {
  const data = await fetch('/api/v1/stats').then(r => r.json());

  // Line chart — log volume
  const hours = data.events_by_hour || [];
  new Chart(document.getElementById('volumeChart'), {
    type: 'line',
    data: {
      labels: hours.map(h => h.hour.slice(11, 16)),
      datasets: [{
        data: hours.map(h => h.count),
        borderColor: '#00d9ff',
        tension: 0.3,
        fill: true,
      }],
    },
    options: { responsive: true, plugins: { legend: { display: false } } },
  });
}
renderCharts();
</script>
```

### Legacy endpoint

`GET /api/stats` still works and returns the original response shape (without `api_version`, `by_mitre`, or `by_triage_status`). New dashboard code uses `/api/v1/stats`.

---

## Quick Reference

| Task | Command |
|------|---------|
| Ingest single event | `curl -X POST localhost:5000/api/v1/ingress -H "Content-Type: application/json" -d '{"message":"test","event_type":"generic"}'` |
| Ingest without detection | Add `"detect": false` to the JSON body |
| Get dashboard stats | `curl localhost:5000/api/v1/stats` |
| List new alerts | `curl "localhost:5000/api/alerts?status=New&limit=20"` |
| Triage an alert | `curl -X PATCH localhost:5000/api/v1/alerts/ID/triage -H "Content-Type: application/json" -d '{"status":"In Progress"}'` |
| View in dashboard | Open `http://localhost:5000` → Alerts tab → click alert → Incident Triage panel |

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `400 validation failed` on ingress | Missing `message` and `event_type` | Include at least one of these fields |
| `413 Request Entity Too Large` | Payload exceeds 512 KB | Split into smaller batches (max 100 events each) |
| `404 alert not found` on triage | Invalid alert ID | Check `GET /api/alerts?limit=5` for valid IDs |
| `invalid status` error | Wrong status string | Use exactly: `New`, `In Progress`, `Resolved`, `False Positive` |
| Status column missing in DB | Migration not run | Restart `python app.py` — migration runs on first DB connection |
| Charts show no data | No events/alerts ingested yet | Send test events via ingress or `/api/ingest` |
| Triage save fails in UI | SIEM not reachable | Check browser console; verify `PATCH /api/v1/alerts/<id>/triage` returns 200 |

---

## Related docs

- `docs/SYSLOG_GUIDE.md` — remote syslog ingestion
- `docs/RULESTATS_GUIDE.md` — rule effectiveness dashboard
- `docs/BACKUP_AND_RECOVERY.md` — backing up `data/siem.db` (includes triage data)
- `CHANGELOG.md` — full v2.1.0 release notes
