# GeoIP & Alert Pipeline - Quick Guide

## What Was Fixed

| Bug | File | Problem |
|-----|------|---------|
| Broken regex | `siem/geoip.py` | `\d\{1,3}` had extra backslash before `{`, so no IP ever matched |
| Missing SQL param | `siem/storage.py` | 9 columns but only 8 `?` placeholders, so all alert inserts crashed |

Both are fixed now.

## How to Test

### 1. Start the SIEM (keep running)

```powershell
python app.py
```

You should see:
```
Starting HomeLab SIEM ...
[Syslog] Listening on udp://0.0.0.0:5140
 * Running on http://0.0.0.0:5000
```

### 2. Send a test attack

Open a **second terminal** while app.py runs:

```powershell
$body = @{
    raw = "45.33.32.156 - - [22/Apr/2026 12:00:00] `"GET /search?id=1%20UNION%20SELECT%201,2,3-- HTTP/1.1`" 404 512"
    source = "flask"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/ingest" -Method Post -ContentType "application/json" -Body $body
```

Expected output:
```
event_id alerts
-------- ------
   12345      1
```

### 3. Check the alert with GeoIP

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/alerts?limit=5"
```

Look for:
```json
{
  "rule_id": "WEB-003",
  "severity": "HIGH",
  "source_ip": "45.33.32.156",
  "geo": "{\"country\": \"United States\", \"city\": \"Fremont\"}"
}
```

### 4. Test multiple countries at once

```powershell
$ips = @(
    @("US", "45.33.32.156"),
    @("Italy", "151.1.1.1"),
    @("Japan", "133.1.1.1"),
    @("France", "80.1.1.1")
)

foreach ($c in $ips) {
    $body = @{
        raw = "$($c[1]) - - [22/Apr/2026 12:00:00] `"GET /search?id=1%20UNION%20SELECT%201,2,3-- HTTP/1.1`" 404 512"
        source = "flask"
    } | ConvertTo-Json

    $r = Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/ingest" -Method Post -ContentType "application/json" -Body $body
    Write-Host "$($c[0]) -> alerts=$($r.alerts)"
}
```

Then view them:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/alerts?limit=10" | ForEach-Object {
    $g = $_.geo | ConvertFrom-Json
    Write-Host "$($_.source_ip) -> $($g.country), $($g.city)"
}
```

## Private IPs

If you use `127.0.0.1` or `192.168.x.x`, GeoIP returns:
```json
{"country": "Internal", "city": "Private Network", "isp": "N/A"}
```
This is expected - private IPs are not on the public internet.

## Quick Reference

| Task | Command |
|------|---------|
| Start SIEM | `python app.py` |
| Dashboard | `http://127.0.0.1:5000` |
| Send attack | `Invoke-RestMethod -Uri http://127.0.0.1:5000/api/ingest -Method Post -Body $body` |
| View alerts | `Invoke-RestMethod -Uri http://127.0.0.1:5000/api/alerts?limit=5` |
| View stats | `Invoke-RestMethod -Uri http://127.0.0.1:5000/api/stats` |

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `Unable to connect` | app.py not running | Start `python app.py` first |
| `alerts: 0` | Log format wrong | Copy exact raw string from examples above |
| `geo: {}` | Private IP or broken regex | Use public IP; regex is fixed |
| No alerts in DB | SQL broken | Check `storage.py` has 9 `?` placeholders |

