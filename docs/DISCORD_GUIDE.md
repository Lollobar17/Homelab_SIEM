# Discord Alert Notifier - Quick Guide

## What Was Fixed

| Bug | File | Problem |
|-----|------|---------|
| No auto-loading | `app.py` | Discord webhook only worked if you manually set the `DISCORD_WEBHOOK_URL` env var before starting |
| Silent failures | `siem/notifier.py` | When webhook was missing, no logs explained why Discord alerts weren't sending |
| No config storage | `config.json` (missing) | Webhook URL had to be re-entered every terminal session |

All are fixed now. Your webhook is saved in `config.json` and loaded automatically.

## How to Set Up

### 1. Save your webhook in `config.json`
Create or edit `config.json` in the project root:
```json
{
  "discord_webhook": "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
}
```

### 2. Start the SIEM
```powershell
python app.py
```

You should see:
```
Starting HomeLab SIEM ...
[Config] Discord webhook loaded from config.json
[Syslog] Listening on udp://0.0.0.0:5140
 * Running on http://0.0.0.0:5000
```

## How to Test

### Quick test — 1 alert (no SIEM needed)
```powershell
python test_discord.py
```
- Tests with config.json URL automatically
- Or pass URL: `python test_discord.py https://discord.com/api/webhooks/...`
- Sends single HIGH test embed

### Full test — all severities + GeoIP
```powershell
python test_discord.py --full
```
- Sends 6 alerts: CRITICAL, HIGH, MEDIUM, LOW
- Verifies color coding, embed fields, GeoIP display

### Via SIEM pipeline
```powershell
# Start SIEM
python app.py

# In second terminal, inject SQLi log
$body = @{
    raw = "45.33.32.156 - - [22/Apr/2026 12:00:00] `"GET /search?id=1%20UNION%20SELECT%201,2,3-- HTTP/1.1`" 404 512"
    source = "flask"
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/ingest" -Method Post -ContentType "application/json" -Body $body
```

## Real Attack Testing from Kali Linux

Your SIEM must be reachable from Kali (same network or bridged VM).

### Step 0: Find your SIEM IP
On Windows host running the SIEM:
```powershell
ipconfig
# Look for IPv4 Address, e.g. 192.168.1.100
```

### Scenario 1: SQLMap SQL Injection (HIGH alert)
```bash
sqlmap -u "http://SIEM_IP:5000/vulnerable?q=1" --batch --level=2
```
- `WEB-003` fires → 🟠 Discord embed with GeoIP

### Scenario 2: Hydra SSH Brute Force (CRITICAL alert)
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://SIEM_IP
```
- Or simulate via syslog if no SSH server:
```bash
for i in {1..12}; do
  echo "<134>Apr 27 15:00:0$i homelab sshd[1234]: Failed password for root from KALI_IP port 22 ssh2" | nc -u SIEM_IP 5140
done
```
- `AUTH-005` fires → 🔴 Discord embed

### Scenario 3: Dirb Directory Traversal (MEDIUM alert)
```bash
dirb http://SIEM_IP:5000 /usr/share/dirb/wordlists/common.txt
# Or:
curl "http://SIEM_IP:5000/../../../etc/passwd"
```
- `WEB-001` fires (MEDIUM — **no Discord** by default, only HIGH+)
- Edit `siem/detector.py` `min_severity="MEDIUM"` to change

### Scenario 4: Web Flood (CRITICAL alert)
```bash
for i in {1..60}; do
  curl -s "http://SIEM_IP:5000/nonexistent$i" > /dev/null
done
```
- `WEB-004` fires → 🔴 Discord embed

## Quick Reference

| Task | Command |
|------|---------|
| Start SIEM | `python app.py` |
| Test Discord (quick) | `python test_discord.py` |
| Test Discord (full) | `python test_discord.py --full` |
| Test with custom URL | `python test_discord.py <url>` |
| Send attack | `Invoke-RestMethod -Uri http://127.0.0.1:5000/api/ingest` |


| View alerts | `Invoke-RestMethod -Uri http://127.0.0.1:5000/api/alerts?limit=5` |
| SQLMap from Kali | `sqlmap -u "http://SIEM_IP:5000/vulnerable?q=1" --batch` |
| Hydra from Kali | `hydra -l root -P rockyou.txt ssh://SIEM_IP` |
| Fake SSH logs | `echo '<134>...sshd...Failed password...' \| nc -u SIEM_IP 5140` |

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `[Config] Discord webhook loaded` never appears | `config.json` missing or wrong format | Check `config.json` has `"discord_webhook": "url"` |
| `[Discord] Skipping notification` | Webhook URL empty | Verify config.json and restart app.py |
| `test_discord.py` says FAIL | URL invalid | Check webhook URL is correct and channel exists |
| Missing embed fields | GeoIP failed | See `GEOIP_GUIDE.md` |
| Kali can't reach SIEM | Firewall / wrong IP | Check `ipconfig`, disable Windows Defender Firewall for port 5000 |
| No alerts from real attacks | Logs not being parsed | Check `logs/flask_access.log` exists |
