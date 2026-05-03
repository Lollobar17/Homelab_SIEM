# Suricata IDS Setup & Operations Guide

## Overview

This document describes the Suricata Intrusion Detection System (IDS) integration with the Homelab SIEM project, the fixes applied, and commands to monitor detected threats in real-time.

---

## What Was Done

### 1. **Docker Integration**
- Set up Suricata as a containerized service using `jasonish/suricata` image
- Integrated Suricata with the existing SIEM container using `docker-compose.yml`
- Configured Suricata to run in the SIEM network namespace (`network_mode: "service:siem"`)
- Suricata monitors `eth0` in IDS mode and sees SIEM service traffic directly

### 2. **Configuration & Rule Setup**
- **suricata.yaml**: Configured to:
  - Monitor eth0 interface
  - Enable EVE JSON logging for structured alert data
  - Load custom rules from `/etc/suricata/rules/rules.rules`
  - Generate fast.log for quick alert viewing
  - Output statistics to stats.log

- **rules.rules**: Created 25+ detection rules covering:
  - **Web Attacks**: SQLi, directory traversal, command injection
  - **Scanners**: Nikto, sqlmap, Nessus detection
  - **Network Reconnaissance**: ICMP ping scans, TCP SYN/FIN/XMAS scans
  - **SSH Version Detection**

### 3. **SIEM Integration**
- Configured Suricata logs to be collected by the SIEM
- SIEM collector tails `suricata-logs/eve.json` from inside the SIEM container
- Alerts stored in SQLite database for historical analysis
- Exposed via REST API and web dashboard

---

## Fixes Applied

### Fix #1: Port Conflict (5140/UDP)
**Problem**: Both SIEM and Suricata containers were trying to bind to port 5140/UDP

**Solution**: 
- Removed the explicit port binding from Suricata in `docker-compose.yml`
- SIEM container handles syslog reception on 5140/UDP
- Suricata runs on the container network without port exposure

**Before**:
```yaml
suricata:
  ports:
    - "5140:5140/udp"  # ❌ Conflict with SIEM
```

**After**:
```yaml
suricata:
  # ✅ Removed port binding - SIEM handles syslog
```

### Fix #2: Rule Loading
**Status**: ✅ Rules loading successfully

- Verified `/etc/suricata/rules/rules.rules` is correctly mounted as a volume
- 25 detection rules successfully loaded on container startup
- No "rule file not found" errors in current logs

---

## Current Status

| Component | Status | Details |
|-----------|--------|---------|
| Suricata Container | ✅ Running | Monitoring `eth0` in SIEM namespace |
| Rules Loaded | ✅ 25 Rules | 1 rule file processed, 0 failed |
| SIEM Dashboard | ✅ Online | HTTP 200 at `http://localhost:5000` |
| API Source Filter | ✅ Working | `/api/events?source=suricata` returns Suricata events |
| Log Files | ✅ Active | `eve.json`, `fast.log`, `stats.log` update in real-time |

---

## Key Statistics

Use live API values instead of static snapshots:

```bash
curl http://localhost:5000/api/stats
curl http://localhost:5000/api/rules/stats
```

---

## Commands to Monitor Suricata

### 1. **Real-Time Fast Alert Log**
View alerts as they happen in a readable format:

```bash
tail -f suricata-logs/fast.log
```

**Example Output**:
```
05/03/2026-14:53:26.404682  [**] [1:5003:1] TCP SYN Scan - SYN Flag [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.65.1:62275 -> 192.168.65.7:2376
```

### 2. **Filter by Attack Type**
View only specific attack categories:

```bash
# View only port scans
tail -f suricata-logs/fast.log | grep -i "scan"

# View only HTTP attacks
tail -f suricata-logs/fast.log | grep -i "http"

# View only SQL injection attempts
tail -f suricata-logs/fast.log | grep -i "sqli"
```

### 3. **Real-Time JSON Alert Stream**
View structured JSON alerts (from eve.json):

```bash
tail -f suricata-logs/eve.json | jq 'select(.event_type=="alert")'
```

**Example Output** (formatted JSON):
```json
{
  "timestamp": "2026-05-03T14:53:26.404682+0000",
  "flow_id": 123456789,
  "event_type": "alert",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 5003,
    "rev": 1,
    "signature": "TCP SYN Scan - SYN Flag",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "src_ip": "192.168.65.1",
  "src_port": 62275,
  "dest_ip": "192.168.65.7",
  "dest_port": 2376,
  "proto": "TCP"
}
```

### 4. **Count Alerts by Rule**
See which rules are triggering most:

```bash
grep -o '\[1:[0-9]*:1\]' suricata-logs/fast.log | sort | uniq -c | sort -rn
```

**Output**:
```
289 [1:5003:1] TCP SYN Scan - SYN Flag
279 [1:6001:1] Unusual HTTP User-Agent
47 [1:5008:1] Port Scanning Behavior
...
```

### 5. **Check Container Logs**
View Suricata startup and runtime messages:

```bash
docker logs suricata_ids | tail -50

# Or with grep for warnings/errors
docker logs suricata_ids | grep -E "Warning|Error|rule"
```

### 6. **Verify Rules Are Loaded**
Check how many rules were successfully loaded:

```bash
docker logs suricata_ids | grep "rule.*loaded"
```

**Expected Output**:
```
Info: detect: 1 rule files processed. 25 rules successfully loaded, 0 rules failed, 0 rules skipped
```

### 7. **Monitor Suricata Statistics**
View real-time performance metrics:

```bash
tail -f suricata-logs/stats.log | grep -E "uptime|pkts_accepted|pkts_dropped"
```

---

## SIEM Dashboard & API

### 1. **Web Dashboard**
Access the SIEM web interface to visualize alerts:

```
http://localhost:5000
```

**Available Views**:
- Dashboard: Overview of alerts, events, and statistics
- Alerts: List of all detected security events
- Statistics: Breakdown by category, severity, source IP

### 2. **REST API Endpoints**

**Get Overall Statistics**:
```bash
curl http://localhost:5000/api/stats
```

**Get Recent Events** (with filtering):
```bash
# Last 10 events
curl "http://localhost:5000/api/events?limit=10"

# Events from Suricata only
curl "http://localhost:5000/api/events?source=suricata&limit=10"

# Filter by category
curl "http://localhost:5000/api/events?category=web&limit=10"
```

**Get Rules Statistics**:
```bash
curl http://localhost:5000/api/rules/stats
```

---

## Detection Rules Summary

### Web Attack Rules (SIDs 1001-3004)

| SID | Rule Name | Purpose |
|-----|-----------|---------|
| 1001-1007 | SQL Injection variants | Detect SQLi attacks |
| 2001-2004 | Directory Traversal | Detect path traversal attempts |
| 3001-3004 | Command Injection | Detect shell command execution |

### Scanner Rules (SIDs 4001-4003)

| SID | Rule Name | Purpose |
|-----|-----------|---------|
| 4001 | Nikto Scanner | Detect Nikto web scanner user-agent |
| 4002 | sqlmap Scanner | Detect sqlmap tool |
| 4003 | Nessus Scanner | Detect Nessus vulnerability scanner |

### Network Reconnaissance Rules (SIDs 5001-6002)

| SID | Rule Name | Purpose |
|-----|-----------|---------|
| 5001 | Nmap in User-Agent | Detect Nmap HTTP requests |
| 5002 | ICMP Echo Request | Detect ping scans |
| 5003 | TCP SYN Scan | Detect half-open port scans |
| 5005 | TCP FIN Scan | Detect FIN scans |
| 5006 | TCP XMAS Scan | Detect XMAS/FPU scans |
| 6001 | Unusual HTTP User-Agent | Detect non-browser HTTP clients |
| 6002 | SSH Version Detection | Detect SSH version probing |

---

## Test Attacks (For Learning)

Generate detectable attacks to test the system:

### 1. **SQL Injection Attempt**
```bash
curl "http://127.0.0.1:5000/vulnerable?q=1%20UNION%20SELECT%201,2,3"
```
Expected Alert: `SQLi - UNION SELECT`

### 2. **Directory Traversal Attempt**
```bash
curl "http://127.0.0.1:5000/../../../etc/passwd"
```
Expected Alert: `Dir Traversal - ../`

### 3. **Command Injection Attempt**
```bash
curl "http://127.0.0.1:5000/cmd?\$%28whoami%29"
```
Expected Alert: `Cmd Injection - Dollar Paren`

### 4. **Port Scan (if you have nmap installed)**
```bash
nmap -sS 127.0.0.1
```
Expected Alerts:
- Multiple `TCP SYN Scan` alerts
- `Port Scanning Behavior` alert

---

## Troubleshooting

### Issue: Suricata container not starting

**Check Status**:
```bash
docker ps -a | grep suricata
docker logs suricata_ids
```

**Common Causes**:
- Port already in use: `docker ps` and check for port conflicts
- Rule syntax error: Check `suricata-logs/suricata.log` for parsing errors
- Missing volume mount: Verify `suricata-rules/` folder exists

**Solution**: Restart containers:
```bash
docker compose down
docker compose up -d
```

### Issue: No alerts being generated

**Verify Rules Are Loaded**:
```bash
docker logs suricata_ids | grep "rules.*loaded"
```

**Check If Suricata Is Monitoring Traffic**:
```bash
tail suricata-logs/stats.log | grep "pkts_accepted"
```

**Manually Test Rule**:
```bash
# Generate HTTP request with suspicious pattern
curl "http://127.0.0.1:5000/?test=union"

# Check if alert was logged
grep "UNION" suricata-logs/fast.log
```

### Issue: Fast.log file very large

**Archive old logs**:
```bash
gzip suricata-logs/fast.log
mv suricata-logs/fast.log.gz suricata-logs/fast.log.$(date +%Y%m%d).gz
```

**Clear logs** (not recommended in production):
```bash
> suricata-logs/fast.log
```

---

## Performance Tuning

### Monitor Packet Loss
```bash
tail -f suricata-logs/stats.log | grep "pkts_dropped"
```

If packets are being dropped:
1. Check CPU usage: `docker stats suricata_ids`
2. Increase thread count in `suricata.yaml`
3. Enable hardware offloading if available

### Check CPU/Memory Usage
```bash
docker stats suricata_ids --no-stream
```

---

## Adding Custom Rules

Edit `suricata-rules/rules.rules` and add new rules:

```
alert http any any -> any 5000 (msg:"Custom Attack Pattern"; content:"dangerous_pattern"; http_uri; classtype:attempted-admin; sid:9999; rev:1;)
```

Then restart Suricata:
```bash
docker compose restart suricata
```

Verify new rule loaded:
```bash
docker logs suricata_ids | grep "9999"
```

---

## References

- **Suricata Official Docs**: https://docs.suricata.io/
- **Rule Format**: https://docs.suricata.io/en/latest/rules/index.html
- **EVE JSON Format**: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

---

## Next Steps

1. **Add Discord Notifications**: Configure `config.json` with Discord webhook for real-time alerts
2. **Enable Remote Syslog**: Forward logs from other hosts to port 5140/UDP
3. **Expand Rule Set**: Add more detection rules based on your environment
4. **Backup Data**: Regularly backup SQLite database in `/app/data/`
5. **Monitor Metrics**: Set up alerts if packet loss exceeds thresholds
