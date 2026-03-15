# HomeLab SIEM

A lightweight, self-hosted **Security Information & Event Management** system built in pure Python.  
Designed to learn cybersecurity concepts hands-on — log collection, threat detection, and a live dashboard.

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat&logo=flask)
![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?style=flat&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

---

## Features

| Feature | Details |
|---|---|
| **Log Collection** | Tails local files + listens on UDP syslog (port 5140) |
| **Log Parsing** | SSH/auth, Apache/Nginx access logs, kernel/dmesg, syslog |
| **Threat Detection** | Rule engine with 8 built-in rules (SSH brute force, SQLi, traversal, …) |
| **MITRE ATT&CK** | Every rule is mapped to a MITRE technique ID |
| **Dashboard** | Live web UI — KPIs, timeline chart, alert table, event stream |
| **REST API** | `/api/events`, `/api/alerts`, `/api/stats`, `/api/ingest` |
| **Demo Simulator** | Generate realistic fake logs without a real Linux system |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/homelab-siem.git
cd homelab-siem

# 2. Install deps (Python 3.10+)
pip install -r requirements.txt

# 3. Run the SIEM
python app.py

# 4. Open dashboard
#    http://localhost:5000

# 5. (optional) Feed demo logs in a second terminal
python simulate_logs.py
```

The `data/siem.db` SQLite database is created automatically on first run.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   HomeLab SIEM                       │
│                                                      │
│  ┌──────────────┐   ┌──────────────┐                │
│  │ File Tailers │   │ UDP Syslog   │  ← collectors  │
│  │ (auth.log,   │   │ (port 5140)  │                │
│  │  nginx, …)   │   └──────┬───────┘                │
│  └──────┬───────┘          │                        │
│         └─────────┬────────┘                        │
│                   ▼                                  │
│          ┌────────────────┐                          │
│          │  collector.py  │  parse_log_line()        │
│          │  (parser)      │                          │
│          └───────┬────────┘                          │
│                  ▼                                   │
│          ┌────────────────┐                          │
│          │  detector.py   │  analyze_event()         │
│          │  (rule engine) │  → alerts[]              │
│          └───────┬────────┘                          │
│                  ▼                                   │
│          ┌────────────────┐                          │
│          │  storage.py    │  SQLite                  │
│          │  (events +     │  data/siem.db            │
│          │   alerts DB)   │                          │
│          └───────┬────────┘                          │
│                  ▼                                   │
│          ┌────────────────┐                          │
│          │   app.py       │  Flask REST API          │
│          │   + dashboard  │  + HTML dashboard        │
│          └────────────────┘                          │
└──────────────────────────────────────────────────────┘
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | KPIs, timeline, top IPs |
| `GET` | `/api/events?limit=N&category=auth` | Recent events |
| `GET` | `/api/alerts?limit=N&severity=HIGH` | Recent alerts |
| `GET` | `/api/rules` | All detection rules |
| `POST` | `/api/ingest` | Manually ingest a log line |
| `GET` | `/api/health` | Health check |

**Ingest example:**
```bash
curl -X POST http://localhost:5000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"raw": "Failed password for root from 1.2.3.4 port 22 ssh2", "source": "myserver"}'
```

---

## Detection Rules

| ID | Name | Severity | MITRE |
|---|---|---|---|
| AUTH-001 | SSH Brute Force | HIGH | T1110 |
| AUTH-002 | Root Login Attempt | HIGH | T1078 |
| AUTH-003 | Successful Root Login | CRITICAL | T1078.003 |
| AUTH-004 | Sudo Privilege Escalation | MEDIUM | T1548.003 |
| WEB-001 | Directory Traversal | MEDIUM | T1083 |
| WEB-002 | Web Brute Force (4xx flood) | MEDIUM | T1110 |
| WEB-003 | SQL Injection Attempt | HIGH | T1190 |
| SYS-001 | OOM Killer Activated | MEDIUM | – |

### Adding a custom rule

Open `siem/detector.py` and add an entry to the `RULES` list:

```python
{
    "id":          "CUSTOM-001",
    "name":        "My Rule",
    "description": "Detects XYZ behaviour.",
    "severity":    "HIGH",          # CRITICAL | HIGH | MEDIUM | LOW
    "category":    "auth",
    "mitre":       "T1234",
    "match":    lambda e: "badword" in e.get("raw","").lower(),
    "threshold":   None,            # None = fire on every match
},
```

---

## Configuration

Edit `config.json`:

```json
{
  "syslog_enabled": true,
  "syslog_port": 5140,
  "watch_files": [
    { "path": "/var/log/auth.log", "name": "auth" }
  ],
  "web_port": 5000
}
```

**Send syslog from another host:**
```bash
logger -n 127.0.0.1 -P 5140 --udp "test message from $(hostname)"
```

---

## Project Structure

```
homelab-siem/
├── app.py               # Flask app + API routes
├── config.json          # User configuration
├── requirements.txt
├── simulate_logs.py     # Demo log generator
├── siem/
│   ├── __init__.py
│   ├── collector.py     # File tailer + UDP syslog receiver + parser
│   ├── detector.py      # Detection rule engine
│   └── storage.py       # SQLite persistence layer
├── templates/
│   └── dashboard.html   # Single-page web dashboard
└── data/
    └── siem.db          # Auto-created SQLite database
```

---

## Running in Demo Mode

If you don't have a Linux server with real logs:

```bash
# Terminal 1 — start SIEM
python app.py

# Terminal 2 — pump fake events
python simulate_logs.py --rate 2.0
```

The simulator generates SSH attacks, web scans, SQL injection attempts and more, so you can see the detection rules fire in real time.

---

## Roadmap

- [ ] GeoIP lookup for source IPs  
- [ ] Discord / Telegram alert notifications  
- [ ] Docker Compose setup  
- [ ] Rule editor in the dashboard UI  
- [ ] CSV / JSON export  

---

## Learning Resources

If you're new to cybersecurity and want to go deeper:

- [MITRE ATT&CK](https://attack.mitre.org) — adversary tactics & techniques
- [TryHackMe](https://tryhackme.com) — hands-on labs
- [The Elastic SIEM Guide](https://www.elastic.co/what-is/siem)

---

## License

MIT — use freely, learn a lot.
