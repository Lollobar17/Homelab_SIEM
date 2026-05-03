# Remote Syslog Collection & SSH Brute-Force Detection - Quick Guide

## What This Does

Your SIEM can now receive **live syslog events** from remote Linux VMs (like Kali) over the network. This enables real-time detection of:

| Alert | Rule ID | MITRE | Trigger |
|-------|---------|-------|---------|
| SSH Brute Force | AUTH-001 | T1110 | 5 failed SSH logins in 60 sec |
| SSH Brute Force — High Volume | AUTH-005 | T1110 | 10+ failed SSH logins in 60 sec |
| Root Login Attempt | AUTH-002 | T1110 | Any root SSH login attempt |
| Sudo Privilege Escalation | AUTH-004 | T1548.003 | Any sudo command run |

Before this fix, your SIEM only read local Windows log files. It never saw Linux auth logs from another machine.

---

## What Was Fixed

| Bug | File | Problem |
|-----|------|---------|
| Missing `run()` method | `siem/collector.py` | `SyslogReceiver.__init__` had socket code without a `run()` method, so the thread crashed silently — no UDP listener ever started |
| Missing socket creation | `siem/collector.py` | `sock` variable was used but never created with `socket.socket(...)` |
| Syslog disabled | `config.json` | `"syslog_enabled": false` prevented receiver initialization entirely |

All three are fixed now.

---

## Prerequisites

- **Windows host** running this SIEM (`python app.py`)
- **Kali Linux VM** (or any Debian-based VM) in VirtualBox
- **VirtualBox Host-Only Adapter** configured on both sides
- Both machines must see each other on `192.168.56.x`

---

## Setup Guide

### Part 1: Windows — Configure the SIEM

The SIEM code and config are already fixed. Just ensure `config.json` has:

```json
{
  "discord_webhook": "https://discord.com/api/webhooks/...",
  "syslog_enabled": true
}
```

If you changed it manually, double-check:
```powershell
Get-Content config.json
```

### Part 2: Kali VM — Verify SSH & Network

1. **Get the VM IP** (must be on Host-Only adapter):
   ```bash
   ip addr show
   ```
   Look for `eth1` or similar with `inet 192.168.56.101/24` (or similar).

2. **Install & enable SSH** if not running:
   ```bash
   sudo apt update
   sudo apt install openssh-server
   sudo systemctl start ssh
   sudo systemctl enable ssh
   sudo ss -tlnp | grep 22
   ```
   Expected output:
   ```
   LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",...))
   ```

3. **Install & configure rsyslog**:
   ```bash
   sudo apt install rsyslog -y
   sudo nano /etc/rsyslog.conf
   ```
   Scroll to bottom and add:
   ```
   *.* @192.168.56.1:5140
   ```
   Save (`Ctrl + O`, `Enter`, `Ctrl + X`), then restart:
   ```bash
   sudo systemctl restart rsyslog
   sudo systemctl enable rsyslog
   ```

### Part 3: VirtualBox — Add Host-Only Adapter (if missing)

If Kali only has `eth0` with `10.0.2.15` (NAT), add a Host-Only adapter:

1. **Shut down** the VM completely (not save state)
2. VirtualBox → VM → **Settings** → **Network** → **Adapter 2**
3. Check **Enable Network Adapter**
4. **Attached to:** `Host-Only Adapter`
5. **Name:** `VirtualBox Host-Only Ethernet Adapter`
6. Start the VM
7. Bring up the interface:
   ```bash
   sudo ip link set eth1 up
   sudo dhclient eth1        # or: sudo dhcpcd eth1
   ip addr show eth1
   ```

---

## How to Test

### 1. Start the SIEM (keep running)

```powershell
python app.py
```

You should see:
```
Starting HomeLab SIEM …
[Syslog] Listening on udp://0.0.0.0:5140
 * Running on http://0.0.0.0:5000
```

### 2. Connectivity Test from Kali

```bash
nc -zvn 192.168.56.1 5140
```

Expected:
```
Connection to 192.168.56.1 5140 port [udp/*] succeeded!
```

### 3. Send a Test Syslog Message

On Kali:
```bash
logger "TEST: failed ssh login from 10.0.2.15"
```

On Windows, verify the event arrived:
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/events?limit=5"
```

Or open `http://127.0.0.1:5000` in your browser.

### 4. Run Real SSH Brute Force with Hydra

From Kali (or Windows with Hydra installed):
```bash
hydra -l MPC -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.101 -t 4
```



Let it run for **20–30 seconds** so Kali generates enough failed login attempts.

> **Note:** Use the VM’s actual IP, not `192.168.56.1` (that’s the Windows host gateway).

**Why you may see only `AUTH-001`:**  
OpenSSH's default `MaxStartups` limit (`10`) throttles Hydra after ~5–8 attempts. Hydra then exits with *"all children were disabled due too many connection errors"*.  
To trigger `AUTH-005` (needs 10+ attempts), either:
1. Increase `MaxStartups` on Kali (see [Troubleshooting](#troubleshooting))
2. Run Hydra **twice in a row** within 60 seconds so attempts accumulate

### 5. Check Alerts

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:5000/api/alerts?limit=10"
```

Or open the dashboard: `http://127.0.0.1:5000`

You should see:
```json
{
  "rule": "AUTH-001",
  "name": "SSH Brute Force",
  "severity": "HIGH",
  "mitre": "T1110",
  "source_ip": "192.168.56.101"
}
```

---

## Full Attack Flow (What Happens Behind the Scenes)

1. **Hydra** connects to Kali SSH, tries passwords
2. **sshd** logs every failed login to `/var/log/auth.log`
3. **rsyslog** forwards those lines to `192.168.56.1:5140` (Windows host)
4. **SIEM SyslogReceiver** listens on UDP 5140, receives the log lines
5. **detector.py** parses auth logs and runs `AUTH-001` / `AUTH-005` rules
6. **Alert** is stored, shown on dashboard, and optionally sent to Discord

```
┌──────────────┐      SSH login       ┌─────────────────┐
│   Hydra      │ ───── attempts ────→ │   Kali VM       │
│  (attacker)  │                      │  sshd / auth.log│
└──────────────┘                      └────────┬────────┘
                                               │
                                               │ rsyslog
                                               │ forwards
                                               ▼
                                     ┌──────────────────┐
                                     │ Windows Host     │
                                     │ SIEM on UDP 5140 │
                                     │ (collector.py)   │
                                     └────────┬─────────┘
                                              │
                                              │ analyze_event()
                                              ▼
                                     ┌──────────────────┐
                                     │ Dashboard        │
                                     │ + Discord alert  │
                                     └──────────────────┘
```

---

## Quick Command Reference

| Task | Command (Kali) | Command (Windows) |
|------|----------------|-------------------|
| Get VM IP | `ip addr show` | — |
| Start SSH | `sudo systemctl start ssh` | — |
| Restart rsyslog | `sudo systemctl restart rsyslog` | — |
| Test syslog connectivity | `nc -zvn 192.168.56.1 5140` | — |
| Send test log | `logger "TEST message"` | — |
| Start SIEM | — | `python app.py` |
| View alerts | — | `Invoke-RestMethod -Uri http://127.0.0.1:5000/api/alerts` |
| Dashboard | — | `http://127.0.0.1:5000` |
| SSH brute force | `hydra -l user -P rockyou.txt ssh://192.168.56.101 -t 4` | — |

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `Connection refused` (Hydra → 192.168.56.1) | Targeting gateway IP, not VM | Use the VM's actual IP (e.g., `192.168.56.101`) |
| `Connection refused` (Hydra → correct IP) | SSH not running on Kali | `sudo systemctl start ssh` |
| `nc` shows connection failed | Windows firewall blocking UDP 5140 | Run PowerShell as Admin:<br>`netsh advfirewall firewall add rule name="SIEM Syslog" dir=in action=allow protocol=udp localport=5140` |
| SIEM shows no `[Syslog] Listening…` | `syslog_enabled: false` in `config.json` | Set to `true` |
| Alerts never appear | Collector thread crashed (old bug) | Ensure `siem/collector.py` has `run()` method and `socket.socket(...)` |
| `dhclient` not found on Kali | Not installed | `sudo apt install isc-dhcp-client` or use `sudo ip addr add 192.168.56.101/24 dev eth1` |
| Adapter 2 greyed out in VirtualBox | VM is running | Shut down the VM completely first |
| Only `AUTH-001` triggers, no `AUTH-005` | OpenSSH `MaxStartups` throttles Hydra after ~10 attempts | Edit `/etc/ssh/sshd_config` on Kali:<br>`MaxStartups 100:30:100`<br>Then `sudo systemctl restart ssh` |

---

## Why This Matters

Before: Your SIEM only saw local Windows web logs — it could detect SQL injection against its own `/vulnerable` endpoint, but nothing else.

After: Your SIEM is a **real log aggregation platform**. Any Linux VM, firewall, or router that supports syslog can stream logs to it. You now have:
- Network-wide SSH brute force detection
- Multi-device log correlation
- MITRE ATT&CK-mapped alerts in real time

This is a genuine SOC-homelab skill.
