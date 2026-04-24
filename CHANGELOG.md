# Changelog

All notable changes to HomeLab SIEM are documented in this file.
This project follows [Keep a Changelog](https://keepachangelog.com) conventions.

---

## [1.3.0] - 2026-04-24

> [!IMPORTANT]
> This release adds GeoIP enrichment to all alerts, providing geographic
> context for source IP addresses. Every alert now includes country, region,
> city, ISP and organization data where available.

### Added

- **siem/geoip.py** — GeoIP lookup module using ip-api.com (free, no API key)
  Results are cached in memory via lru_cache to avoid redundant requests.
  Private and reserved IP ranges are handled gracefully.

- **geo field** added to all generated alerts in detector.py
  Every alert now includes geographic data for the source IP.

- **geo column** added to alerts table in storage.py
  Automatic migration handles existing databases on startup.

---

## [1.2.0] - 2026-03-28

> [!IMPORTANT]
> This release implements all remaining security improvements identified
> during the penetration testing assessment. All 7 gaps (G-01 through G-07)
> are now either resolved or explicitly tracked as future work.

### Added

- AUTH-005 — SSH Brute Force High Volume rule (CRITICAL severity)
  Triggers when more than 10 failed SSH attempts occur from the same IP
  in 60 seconds. Closes G-04.

- AUTH-006 — Successful Login After Failures rule (CRITICAL severity)
  Triggers when a successful login follows 3+ failed attempts from the
  same IP in 5 minutes. Closes G-07 (partial).

- WEB-004 — Web Brute Force High Volume rule (CRITICAL severity)
  Triggers when more than 50 HTTP 4xx responses come from the same IP
  in 60 seconds. Closes G-07 (partial).

- Flask/Werkzeug access log parser added to collector.py
  The SIEM now parses Flask access logs and detects web-layer anomalies.
  Closes G-05 and G-06.

- ANSI escape code stripping added to _process_raw_line() in collector.py
  Ensures reliable parsing of Werkzeug logs that include terminal color codes.

- stress-test mode added to simulate_logs.py
  New --stress-test flag fires AUTH-005, WEB-004 and AUTH-006 in sequence
  for threshold validation testing.

### Changed

- source_ip added to all generated alerts in detector.py
  Every alert now includes the attacker IP extracted from the log event.
  Closes G-03.

- Database migration added to storage.py
  Automatic schema migration runs on startup — adds source_ip column to
  existing databases without requiring manual intervention.

### Known Gaps — Planned for v1.4.0

> [!CAUTION]
> The following gap was identified during assessment and remains open.
> It requires significant architectural work beyond rule engine changes.

- G-01 — No network-level scanning detection
  Requires integration with a network monitoring tool such as Suricata
  or Zeek to detect inbound port scanning activity.

---

## [1.1.0] - 2026-03-26

> [!IMPORTANT]
> This release addresses initial documentation gaps identified during
> the penetration testing assessment conducted via the
> [Network Security Monitoring Lab](https://github.com/Lollobar17/Network_Security_Lab).

### Added

- CHANGELOG.md — version tracking and change documentation
- Security Assessment section in README — links to external pentest findings

### Changed

- AUTH-002 rule — updated MITRE classification from T1078 (Valid Accounts)
  to T1110 (Brute Force) for repeated root SSH login attempts.
  Closes G-02.

---

## [1.0.0] - 2026-03-01

> [!NOTE]
> Initial release of HomeLab SIEM — core functionality implemented.

### Added

- Log collection via file tailers and UDP syslog (port 5140)
- Log parsing for SSH/auth, Apache/Nginx, kernel/dmesg and syslog
- Rule engine with 8 built-in detection rules mapped to MITRE ATT&CK
- Live web dashboard — KPIs, timeline chart, alert table, event stream
- REST API — /api/events, /api/alerts, /api/stats, /api/ingest
- Demo simulator for generating realistic fake logs
- SQLite persistence layer

### Detection Rules — v1.0.0

> [!TIP]
> All rules are mapped to MITRE ATT&CK techniques. Use the rule IDs
> to cross-reference findings in the security assessment report.

| ID | Name | Severity | MITRE |
|---|---|---|---|
| AUTH-001 | SSH Brute Force | HIGH | T1110 |
| AUTH-002 | Root Login Attempt | HIGH | T1078 |
| AUTH-003 | Successful Root Login | CRITICAL | T1078.003 |
| AUTH-004 | Sudo Privilege Escalation | MEDIUM | T1548.003 |
| WEB-001 | Directory Traversal | MEDIUM | T1083 |
| WEB-002 | Web Brute Force (4xx flood) | MEDIUM | T1110 |
| WEB-003 | SQL Injection Attempt | HIGH | T1190 |
| SYS-001 | OOM Killer Activated | MEDIUM | — |

---

## Versioning

This project uses [Semantic Versioning](https://semver.org):
- MAJOR — breaking changes to API or architecture
- MINOR — new features or detection rules
- PATCH — bug fixes and minor improvements
