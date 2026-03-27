# Changelog

All notable changes to HomeLab SIEM are documented in this file.
This project follows [Keep a Changelog](https://keepachangelog.com) conventions.

---

## [1.1.0] - 2026-03-26

> [!IMPORTANT]
> This release addresses security gaps identified during a structured
> penetration testing assessment conducted via the
> [Network Security Monitoring Lab](https://github.com/Lollobar17/Network_Security_Lab).
> All changes are directly traceable to documented findings in the
> gap analysis report (G-01 through G-07).

### Added

- **CHANGELOG.md** — version tracking and change documentation
- **Security Assessment section** in README — links to the external
  pentest findings that motivated this release

### Changed

- **AUTH-002 rule** — updated MITRE classification from T1078 (Valid Accounts)
  to T1110 (Brute Force) for repeated root SSH login attempts
  *(addresses gap G-02)*

### Fixed

- **Alert schema** — added `source_ip` as a mandatory field in alert
  data returned by `/api/alerts`
  *(addresses gap G-03)*

### Known Gaps — Planned for v1.2.0

> [!CAUTION]
> The following gaps were identified during assessment and are not yet
> resolved in this release. They are tracked in the improvement roadmap.

- **G-01** — No network-level scanning detection (requires Suricata/Zeek integration)
- **G-04** — No brute force volume correlation rule (time-window based)
- **G-05 / G-06** — Flask access logs not parsed (web layer blind spot)
- **G-07** — No CRITICAL severity threshold defined

> [!NOTE]
> G-05 and G-06 are partially mitigated by existing rules WEB-001
> (Directory Traversal) and WEB-003 (SQL Injection Attempt), which
> would fire if Flask access logs were parsed by the collector.

---

## [1.0.0] - 2026-03-01

> [!NOTE]
> Initial release of HomeLab SIEM — core functionality implemented.

### Added

- Log collection via file tailers and UDP syslog (port 5140)
- Log parsing for SSH/auth, Apache/Nginx, kernel/dmesg and syslog
- Rule engine with 8 built-in detection rules mapped to MITRE ATT&CK
- Live web dashboard — KPIs, timeline chart, alert table, event stream
- REST API — `/api/events`, `/api/alerts`, `/api/stats`, `/api/ingest`
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
- **MAJOR** — breaking changes to API or architecture
- **MINOR** — new features or detection rules
- **PATCH** — bug fixes and minor improvements
