# Nim Log Tracer — Whitelist/Blacklist Pre-Filter Guide

## What This Does

Adds a fast, dependency-free log-triage stage in front of the ingestion
pipeline. It reads raw log lines in the same shapes `siem/collector.py`
already tails (SSH/`auth.log`, Apache/Nginx/Flask access logs, kernel
`dmesg`, syslog with `<priority>`, Suricata `eve.json`), classifies each
one against a whitelist/blacklist, and:

| Verdict | Action |
|---|---|
| **Whitelisted** | Dropped — never sent, never costs a rule-engine pass or a SQLite write |
| **Blacklisted** | Forwarded to `POST /api/v1/ingress`, tagged with a `TRIAGE-*` reference ID |
| **Unknown** | Forwarded to `POST /api/v1/ingress` unchanged, for `detector.py` to evaluate |

This does **not** replace the detection rule engine — stateful rules like
`AUTH-001` (SSH brute-force counting) still need every real event, so
every forwarded batch is sent with `"detect": true`. The point is purely
to stop routine, known-benign traffic (health checks, static assets,
successful logins from trusted hosts, ...) from ever reaching the rule
engine and the database, which matters on the constrained hardware this
project targets (see `docs/API_V1_GUIDE.md`).

Matching uses two strategies depending on the field:

- **Exact fields** (`srcIp`, `process`, `path`) — hash-table lookup, O(1)
  regardless of list size
- **Free text** (the parsed `message`) — a hand-rolled Aho-Corasick
  automaton, so matching against thousands of blacklist substrings costs
  one pass over the text, not one `contains()` call per pattern

---

## Prerequisites

- Nim ≥ 1.6 (`nim --version`) — no external packages needed, stdlib only
- `Homelab_SIEM` running (`python app.py`), reachable on its configured
  `web_port` (default `5000`)
- If `SIEM_AGENT_TOKEN` is set on the SIEM host, the same value is needed
  when running the tracer

---

## Where the code lives

The tracer is part of the existing `purple-team/nim` Nim project — it
reuses `sender.nim` (HTTP transport, retry with backoff, `X-Agent-Token`
auth) and `models.nim` (`Result[T]`) exactly as they already exist for the
purple-team lab. No existing lab file is modified except one line in
`nimble.nimble`.

```
purple-team/nim/src/log_ingest.nim       # raw line -> ParsedEvent
purple-team/nim/src/triage_matcher.nim   # whitelist/blacklist engine
purple-team/nim/src/log_tracer.nim       # CLI entry point
purple-team/nim/rules/sample_rules.json  # example whitelist/blacklist rules
purple-team/nim/tests/test_log_ingest.nim
purple-team/nim/tests/test_triage_matcher.nim
```

```diff
# nimble.nimble
- bin           = @["main"]
+ bin           = @["main", "log_tracer"]
```

---

## Build

```bash
cd purple-team/nim
nimble install
nim c -d:release -o:bin/log_tracer src/log_tracer.nim
```

## Run

```bash
./bin/log_tracer --rules=rules/sample_rules.json \
                  --input=/var/log/auth.log \
                  --source=auth.log \
                  --url=http://localhost:5000/api/v1/ingress
```

Or tail a live file into it, the same role `LogFileTailer` plays in
`collector.py`:

```bash
tail -F /var/log/auth.log | ./bin/log_tracer --rules=rules/sample_rules.json --source=auth.log
```

`SIEM_INGEST_URL` and `SIEM_AGENT_TOKEN` are read from the environment by
default — the same variable names `main.nim` already uses, so one `.env`
covers both the purple-team lab and the tracer.

> `std/parseopt` doesn't auto-associate space-separated long-option
> values — use `--flag=value`, not `--flag value`.

| Flag | Required | Default | Description |
|---|---|---|---|
| `--rules` | yes | — | Path to the whitelist/blacklist JSON |
| `--input` | no | stdin | File to read raw log lines from |
| `--source` | no | `log_tracer` | Stored as `source` on every forwarded event |
| `--url` | no | `$SIEM_INGEST_URL` or `http://localhost:5000/api/v1/ingress` | Ingress endpoint |
| `--token` | no | `$SIEM_AGENT_TOKEN` | Sent as `X-Agent-Token` if the SIEM has one configured |
| `--batch-size` | no | `50` | Events per POST (server max is 100) |
| `--quiet` | no | off | Suppress stderr progress/summary lines |

---

## Rules format

```json
{
  "blacklist": {
    "exact": { "srcIp": {}, "process": {}, "path": {} },
    "patterns": [ { "pattern": "Failed password", "ruleId": "TRIAGE-ssh-failed-password" } ]
  },
  "whitelist": { "...": "same shape" }
}
```

Rule IDs are prefixed `TRIAGE-` deliberately, so they can never collide
with real detection rule IDs (`AUTH-*`, `WEB-*`, `FAL-*`, `PROC-*`, ...).
They land in `fields.tracer_rule_id` as traceability metadata only — they
don't create alerts by themselves; `detector.py` still owns that.
Blacklist always wins over whitelist on the same event.

See `rules/sample_rules.json` for a worked example: SSH brute-force,
path-traversal, SQLi, WordPress-scanner, and OOM-killer on the blacklist
side; health-check, metrics, localhost, and successful-login on the
whitelist side.

---

## Forwarded event shape

Matches `siem/ingress.py::normalize_event` exactly:

```json
{
  "timestamp": "2026-07-19T07:54:36Z",
  "source": "auth.log",
  "category": "auth",
  "event_type": "auth.flagged",
  "message": "Failed password for root from 203.0.113.10 port 51234 ssh2",
  "source_ip": "203.0.113.10",
  "severity": "HIGH",
  "fields": {
    "tracer_verdict": "vBlacklisted",
    "tracer_rule_id": "TRIAGE-ssh-failed-password",
    "tracer_matched_field": "message",
    "process": "sshd"
  }
}
```

`severity` is only set (`HIGH`) for blacklisted events, and it's metadata
stored on the event — not what creates an alert. `detector.py`'s own
rules decide that independently, since `detect: true` runs on every batch.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `error: --rules is required` | Flag missing or wrong syntax | Must be `--rules=path`, not `--rules path` |
| `rules file not found` | Bad path | Check the path is relative to the working directory you ran `log_tracer` from |
| `FAILED to send batch ... Connection refused` | SIEM not running, or wrong `--url`/`SIEM_INGEST_URL` | Confirm `python app.py` is up and reachable on that host/port |
| `errore client non recuperabile: 401` | `SIEM_AGENT_TOKEN` set on the SIEM but `--token`/`SIEM_AGENT_TOKEN` missing or wrong on the tracer side | Set the same token on both sides |
| `errore client non recuperabile: 400` | Malformed batch, or empty `message`/`event_type` on every event | Shouldn't happen from normal log lines — check the input for binary/garbage data |
| Everything comes back `unknown`, nothing whitelisted | Rules file paths/patterns don't match your actual log format | Run a few real lines through `log_ingest` manually (unit tests in `tests/test_log_ingest.nim` show expected field extraction) |
| High CPU / DB growth didn't improve | Whitelist too narrow for your actual noise | Check `fields.tracer_verdict` on stored events to see what's slipping through as `unknown` and tune the whitelist |

---

## Why This Matters

Before: every single tailed log line — routine health checks, static
asset requests, successful logins — pays the full cost of `analyze_event()`
and a SQLite write.

After: known-benign noise never leaves the tracer. What reaches the SIEM
is exactly what's worth spending CPU and storage on: known-bad IOCs
(tagged for fast triage) and everything genuinely unclassified, still
fully evaluated by the real rule engine. On resource-constrained homelab
hardware, that's the difference between a SIEM that keeps up and one that
falls behind its own log volume.
