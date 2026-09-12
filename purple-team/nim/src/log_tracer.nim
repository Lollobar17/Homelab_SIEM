## log_tracer.nim — Entry point for the log-triage tool.
##
## Reads raw log lines (the same shapes collector.py already tails: auth.log,
## Apache/Nginx/Flask access logs, kernel dmesg, syslog, Suricata eve.json),
## classifies each one against a whitelist/blacklist, drops known-good noise,
## and batches the rest into POST /api/v1/ingress — reusing sender.nim's
## retry/backoff HTTP transport unchanged, the same one main.nim already
## uses for the purple-team lab.
##
## The point isn't to replace detector.py's rule engine (stateful rules like
## AUTH-001's brute-force counting still need every real event) — it's to
## stop known-benign noise from ever reaching it, since analyze_event() +
## a SQLite write cost real CPU on constrained homelab hardware, and every
## deployment tails files that are mostly routine traffic.
##
## Usage:
##   ./log_tracer --rules=rules.json --input=/var/log/auth.log --source=auth.log
##   tail -F /var/log/auth.log | ./log_tracer --rules=rules.json --source=auth.log
##
## Env vars (same names as main.nim, for consistency across the lab):
##   SIEM_INGEST_URL   default: http://localhost:5000/api/v1/ingress
##   SIEM_AGENT_TOKEN  default: "" (no auth header sent)

import std/[parseopt, streams, os, json, times, strutils, tables]
import ./models
import ./sender
import ./log_ingest
import ./triage_matcher

type
  Config = object
    rulesPath: string
    inputPath: string    ## "" means stdin
    sourceName: string     ## label stored in `source`, e.g. "auth.log", "nginx-access"
    url: string
    token: string
    batchSize: int
    quiet: bool

proc getEnvOr(key, fallback: string): string =
  let v = getEnv(key)
  if v.len > 0: v else: fallback

proc assign(cfg: var Config, key, val: string) =
  case key
  of "rules", "r": cfg.rulesPath = val
  of "input", "i": cfg.inputPath = val
  of "source", "s": cfg.sourceName = val
  of "url", "u": cfg.url = val
  of "token", "t": cfg.token = val
  of "batch-size": cfg.batchSize = parseInt(val)
  else: discard

proc parseArgs(): Config =
  var cfg = Config(
    inputPath: "",
    sourceName: "log_tracer",
    url: getEnvOr("SIEM_INGEST_URL", "http://localhost:5000/api/v1/ingress"),
    token: getEnvOr("SIEM_AGENT_TOKEN", ""),
    batchSize: 50,
    quiet: false
  )
  var p = initOptParser()
  # std/parseopt doesn't associate space-separated long-option values
  # (`--rules foo.json`) automatically — only `--rules=foo.json`. `pending`
  # captures the option waiting for its value as the next cmdArgument.
  var pending = ""

  for kind, key, val in p.getopt():
    case kind
    of cmdLongOption, cmdShortOption:
      case key
      of "quiet", "q": cfg.quiet = true
      of "help", "h":
        echo "log_tracer --rules=<file.json> [--input=<file>] [--source=<label>] [--url=<ingress-url>] [--token=<agent-token>] [--batch-size=N] [--quiet]"
        quit(0)
      of "rules", "r", "input", "i", "source", "s", "url", "u", "token", "t", "batch-size":
        if val.len > 0: assign(cfg, key, val)
        else: pending = key
      else:
        stderr.writeLine("unknown option: " & key)
        quit(1)
    of cmdArgument:
      if pending.len > 0:
        assign(cfg, pending, key)
        pending = ""
      else:
        stderr.writeLine("unexpected argument: " & key)
        quit(1)
    of cmdEnd:
      discard

  if cfg.rulesPath.len == 0:
    stderr.writeLine("error: --rules is required")
    quit(1)
  result = cfg

# ── Rules loading (JSON — kept dependency-free, same rationale as before) ──

proc loadExactTable(node: JsonNode, key: string): Table[string, string] =
  result = initTable[string, string]()
  if node.hasKey(key):
    for k, v in node[key].pairs:
      result[k.toLowerAscii()] = v.getStr()

proc loadPatterns(node: JsonNode): seq[tuple[pattern: string, ruleId: string]] =
  result = @[]
  if node.hasKey("patterns"):
    for entry in node["patterns"]:
      result.add((pattern: entry["pattern"].getStr(), ruleId: entry["ruleId"].getStr()))

proc loadRuleSet(node: JsonNode): RuleSet =
  let exact = if node.hasKey("exact"): node["exact"] else: newJObject()
  result.exactSrcIp = loadExactTable(exact, "srcIp")
  result.exactProcess = loadExactTable(exact, "process")
  result.exactPath = loadExactTable(exact, "path")
  result.patterns = loadPatterns(node)

proc loadRules(path: string): Rules =
  if not fileExists(path):
    raise newException(IOError, "rules file not found: " & path)
  let root = parseJson(readFile(path))
  result.blacklist = if root.hasKey("blacklist"): loadRuleSet(root["blacklist"]) else: RuleSet()
  result.whitelist = if root.hasKey("whitelist"): loadRuleSet(root["whitelist"]) else: RuleSet()

# ── Ingress payload — same wire shape as telemetry.nim::buildGenericEvent,
#    but with `category` as a plain string: log_tracer's categories (auth,
#    web, kernel, syslog, suricata, generic) match collector.py's
#    _infer_category set, not the purple-team lab's EventCategory enum, so
#    telemetry.nim's typed helper doesn't apply here without widening an
#    enum that other lab modules depend on. ──────────────────────────────

proc isoNow(): string =
  now().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'")

proc buildIngressEvent(ev: ParsedEvent, info: MatchInfo, source: string): JsonNode =
  var fields = %*{
    "tracer_verdict": $info.verdict,
  }
  if info.ruleId.len > 0:
    fields["tracer_rule_id"] = %info.ruleId
    fields["tracer_matched_field"] = %info.field
  if ev.process.len > 0: fields["process"] = %ev.process
  if ev.hostname.len > 0: fields["hostname"] = %ev.hostname
  if ev.path.len > 0: fields["path"] = %ev.path
  if ev.httpMethod.len > 0: fields["method"] = %ev.httpMethod
  if ev.status.len > 0: fields["status"] = %ev.status
  if ev.signature.len > 0: fields["signature"] = %ev.signature

  let eventType = ev.category & (if info.verdict == vBlacklisted: ".flagged" else: ".observed")

  result = %*{
    "timestamp": isoNow(),
    "source": source,
    "category": ev.category,
    "event_type": eventType,
    "message": (if ev.message.len > 0: ev.message else: ev.raw),
    "fields": fields
  }
  if ev.srcIp.len > 0:
    result["source_ip"] = %ev.srcIp
  if info.verdict == vBlacklisted:
    result["severity"] = %"HIGH"

# ── Main loop ───────────────────────────────────────────────────────────

proc flush(cfg: Config, buffer: seq[JsonNode]) =
  if buffer.len == 0:
    return
  let body = %*{"source": cfg.sourceName, "detect": true, "events": buffer}
  let senderCfg = newSenderConfig(cfg.url, cfg.token)
  let res = send(senderCfg, $body)
  if res.isOk:
    if not cfg.quiet:
      stderr.writeLine("log_tracer: sent batch of " & $buffer.len & " events, status " & $res.value)
  else:
    stderr.writeLine("log_tracer: FAILED to send batch of " & $buffer.len & " events: " & res.error)

proc main() =
  let cfg = parseArgs()

  if not cfg.quiet:
    stderr.writeLine("log_tracer: loading rules from " & cfg.rulesPath)
  let compiled = compile(loadRules(cfg.rulesPath))

  if not cfg.quiet:
    stderr.writeLine("log_tracer: forwarding to " & cfg.url & " as source=\"" & cfg.sourceName & "\"")

  let inputStream: Stream =
    if cfg.inputPath.len == 0: newFileStream(stdin)
    else: newFileStream(cfg.inputPath, fmRead)
  if inputStream == nil:
    stderr.writeLine("error: could not open input " & (if cfg.inputPath.len == 0: "stdin" else: cfg.inputPath))
    quit(1)

  var buffer: seq[JsonNode] = @[]
  var blacklisted = 0
  var whitelisted = 0
  var unknown = 0
  var line: string

  while inputStream.readLine(line):
    if line.strip().len == 0:
      continue
    let ev = parseLogLine(line, cfg.sourceName)
    let info = classify(compiled, ev)
    case info.verdict
    of vBlacklisted:
      inc blacklisted
      buffer.add(buildIngressEvent(ev, info, cfg.sourceName))
    of vWhitelisted:
      inc whitelisted
      # dropped silently — the entire point of the triage layer
    of vUnknown:
      inc unknown
      buffer.add(buildIngressEvent(ev, info, cfg.sourceName))

    if buffer.len >= cfg.batchSize:
      flush(cfg, buffer)
      buffer.setLen(0)

  flush(cfg, buffer)

  if not cfg.quiet:
    stderr.writeLine("log_tracer: done — blacklisted=" & $blacklisted &
      " whitelisted(dropped)=" & $whitelisted & " unknown=" & $unknown)

when isMainModule:
  main()
