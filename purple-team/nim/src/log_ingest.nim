## log_ingest.nim — Parses raw log lines into the same shape collector.py
## already produces, so log_tracer can sit in front of it (or replace the
## file-tailing part of it) without changing what reaches the rule engine.
##
## Mirrors, line by line, the regex cases in siem/collector.py::parse_log_line:
##   1. SSH / auth.log      (sshd, sudo, su)
##   2. Apache / Nginx access log
##   3. Flask / Werkzeug access log
##   4. Kernel / dmesg
##   5. Suricata eve.json (only when source == "suricata")
##   6. Syslog with <priority>
##   7. Generic fallback — nothing is ever dropped at the parse stage
##
## Deliberately dependency-free: no PCRE (`std/re`) so the binary has zero
## shared-library requirements beyond libc. Parsing is done with plain
## substring/split logic, which is also measurably faster than backtracking
## regex for these fixed, simple grammars.

import std/[strutils, json, options, sequtils]

type
  ParsedEvent* = object
    raw*: string
    source*: string
    category*: string        ## "auth" | "web" | "kernel" | "suricata" | "syslog" | "generic"
    srcIp*: string
    process*: string          ## auth: sshd/sudo/su
    path*: string               ## web: request path (no query string)
    httpMethod*: string               ## web: GET/POST/...
    status*: string                 ## web: HTTP status code, as string
    message*: string                  ## free-text message, used for pattern matching
    signature*: string                  ## suricata: alert signature name
    hostname*: string                     ## journald: reporting host, when parsed

proc isDigits(s: string): bool =
  s.len > 0 and s.allCharsInSet(Digits)

proc looksLikeIso8601(s: string): bool =
  ## Crude but sufficient shape check for "YYYY-MM-DDTHH:MM:SS..." — used to
  ## tell a journald-exported line apart from classic "Mon DD HH:MM:SS" syslog,
  ## which tryParseAuth already handles via plain substring search.
  s.len >= 19 and
    s[4] == '-' and s[7] == '-' and s[10] == 'T' and s[13] == ':' and s[16] == ':' and
    s[0 .. 3].isDigits() and s[5 .. 6].isDigits() and s[8 .. 9].isDigits()

proc firstIp(s: string): string =
  ## Finds the first dotted-quad IPv4 substring in `s`, mirroring the
  ## Python collector's `\b(\d{1,3}(?:\.\d{1,3}){3})\b` extraction — used
  ## only on the auth.log path, so a small manual scanner is enough.
  let parts = s.split(' ')
  for token in parts:
    let cleaned = token.strip(chars = {'(', ')', ',', ':', ';'})
    let segs = cleaned.split('.')
    if segs.len == 4 and segs.allIt(it.isDigits() and it.len <= 3):
      return cleaned
  return ""

proc tryParseAuth(raw: string): Option[ParsedEvent] =
  ## Looks for "... sshd[1234]: message" / "... sudo: message" / "... su: message"
  ## / "... login[1234]: message" anywhere in the line, same as the Python
  ## regex (no anchoring to start). "login" is included because direct
  ## console/tty root logins (PAM's "ROOT LOGIN on '/dev/ttyN'") are as
  ## security-relevant as sshd/sudo and belong in the same "auth" category
  ## so detector.py's AUTH-* rules (which all require category=="auth")
  ## can actually see them.
  for proc_name in ["sshd", "sudo", "su", "login"]:
    let marker = proc_name & "["
    var idx = raw.find(marker)
    var procEnd = -1
    if idx >= 0:
      procEnd = raw.find("]:", idx)
    else:
      # form without a PID: "... sudo: message"
      idx = raw.find(proc_name & ":")
      if idx >= 0:
        procEnd = idx + proc_name.len
    if idx >= 0 and procEnd >= 0:
      let msgStart = raw.find(':', procEnd) + 1
      if msgStart > 0 and msgStart <= raw.len:
        let msg = raw[msgStart .. ^1].strip()
        var ev = ParsedEvent(raw: raw, category: "auth", process: proc_name, message: msg)
        ev.srcIp = firstIp(msg)
        return some(ev)
  return none(ParsedEvent)

proc tryParseWebAccess(raw: string): Option[ParsedEvent] =
  ## Handles both classic Apache/Nginx combined log and Flask/Werkzeug's
  ## `ip - - [date] "METHOD path HTTP/1.1" status` shape — they differ only
  ## in the "- ..." vs "- - ..." prefix, so one parser covers both.
  if " - " notin raw or " [" notin raw or "] \"" notin raw:
    return none(ParsedEvent)
  let ipEnd = raw.find(" - ")
  if ipEnd <= 0:
    return none(ParsedEvent)
  let ip = raw[0 ..< ipEnd]
  if firstIp(ip).len == 0:
    return none(ParsedEvent)   # doesn't start with an IP -> not this format

  let quoteStart = raw.find("\"")
  let quoteEnd = raw.find("\"", quoteStart + 1)
  if quoteStart < 0 or quoteEnd < 0:
    return none(ParsedEvent)
  let requestLine = raw[quoteStart + 1 ..< quoteEnd]
  let reqParts = requestLine.split(' ')
  if reqParts.len < 2:
    return none(ParsedEvent)

  let fullUri = reqParts[1]
  let path = fullUri.split('?')[0]

  # status code: first 3-digit token after the closing quote
  var status = ""
  let afterQuote = raw[quoteEnd + 1 .. ^1].strip()
  for token in afterQuote.split(' '):
    if token.len == 3 and token.isDigits():
      status = token
      break

  var ev = ParsedEvent(raw: raw, category: "web", srcIp: ip,
                        httpMethod: reqParts[0], path: path, status: status)
  ev.message = reqParts[0] & " " & fullUri
  return some(ev)

proc tryParseKernel(raw: string): Option[ParsedEvent] =
  ## "[12345.678901] message" — dmesg-style bracketed timestamp prefix.
  if not raw.startsWith("["):
    return none(ParsedEvent)
  let closeBracket = raw.find("]")
  if closeBracket < 0:
    return none(ParsedEvent)
  let inner = raw[1 ..< closeBracket]
  # timestamp body must look like digits/dots/spaces only
  for ch in inner:
    if ch notin Digits and ch != '.' and ch != ' ':
      return none(ParsedEvent)
  let msg = raw[closeBracket + 1 .. ^1].strip()
  if msg.len == 0:
    return none(ParsedEvent)
  return some(ParsedEvent(raw: raw, category: "kernel", message: msg))

proc tryParseSuricata(raw: string, source: string): Option[ParsedEvent] =
  if source != "suricata" or not raw.strip().startsWith("{"):
    return none(ParsedEvent)
  try:
    let node = parseJson(raw)
    if node.hasKey("event_type") and node["event_type"].getStr() == "alert":
      let alert = if node.hasKey("alert"): node["alert"] else: newJObject()
      var ev = ParsedEvent(raw: raw, category: "suricata")
      ev.signature = if alert.hasKey("signature"): alert["signature"].getStr() else: ""
      ev.srcIp = if node.hasKey("src_ip"): node["src_ip"].getStr() else: ""
      ev.message = ev.signature
      return some(ev)
  except JsonParsingError:
    discard
  return none(ParsedEvent)

proc tryParseSyslogPriority(raw: string): Option[ParsedEvent] =
  ## "<134>rest of message" — RFC 3164/5424 priority prefix.
  if not raw.startsWith("<"):
    return none(ParsedEvent)
  let closeAngle = raw.find(">")
  if closeAngle < 2:
    return none(ParsedEvent)
  let pri = raw[1 ..< closeAngle]
  if not pri.isDigits():
    return none(ParsedEvent)
  let msg = raw[closeAngle + 1 .. ^1].strip()
  return some(ParsedEvent(raw: raw, category: "syslog", message: msg))

proc tryParseJournald(raw: string): Option[ParsedEvent] =
  ## "<ISO8601-timestamp> <hostname> <process>[<pid>]: <message>" — what
  ## `auth.log` actually contains on systemd-journald-based systems (e.g.
  ## Ubuntu on WSL2) when it's a forwarded journal export rather than a
  ## classic rsyslog line. Non-auth daemons (polkitd, NetworkManager,
  ## systemd-logind, ...) end up here; sshd/sudo/su are already caught
  ## earlier by tryParseAuth's substring search regardless of the
  ## timestamp format in front of them.
  let idx1 = raw.find(' ')
  if idx1 < 0:
    return none(ParsedEvent)
  if not looksLikeIso8601(raw[0 ..< idx1]):
    return none(ParsedEvent)

  let idx2 = raw.find(' ', idx1 + 1)
  if idx2 < 0:
    return none(ParsedEvent)
  let hostname = raw[idx1 + 1 ..< idx2]
  let rest = raw[idx2 + 1 .. ^1]

  let colonIdx = rest.find(':')
  if colonIdx < 0:
    return none(ParsedEvent)
  let procPart = rest[0 ..< colonIdx].strip()
  let message = rest[colonIdx + 1 .. ^1].strip()
  if procPart.len == 0 or message.len == 0:
    return none(ParsedEvent)

  var procName = procPart
  let bracketIdx = procPart.find('[')
  if bracketIdx > 0:
    procName = procPart[0 ..< bracketIdx]

  # A real "process[pid]:" prefix never contains a space; if it does, this
  # colon just happened to appear inside an ordinary sentence, not a prefix.
  if procName.contains(' '):
    return none(ParsedEvent)

  result = some(ParsedEvent(raw: raw, category: "syslog", process: procName,
                             message: message, hostname: hostname))

proc parseLogLine*(raw: string, source: string): ParsedEvent =
  ## Best-effort parser: tries each known shape in the same priority order
  ## as collector.py, falls back to a generic "message = raw line" event so
  ## nothing is ever silently dropped at the parse stage — filtering
  ## decisions belong to matcher.nim, not here.
  let authResult = tryParseAuth(raw)
  if authResult.isSome: return authResult.get()

  let webResult = tryParseWebAccess(raw)
  if webResult.isSome: return webResult.get()

  let kernelResult = tryParseKernel(raw)
  if kernelResult.isSome: return kernelResult.get()

  let journaldResult = tryParseJournald(raw)
  if journaldResult.isSome: return journaldResult.get()

  let suricataResult = tryParseSuricata(raw, source)
  if suricataResult.isSome: return suricataResult.get()

  let syslogResult = tryParseSyslogPriority(raw)
  if syslogResult.isSome: return syslogResult.get()

  result = ParsedEvent(raw: raw, category: "generic", message: raw)
