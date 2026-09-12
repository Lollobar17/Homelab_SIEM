## triage_matcher.nim — Whitelist/blacklist matching engine.
##
## Same two strategies as before, retargeted at the fields log_ingest.nim
## actually produces from real Homelab_SIEM log sources:
##  - exact fields (srcIp, process, path)   -> Table lookup, O(1)
##  - free text (message)                    -> Aho-Corasick, O(n) per event
##                                               regardless of pattern count
##
## Blacklist always wins over whitelist on the same event: a known-bad IP
## hitting a whitelisted health-check path still gets flagged.

import std/[tables, strutils]
import log_ingest

type
  Verdict* = enum
    vBlacklisted    ## known-bad -> forward, tagged, detect=true
    vWhitelisted    ## known-good noise -> drop, never sent
    vUnknown        ## neither -> forward for the real rule engine to see

  MatchInfo* = object
    verdict*: Verdict
    ruleId*: string     ## tracer-side tag, prefixed TRIAGE- to avoid any
                          ## collision with real detection rule IDs (AUTH-*,
                          ## WEB-*, FAL-*, ...) — this is metadata, not a
                          ## replacement for detector.py's rule engine.
    field*: string      ## which field matched

  RuleSet* = object
    exactSrcIp*: Table[string, string]
    exactProcess*: Table[string, string]
    exactPath*: Table[string, string]
    patterns*: seq[tuple[pattern: string, ruleId: string]]   ## matched against `message`

  Rules* = object
    blacklist*: RuleSet
    whitelist*: RuleSet

# ── Aho-Corasick automaton (same construction as before) ─────────────────

type
  ACNode = object
    children: Table[char, int]
    fail: int
    output: seq[int]

  AhoCorasick = object
    nodes: seq[ACNode]
    ruleIds: seq[string]

proc newAhoCorasick(): AhoCorasick =
  result.nodes = @[ACNode(fail: 0)]

proc addPattern(ac: var AhoCorasick, pattern, ruleId: string) =
  var node = 0
  for ch in pattern:
    if ch notin ac.nodes[node].children:
      ac.nodes.add(ACNode(fail: 0))
      ac.nodes[node].children[ch] = ac.nodes.len - 1
    node = ac.nodes[node].children[ch]
  ac.ruleIds.add(ruleId)
  ac.nodes[node].output.add(ac.ruleIds.len - 1)

proc buildAC(patterns: seq[tuple[pattern: string, ruleId: string]]): AhoCorasick =
  result = newAhoCorasick()
  for p in patterns:
    result.addPattern(p.pattern.toLowerAscii(), p.ruleId)

  var queue: seq[int] = @[]
  for ch, childIdx in result.nodes[0].children:
    result.nodes[childIdx].fail = 0
    queue.add(childIdx)

  var head = 0
  while head < queue.len:
    let current = queue[head]
    inc head
    for ch, childIdx in result.nodes[current].children:
      let fallback = result.nodes[current].fail
      var failState = fallback
      if ch in result.nodes[fallback].children and result.nodes[fallback].children[ch] != childIdx:
        failState = result.nodes[fallback].children[ch]
      elif current == 0:
        failState = 0
      result.nodes[childIdx].fail = failState
      result.nodes[childIdx].output.add(result.nodes[failState].output)
      queue.add(childIdx)

proc firstMatch(ac: AhoCorasick, text: string): int =
  if ac.ruleIds.len == 0:
    return -1
  let lowered = text.toLowerAscii()
  var state = 0
  for ch in lowered:
    while state != 0 and ch notin ac.nodes[state].children:
      state = ac.nodes[state].fail
    if ch in ac.nodes[state].children:
      state = ac.nodes[state].children[ch]
    else:
      state = 0
    if ac.nodes[state].output.len > 0:
      return ac.nodes[state].output[0]
  return -1

# ── Compiled rule sets ────────────────────────────────────────────────────

type
  CompiledRuleSet = object
    exactSrcIp: Table[string, string]
    exactProcess: Table[string, string]
    exactPath: Table[string, string]
    ac: AhoCorasick

  CompiledRules* = object
    blacklist: CompiledRuleSet
    whitelist: CompiledRuleSet

proc compileRuleSet(rs: RuleSet): CompiledRuleSet =
  result.exactSrcIp = rs.exactSrcIp
  result.exactProcess = rs.exactProcess
  result.exactPath = rs.exactPath
  result.ac = buildAC(rs.patterns)

proc compile*(rules: Rules): CompiledRules =
  result.blacklist = compileRuleSet(rules.blacklist)
  result.whitelist = compileRuleSet(rules.whitelist)

proc evaluate(rs: CompiledRuleSet, ev: ParsedEvent): MatchInfo =
  if ev.srcIp.len > 0 and ev.srcIp in rs.exactSrcIp:
    return MatchInfo(ruleId: rs.exactSrcIp[ev.srcIp], field: "srcIp")
  if ev.process.len > 0 and ev.process.toLowerAscii() in rs.exactProcess:
    return MatchInfo(ruleId: rs.exactProcess[ev.process.toLowerAscii()], field: "process")
  if ev.path.len > 0 and ev.path.toLowerAscii() in rs.exactPath:
    return MatchInfo(ruleId: rs.exactPath[ev.path.toLowerAscii()], field: "path")
  if ev.message.len > 0:
    let idx = rs.ac.firstMatch(ev.message)
    if idx >= 0:
      return MatchInfo(ruleId: rs.ac.ruleIds[idx], field: "message")
  return MatchInfo(ruleId: "", field: "")

proc classify*(rules: CompiledRules, ev: ParsedEvent): MatchInfo =
  let bl = evaluate(rules.blacklist, ev)
  if bl.ruleId.len > 0:
    result = bl
    result.verdict = vBlacklisted
    return result

  let wl = evaluate(rules.whitelist, ev)
  if wl.ruleId.len > 0:
    result = wl
    result.verdict = vWhitelisted
    return result

  result = MatchInfo(verdict: vUnknown, ruleId: "", field: "")
