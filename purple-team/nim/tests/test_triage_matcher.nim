import std/[unittest, tables]
import ../src/log_ingest
import ../src/triage_matcher

suite "triage_matcher":
  test "blacklist pattern match on message (SSH brute-force signal)":
    var bl = RuleSet()
    bl.patterns.add((pattern: "Failed password", ruleId: "TRIAGE-ssh-failed-password"))
    let rules = Rules(blacklist: bl, whitelist: RuleSet())
    let compiled = compile(rules)

    let ev = ParsedEvent(category: "auth", process: "sshd", message: "Failed password for root from 203.0.113.10 port 51234 ssh2")
    let info = classify(compiled, ev)
    check info.verdict == vBlacklisted
    check info.ruleId == "TRIAGE-ssh-failed-password"

  test "whitelist exact path drops known health-check noise":
    var wl = RuleSet()
    wl.exactPath["/api/health"] = "TRIAGE-known-healthcheck"
    let rules = Rules(blacklist: RuleSet(), whitelist: wl)
    let compiled = compile(rules)

    let ev = ParsedEvent(category: "web", path: "/api/health")
    let info = classify(compiled, ev)
    check info.verdict == vWhitelisted

  test "blacklist takes priority over whitelist on the same event":
    var bl = RuleSet()
    bl.exactSrcIp["185.220.101.1"] = "TRIAGE-known-tor-exit-node"
    var wl = RuleSet()
    wl.exactPath["/api/health"] = "TRIAGE-known-healthcheck"
    let rules = Rules(blacklist: bl, whitelist: wl)
    let compiled = compile(rules)

    let ev = ParsedEvent(category: "web", path: "/api/health", srcIp: "185.220.101.1")
    let info = classify(compiled, ev)
    check info.verdict == vBlacklisted
    check info.ruleId == "TRIAGE-known-tor-exit-node"

  test "no match falls through to unknown":
    let rules = Rules(blacklist: RuleSet(), whitelist: RuleSet())
    let compiled = compile(rules)

    let ev = ParsedEvent(category: "web", path: "/dashboard", srcIp: "10.0.0.5")
    let info = classify(compiled, ev)
    check info.verdict == vUnknown

  test "aho-corasick matches many blacklist patterns in one pass, case-insensitive":
    var bl = RuleSet()
    bl.patterns.add((pattern: "union select", ruleId: "TRIAGE-sqli-union-select"))
    bl.patterns.add((pattern: "/etc/passwd", ruleId: "TRIAGE-path-traversal-passwd"))
    bl.patterns.add((pattern: "/wp-admin", ruleId: "TRIAGE-wp-admin-scan"))
    let rules = Rules(blacklist: bl, whitelist: RuleSet())
    let compiled = compile(rules)

    let ev = ParsedEvent(category: "web", message: "GET /wp-admin/admin-ajax.php")
    let info = classify(compiled, ev)
    check info.verdict == vBlacklisted
    check info.ruleId == "TRIAGE-wp-admin-scan"
