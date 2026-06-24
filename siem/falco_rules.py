"""
siem/falco_rules.py — Detection rules for Falco runtime security alerts.

Add to siem/detector.py after RULES definition:
    from siem.falco_rules import FALCO_RULES
    RULES.extend(FALCO_RULES)
"""

FALCO_RULES = [
    {
        "id": "FAL-001",
        "name": "Falco: Shell Spawned in Container",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1059",
        "description": "Interactive shell opened inside a running container",
        "match": lambda e: (
            e.get("source") == "falco"
            and "terminal shell in container" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-002",
        "name": "Falco: New Binary Dropped and Executed",
        "severity": "CRITICAL",
        "category": "runtime_security",
        "mitre": "T1059",
        "description": "New executable dropped and run inside container",
        "match": lambda e: (
            e.get("source") == "falco"
            and "drop and execute" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-003",
        "name": "Falco: Crypto Miner Detected",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1496",
        "description": "Crypto mining process detected inside container",
        "match": lambda e: (
            e.get("source") == "falco"
            and "crypto miner" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-004",
        "name": "Falco: Privileged Container Launched",
        "severity": "CRITICAL",
        "category": "runtime_security",
        "mitre": "T1611",
        "description": "Container launched with --privileged flag",
        "match": lambda e: (
            e.get("source") == "falco"
            and "privileged container" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-005",
        "name": "Falco: Privilege Escalation via Sudo",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1548.003",
        "description": "Sudo usage detected inside container",
        "match": lambda e: (
            e.get("source") == "falco"
            and "sudo" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-006",
        "name": "Falco: Container Escape Attempt",
        "severity": "CRITICAL",
        "category": "runtime_security",
        "mitre": "T1611",
        "description": "Container escape pattern detected",
        "match": lambda e: (
            e.get("source") == "falco"
            and "container escape" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-007",
        "name": "Falco: Ptrace Anti-Debug Syscall",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1055.008",
        "description": "ptrace() syscall — possible process injection",
        "match": lambda e: (
            e.get("source") == "falco"
            and "ptrace" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-008",
        "name": "Falco: Container Drift Detected",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1525",
        "description": "New file written to container layer at runtime",
        "match": lambda e: (
            e.get("source") == "falco"
            and "drift" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-009",
        "name": "Falco: Write to Binary Directory",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1574",
        "description": "Write to /bin, /sbin, /usr/bin — binary hijacking attempt",
        "match": lambda e: (
            e.get("source") == "falco"
            and any(x in e.get("fields", {}).get("rule", "").lower()
                    for x in ["write below binary", "modify binary"])
        ),
    },
    {
        "id": "FAL-010",
        "name": "Falco: Cron Job Modified",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1053.003",
        "description": "Cron configuration modified inside container",
        "match": lambda e: (
            e.get("source") == "falco"
            and "cron" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-011",
        "name": "Falco: Symlink Over Sensitive File",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1574.009",
        "description": "Symlink targeting sensitive file",
        "match": lambda e: (
            e.get("source") == "falco"
            and "symlink" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-012",
        "name": "Falco: Sensitive File Read",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1552",
        "description": "Process reading /etc/shadow or similar credential files",
        "match": lambda e: (
            e.get("source") == "falco"
            and "sensitive file" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-013",
        "name": "Falco: Environment Variables Read from /proc",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1552.007",
        "description": "Process reading /proc/*/environ — credential harvesting",
        "match": lambda e: (
            e.get("source") == "falco"
            and "/proc" in e.get("fields", {}).get("rule", "").lower()
            and "environ" in e.get("message", "").lower()
        ),
    },
    {
        "id": "FAL-014",
        "name": "Falco: Write to /etc Directory",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1562.001",
        "description": "Unauthorized write to /etc — configuration tampering",
        "match": lambda e: (
            e.get("source") == "falco"
            and "write below etc" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-015",
        "name": "Falco: Unexpected Outbound Network Connection",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1071",
        "description": "Container making unexpected outbound connection",
        "match": lambda e: (
            e.get("source") == "falco"
            and any(x in e.get("fields", {}).get("rule", "").lower()
                    for x in ["unexpected network", "outbound connection", "network connection outside"])
        ),
    },
    {
        "id": "FAL-016",
        "name": "Falco: Outbound Connection to Known C2",
        "severity": "CRITICAL",
        "category": "runtime_security",
        "mitre": "T1071",
        "description": "Container connecting to known C2 infrastructure",
        "match": lambda e: (
            e.get("source") == "falco"
            and "c2" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-017",
        "name": "Falco: Network Traffic Outside Local Subnet",
        "severity": "HIGH",
        "category": "runtime_security",
        "mitre": "T1048",
        "description": "Container sending data outside local subnet",
        "match": lambda e: (
            e.get("source") == "falco"
            and "outside local subnet" in e.get("fields", {}).get("rule", "").lower()
        ),
    },
    {
        "id": "FAL-018",
        "name": "Falco + ArachneC2: Runtime C2 Activity Confirmed",
        "severity": "CRITICAL",
        "category": "runtime_security",
        "mitre": "T1071.001",
        "description": "Falco detected network activity matching ArachneC2 pattern",
        "match": lambda e: (
            e.get("source") == "falco"
            and e.get("category") == "runtime_security"
            and e.get("severity") in ("HIGH", "CRITICAL")
            and any(x in e.get("message", "").lower()
                    for x in ["updates.microsoft.com", "beacon", "arachne", "4444"])
        ),
    },
]
