"""
process_rules.py — Detection rules for host process telemetry (Go agent).
"""

SUSPICIOUS_DISCOVERY_UTILS = {"uname", "id", "whoami", "hostname", "ifconfig", "ip", "w", "who"}
EXPECTED_PARENTS = {"bash", "sh", "zsh", "dash", "cmd.exe", "powershell.exe", "ansible", "ssh", "systemd"}


def _child_name(event: dict) -> str:
    return (event.get("fields", {}).get("child_process_name") or "").lower()


def _parent_name(event: dict) -> str:
    return (event.get("fields", {}).get("process_name") or "").lower()


def _is_process_spawn(event: dict) -> bool:
    return (
        event.get("category") == "process"
        and event.get("fields", {}).get("action") == "spawn"
        and bool(_child_name(event))
    )


PROCESS_RULES = [
    {
        "id": "PROC-001",
        "name": "Discovery Utility Spawned by Unwhitelisted Process",
        "description": (
            "Un processo non presente nella whitelist di parent attesi ha "
            "generato un'utility di discovery di sistema. Comportamento "
            "coerente con un binario che offusca staticamente il comando "
            "(T1027) per poi eseguire discovery post-exploitation (T1082)."
        ),
        "severity": "HIGH",
        "category": "process",
        "mitre": "T1082",
        "match": lambda e: (
            _is_process_spawn(e)
            and _child_name(e) in SUSPICIOUS_DISCOVERY_UTILS
            and _parent_name(e) not in EXPECTED_PARENTS
        ),
        "threshold": None,
    },
    {
        "id": "PROC-002",
        "name": "Discovery Utility Spawned by Expected Parent",
        "description": (
            "Un'utility di discovery è stata lanciata da un parent atteso. "
            "Probabilmente benigno, segnalato a bassa severità per visibilità."
        ),
        "severity": "LOW",
        "category": "process",
        "mitre": "T1082",
        "match": lambda e: (
            _is_process_spawn(e)
            and _child_name(e) in SUSPICIOUS_DISCOVERY_UTILS
            and _parent_name(e) in EXPECTED_PARENTS
        ),
        "threshold": None,
    },
]
