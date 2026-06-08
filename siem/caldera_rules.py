"""
caldera_rules.py — MITRE Caldera purple-team rules (lightweight)

Only string/field checks — no regex, no counters, no external API calls.
Evaluated only when is_caldera_event() is True (see detector.py).
"""

from siem.caldera_parser import is_caldera_event


def _f(e: dict, key: str) -> str:
    return str((e.get("fields") or {}).get(key, "")).lower()


def _technique(e: dict) -> str:
    return str((e.get("fields") or {}).get("technique_id", "") or "").upper()


def _tactic(e: dict) -> str:
    return _f(e, "tactic")


def _matches_tactic(e: dict, *keywords: str) -> bool:
    t = _tactic(e)
    return any(k in t for k in keywords)


CALDERA_RULES = [
    {
        "id": "CAL-001",
        "name": "Caldera Ability Executed",
        "description": "MITRE Caldera executed an ability on a lab agent (purple team).",
        "severity": "MEDIUM",
        "category": "purple_team",
        "mitre": None,  # filled from technique_id at alert time
        "match": lambda e: (
            is_caldera_event(e)
            and "caldera" in _f(e, "event_type")
        ),
        "threshold": None,
    },
    {
        "id": "CAL-002",
        "name": "Caldera Lateral Movement",
        "description": "Caldera ability mapped to lateral movement.",
        "severity": "HIGH",
        "category": "purple_team",
        "mitre": "T1021",
        "match": lambda e: (
            is_caldera_event(e)
            and (
                _matches_tactic(e, "lateral")
                or _technique(e).startswith("T1021")
            )
        ),
        "threshold": None,
    },
    {
        "id": "CAL-003",
        "name": "Caldera Persistence",
        "description": "Caldera ability mapped to persistence.",
        "severity": "HIGH",
        "category": "purple_team",
        "mitre": "T1098",
        "match": lambda e: (
            is_caldera_event(e)
            and (
                _matches_tactic(e, "persist")
                or _technique(e).startswith("T1098")
            )
        ),
        "threshold": None,
    },
    {
        "id": "CAL-004",
        "name": "Caldera Command Execution",
        "description": "Caldera ran an execution-phase ability or shell command.",
        "severity": "MEDIUM",
        "category": "purple_team",
        "mitre": "T1059",
        "match": lambda e: (
            is_caldera_event(e)
            and (
                _matches_tactic(e, "execution")
                or _technique(e).startswith("T1059")
                or _technique(e).startswith("T1106")
                or bool(_f(e, "command"))
            )
        ),
        "threshold": None,
    },
    {
        "id": "CAL-005",
        "name": "Caldera Exfiltration",
        "description": "Caldera ability mapped to exfiltration.",
        "severity": "HIGH",
        "category": "purple_team",
        "mitre": "T1048",
        "match": lambda e: (
            is_caldera_event(e)
            and (
                _matches_tactic(e, "exfil")
                or _technique(e).startswith("T1048")
                or _technique(e).startswith("T1041")
            )
        ),
        "threshold": None,
    },
]
