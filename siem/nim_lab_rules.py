"""
nim_lab_rules.py — Detection rules per la telemetria generata dal
laboratorio Nim (eventi con "source": "nim-agent").

Stesso principio di siem/process_rules.py (che copre la telemetria del Go
agent), ma adattato allo schema wire prodotto da behavior_lab.nim /
correlation_lab.nim: qui la categoria è "behavior" invece di "process", e
i campi sono process_name/parent_process_name invece di
child_process_name/process_name usati dallo schema del Go agent.

Principio esplicito (dal quadro concordato con l'utente): NESSUNA regola
qui per eventi con category == "transform" o category == "lifecycle". Il
fatto che un dato sia rappresentato in byte, trasformato in modo
reversibile, o che un programma segua un normale ciclo di vita, non
costituisce di per sé un segnale di detection. Questi eventi restano
comunque visibili e normalizzati nel SIEM (osservabilità), ma non generano
alert: creare una detection "perché sì" per ogni tipo di evento
disponibile produce solo rumore e falsi positivi inutili.
"""

SUSPICIOUS_DISCOVERY_UTILS = {"uname", "whoami", "id", "hostname", "ifconfig", "ip", "w", "who"}
EXPECTED_PARENTS = {"bash", "sh", "zsh", "dash", "systemd", "ansible", "ssh"}


def _is_nim_behavior_spawn(event: dict) -> bool:
    return (
        event.get("source") == "nim-agent"
        and event.get("category") == "behavior"
        and event.get("fields", {}).get("action") == "spawn"
        and bool(event.get("fields", {}).get("process_name"))
    )


def _process_name(event: dict) -> str:
    return (event.get("fields", {}).get("process_name") or "").lower()


def _parent_process_name(event: dict) -> str:
    return (event.get("fields", {}).get("parent_process_name") or "").lower()


NIM_LAB_RULES = [
    {
        "id": "NIM-BEHAVIOR-001",
        "name": "Discovery utility (nim-agent) da parent non whitelisted",
        "description": (
            "Equivalente concettuale di PROC-001, per la telemetria prodotta "
            "dal laboratorio Nim: un'utility di discovery di sistema viene "
            "lanciata da un processo il cui parent non è tra quelli attesi."
        ),
        "severity": "HIGH",
        "category": "behavior",
        "mitre": "T1082",
        "match": lambda e: (
            _is_nim_behavior_spawn(e)
            and _process_name(e) in SUSPICIOUS_DISCOVERY_UTILS
            and _parent_process_name(e) not in EXPECTED_PARENTS
        ),
        "threshold": None,
    },
    {
        "id": "NIM-BEHAVIOR-002",
        "name": "Discovery utility (nim-agent) da parent atteso",
        "description": (
            "Stesso pattern di NIM-BEHAVIOR-001 ma con parent whitelisted: "
            "probabilmente benigno, severità bassa per sola visibilità."
        ),
        "severity": "LOW",
        "category": "behavior",
        "mitre": "T1082",
        "match": lambda e: (
            _is_nim_behavior_spawn(e)
            and _process_name(e) in SUSPICIOUS_DISCOVERY_UTILS
            and _parent_process_name(e) in EXPECTED_PARENTS
        ),
        "threshold": None,
    },
]
