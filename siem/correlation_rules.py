"""
correlation_rules.py — Motore di correlazione separato per sequenze di
eventi (source == "nim-agent", category == "correlation").

A differenza di process_rules.py e nim_lab_rules.py, che valutano UN
evento alla volta (match(event) -> bool), qui le regole valutano una
SEQUENZA di eventi correlati, incapsulata nel campo "fields.events" di un
evento con category == "correlation" prodotto da correlation_lab.nim.

Motore intenzionalmente separato (non innestato in RULES di detector.py):
la firma di match è diversa (guarda dentro una sequenza annidata, non
i campi di un evento piatto), e le regole di correlazione non devono MAI
scattare per un singolo indicatore isolato — solo per una combinazione di
eventi con una relazione riconoscibile (stessa catena di processo,
sequenza temporale coerente entro una finestra massima).
"""

MAX_CORRELATION_WINDOW_MS = 1000

DISCOVERY_UTILS = {"uname", "whoami", "id", "hostname", "ifconfig", "ip", "w", "who"}


def _is_correlation_event(event: dict) -> bool:
    events = event.get("fields", {}).get("events")
    return event.get("category") == "correlation" and isinstance(events, list)


def _sub_events(event: dict) -> list:
    return event.get("fields", {}).get("events", [])


def _unknown_parent_then_discovery(event: dict) -> bool:
    """
    Condizione CORR-001: un evento A (spawn con parent sconosciuto) seguito,
    entro MAX_CORRELATION_WINDOW_MS, da un evento B in cui il processo
    lanciato da A esegue un'utility di discovery. Nessuno dei due eventi
    preso da solo è necessariamente anomalo — il segnale nasce dalla
    sequenza e dalla coerenza temporale tra i due.
    """
    if not _is_correlation_event(event):
        return False

    subs = _sub_events(event)
    if len(subs) < 2:
        return False

    for i in range(len(subs) - 1):
        a, b = subs[i], subs[i + 1]
        a_fields = a.get("fields", {})
        b_fields = b.get("fields", {})

        a_is_unknown_parent_spawn = (
            a_fields.get("action") == "spawn"
            and a_fields.get("parent_process_name") == "unknown"
        )
        b_is_discovery_child_of_a = (
            b_fields.get("action") == "spawn"
            and b_fields.get("parent_process_name") == a_fields.get("process_name")
            and (b_fields.get("process_name") or "").lower() in DISCOVERY_UTILS
        )
        offset_a = a.get("timestamp_offset_ms", 0)
        offset_b = b.get("timestamp_offset_ms", 0)
        within_window = (offset_b - offset_a) <= MAX_CORRELATION_WINDOW_MS

        if a_is_unknown_parent_spawn and b_is_discovery_child_of_a and within_window:
            return True

    return False


CORRELATION_RULES = [
    {
        "id": "CORR-001",
        "name": "Discovery di sistema dopo processo con parent sconosciuto",
        "description": (
            "Un processo con parent non identificato genera, entro una "
            "finestra temporale ristretta, un processo figlio che esegue "
            "un'utility di discovery di sistema. Il segnale nasce dalla "
            "sequenza e dalla coerenza temporale, non da un singolo evento."
        ),
        "severity": "MEDIUM",
        "category": "correlation",
        "mitre": "T1082",
        "match": _unknown_parent_then_discovery,
        "threshold": None,
    },
]


def evaluate_correlation(event: dict) -> list[str]:
    """Punto di ingresso del motore: quali regole di correlazione scattano
    per questo evento (tipicamente un evento category == "correlation")."""
    return [rule["id"] for rule in CORRELATION_RULES if rule["match"](event)]
