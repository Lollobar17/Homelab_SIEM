from siem.nim_lab_rules import NIM_LAB_RULES


def _fire(event: dict) -> list[str]:
    fired = []
    for rule in NIM_LAB_RULES:
        if rule["match"](event) and (rule["threshold"] is None or rule["threshold"](event)):
            fired.append(rule["id"])
    return fired


def _nim_behavior_event(process_name: str, parent_process_name: str) -> dict:
    return {
        "source": "nim-agent",
        "category": "behavior",
        "fields": {
            "action": "spawn",
            "process_name": process_name,
            "parent_process_name": parent_process_name,
        },
    }


def test_unwhitelisted_parent_triggers_high_severity():
    event = _nim_behavior_event("uname", "loader_test")
    assert _fire(event) == ["NIM-BEHAVIOR-001"]


def test_expected_parent_triggers_only_low_severity():
    event = _nim_behavior_event("uname", "bash")
    assert _fire(event) == ["NIM-BEHAVIOR-002"]


def test_go_agent_process_events_are_not_matched_by_nim_rules():
    # Stesso pattern comportamentale ma source="go-agent": le regole Nim
    # non devono interferire con la telemetria del Go agent (quella la
    # copre process_rules.py).
    event = {
        "source": "go-agent",
        "category": "process",
        "fields": {"action": "spawn", "child_process_name": "uname",
                   "process_name": "loader_test"},
    }
    assert _fire(event) == []


def test_transform_category_never_fires_any_nim_rule():
    # Principio esplicito: nessuna detection per eventi transform/lifecycle.
    event = {
        "source": "nim-agent",
        "category": "transform",
        "fields": {"reversible": True, "key": 90},
    }
    assert _fire(event) == []


def test_lifecycle_category_never_fires_any_nim_rule():
    event = {
        "source": "nim-agent",
        "category": "lifecycle",
        "fields": {"stage": "execution", "sequence_number": 3},
    }
    assert _fire(event) == []


def test_benign_child_process_does_not_trigger():
    event = _nim_behavior_event("ls", "loader_test")
    assert _fire(event) == []


def test_missing_process_name_does_not_trigger():
    event = {
        "source": "nim-agent",
        "category": "behavior",
        "fields": {"action": "spawn", "parent_process_name": "bash"},
    }
    assert _fire(event) == []
