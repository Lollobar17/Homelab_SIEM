"""tests/test_process_rules.py — Regression test per PROC-001/PROC-002."""

from siem.process_rules import PROCESS_RULES


def _fire(event: dict) -> list[str]:
    fired = []
    for rule in PROCESS_RULES:
        if rule["match"](event) and (rule["threshold"] is None or rule["threshold"](event)):
            fired.append(rule["id"])
    return fired


def _process_event(process_name: str, child_name: str) -> dict:
    return {
        "category": "process",
        "fields": {
            "action": "spawn",
            "process_name": process_name,
            "child_process_name": child_name,
            "child_command_line": f"{child_name} -a",
        },
    }


def test_unwhitelisted_parent_triggers_high_severity():
    event = _process_event(process_name="loader_test", child_name="uname")
    assert _fire(event) == ["PROC-001"]


def test_expected_parent_triggers_only_low_severity():
    event = _process_event(process_name="bash", child_name="uname")
    assert _fire(event) == ["PROC-002"]


def test_ansible_parent_does_not_trigger_high():
    event = _process_event(process_name="ansible", child_name="whoami")
    assert "PROC-001" not in _fire(event)


def test_non_process_category_is_ignored():
    event = {"category": "auth", "fields": {"message": "failed login"}}
    assert _fire(event) == []


def test_benign_child_process_does_not_trigger():
    event = _process_event(process_name="loader_test", child_name="ls")
    assert _fire(event) == []
