from siem.correlation_rules import evaluate_correlation, CORRELATION_RULES


def _correlation_event(sub_events: list) -> dict:
    return {
        "source": "nim-agent",
        "category": "correlation",
        "fields": {
            "sequence_id": "CORR-TEST",
            "event_count": len(sub_events),
            "events": sub_events,
        },
    }


def _sub_event(event_id: str, offset_ms: int, action: str,
               process_name: str, parent_process_name: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp_offset_ms": offset_ms,
        "category": "behavior",
        "fields": {
            "action": action,
            "process_name": process_name,
            "parent_process_name": parent_process_name,
        },
    }


def test_positive_sequence_fires_corr_001():
    # Stessa identica forma prodotta da
    # correlation_lab.buildDiscoveryAfterUnexpectedParentSequence()
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "loader_test", "unknown"),
        _sub_event("evt-002", 150, "spawn", "uname", "loader_test"),
    ])
    assert evaluate_correlation(event) == ["CORR-001"]


def test_sequence_outside_time_window_does_not_fire():
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "loader_test", "unknown"),
        _sub_event("evt-002", 5000, "spawn", "uname", "loader_test"),  # troppo tardi
    ])
    assert evaluate_correlation(event) == []


def test_single_event_never_fires_correlation_rule():
    # Un singolo evento isolato, per quanto sospetto, non deve MAI far
    # scattare una regola di correlazione: serve la sequenza.
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "uname", "loader_test"),
    ])
    assert evaluate_correlation(event) == []


def test_known_parent_does_not_fire():
    # Il primo evento ha un parent noto (non "unknown"): non e' il pattern
    # cercato, anche se il secondo evento e' comunque una discovery utility.
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "some_tool", "bash"),
        _sub_event("evt-002", 100, "spawn", "uname", "some_tool"),
    ])
    assert evaluate_correlation(event) == []


def test_second_event_not_a_discovery_util_does_not_fire():
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "loader_test", "unknown"),
        _sub_event("evt-002", 100, "spawn", "ls", "loader_test"),  # non e' discovery
    ])
    assert evaluate_correlation(event) == []


def test_non_correlation_category_is_ignored():
    event = {"source": "nim-agent", "category": "behavior", "fields": {}}
    assert evaluate_correlation(event) == []


def test_empty_sub_events_list_does_not_fire():
    event = _correlation_event([])
    assert evaluate_correlation(event) == []


def test_correlation_rules_have_required_documentation_fields():
    # Ogni regola di correlazione deve documentare id/descrizione/severita'/
    # test positivo-negativo (qui verifichiamo solo la struttura del dict,
    # i test positivo/negativo sono le funzioni sopra).
    for rule in CORRELATION_RULES:
        assert rule["id"]
        assert rule["description"]
        assert rule["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert callable(rule["match"])
