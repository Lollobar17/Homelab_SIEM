## test_correlation_lab.nim — Test per src/correlation_lab.nim

import std/unittest
import std/json
import ../src/models
import ../src/correlation_lab

suite "isTemporallyCoherent":
  test "sequenza vuota e' sempre coerente":
    let empty = newCorrelationSequence("X", "vuota", @[])
    check isTemporallyCoherent(empty, 1000) == true

  test "eventi entro la finestra sono coerenti":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    check isTemporallyCoherent(s, 1000) == true   # 150ms di span, finestra 1000ms

  test "eventi fuori dalla finestra NON sono coerenti":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    check isTemporallyCoherent(s, 100) == false   # 150ms di span, finestra 100ms

  test "un singolo evento e' sempre coerente (span zero)":
    let single = newCorrelationSequence("X", "singolo",
      @[newCorrelationEvent("e1", 0, ecBehavior, %*{"a": 1})])
    check isTemporallyCoherent(single, 0) == true

suite "buildDiscoveryAfterUnexpectedParentSequence":
  test "produce esattamente 2 eventi in ordine temporale":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    check s.events.len == 2
    check s.events[0].timestampOffsetMs < s.events[1].timestampOffsetMs

  test "il secondo evento referenzia lo stesso processo lanciato dal primo":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    check s.events[0].fields["process_name"].getStr() ==
          s.events[1].fields["parent_process_name"].getStr()

suite "toTelemetryFields":
  test "serializza correttamente numero e contenuto degli eventi":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    let fields = toTelemetryFields(s)

    check fields["sequence_id"].getStr() == "CORR-001"
    check fields["event_count"].getInt() == 2
    check fields["events"].len == 2
    check fields["events"][0]["event_id"].getStr() == "evt-001"
    check fields["events"][1]["fields"]["process_name"].getStr() == "uname"
