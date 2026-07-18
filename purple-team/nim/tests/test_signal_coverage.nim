## test_signal_coverage.nim — Test per src/signal_coverage.nim

import std/unittest
import std/json
import ../src/signal_coverage

suite "newCoverageEntry — visibilita' calcolata automaticamente":
  test "catena completa -> visibilita' full":
    let e = newCoverageEntry("BEHAVIOR-001", "process_creation event",
                              telemetryCollected = true, normalizedBySiem = true,
                              applicableRuleId = "PROC-001", detectionFired = true)
    check e.visibility == vlFull

  test "telemetria raccolta ma nessuna regola applicabile -> partial":
    let e = newCoverageEntry("TRANSFORM-001", "byte_transform event",
                              telemetryCollected = true, normalizedBySiem = true,
                              applicableRuleId = "", detectionFired = false)
    check e.visibility == vlPartial

  test "telemetria raccolta ma non normalizzata -> partial":
    let e = newCoverageEntry("X", "segnale grezzo",
                              telemetryCollected = true, normalizedBySiem = false,
                              applicableRuleId = "", detectionFired = false)
    check e.visibility == vlPartial

  test "nessuna telemetria, nessuna normalizzazione -> none":
    let e = newCoverageEntry("X", "comportamento non osservato",
                              telemetryCollected = false, normalizedBySiem = false,
                              applicableRuleId = "", detectionFired = false)
    check e.visibility == vlNone

  test "regola applicabile ma detection NON scattata -> non e' full":
    # caso interessante: la regola esiste ma per qualche motivo non ha
    # fatto match (es. soglia non raggiunta) -> non possiamo dire "full"
    let e = newCoverageEntry("X", "segnale sotto soglia",
                              telemetryCollected = true, normalizedBySiem = true,
                              applicableRuleId = "PROC-001", detectionFired = false)
    check e.visibility == vlPartial

suite "buildCoverageMatrix":
  test "riepilogo conta correttamente gli scenari completamente visibili":
    let entries = @[
      newCoverageEntry("A", "sig-a", true, true, "RULE-A", true),   # full
      newCoverageEntry("B", "sig-b", true, true, "", false),        # partial
      newCoverageEntry("C", "sig-c", false, false, "", false),      # none
      newCoverageEntry("D", "sig-d", true, true, "RULE-D", true)    # full
    ]
    let matrix = buildCoverageMatrix(entries)

    check matrix["total_scenarios"].getInt() == 4
    check matrix["fully_visible_count"].getInt() == 2
    check matrix["coverage_matrix"].len == 4

  test "matrice vuota produce riepilogo coerente (zero, non errore)":
    let matrix = buildCoverageMatrix(@[])
    check matrix["total_scenarios"].getInt() == 0
    check matrix["fully_visible_count"].getInt() == 0
    check matrix["coverage_matrix"].len == 0
