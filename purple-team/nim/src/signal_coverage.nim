## signal_coverage.nim — Laboratorio C: segnali e copertura.
##
## Per ogni scenario, registra l'intera catena concettuale:
##   scenario -> segnale generato -> telemetria raccolta -> normalizzato
##   dal SIEM -> regola applicabile -> detection scattata -> livello di
##   visibilità (completa / parziale / assente).
##
## La visibilità NON si assegna a mano: si calcola dagli altri campi, per
## evitare che i due valori possano andare fuori sincrono tra loro.

import std/json

type
  VisibilityLevel* = enum
    vlFull = "full"        ## telemetria raccolta + normalizzata + regola + detection scattata
    vlPartial = "partial"  ## qualcosa è osservabile, ma la catena non è completa
    vlNone = "none"        ## nessuna visibilità: il comportamento è invisibile allo stack attuale

  CoverageEntry* = object
    scenarioId*: string
    signalGenerated*: string
    telemetryCollected*: bool
    normalizedBySiem*: bool
    applicableRuleId*: string
      ## stringa vuota = nessuna regola del SIEM si applica a questo segnale
    detectionFired*: bool
    visibility*: VisibilityLevel

proc computeVisibility(telemetryCollected, normalizedBySiem: bool,
                        applicableRuleId: string, detectionFired: bool): VisibilityLevel =
  if telemetryCollected and normalizedBySiem and
     applicableRuleId.len > 0 and detectionFired:
    vlFull
  elif telemetryCollected or normalizedBySiem:
    vlPartial
  else:
    vlNone

proc newCoverageEntry*(scenarioId, signalGenerated: string,
                        telemetryCollected, normalizedBySiem: bool,
                        applicableRuleId: string,
                        detectionFired: bool): CoverageEntry =
  ## `computeVisibility` è una proc privata (nessun `*`): usata solo qui
  ## dentro il modulo, non ha motivo di essere esportata.
  CoverageEntry(
    scenarioId: scenarioId,
    signalGenerated: signalGenerated,
    telemetryCollected: telemetryCollected,
    normalizedBySiem: normalizedBySiem,
    applicableRuleId: applicableRuleId,
    detectionFired: detectionFired,
    visibility: computeVisibility(telemetryCollected, normalizedBySiem,
                                   applicableRuleId, detectionFired)
  )

proc toTelemetryFields*(e: CoverageEntry): JsonNode =
  %*{
    "scenario_id": e.scenarioId,
    "signal_generated": e.signalGenerated,
    "telemetry_collected": e.telemetryCollected,
    "normalized_by_siem": e.normalizedBySiem,
    "applicable_rule_id": e.applicableRuleId,
    "detection_fired": e.detectionFired,
    "visibility": $e.visibility
  }

proc buildCoverageMatrix*(entries: seq[CoverageEntry]): JsonNode =
  ## Aggrega più CoverageEntry in un'unica matrice, con un piccolo riepilogo
  ## calcolato (quanti scenari sono completamente visibili) — utile per
  ## avere un colpo d'occhio senza dover contare a mano le singole voci.
  var arr = newJArray()
  var fullyVisibleCount = 0
  for e in entries:
    arr.add(toTelemetryFields(e))
    if e.visibility == vlFull:
      inc fullyVisibleCount

  %*{
    "coverage_matrix": arr,
    "total_scenarios": entries.len,
    "fully_visible_count": fullyVisibleCount
  }
