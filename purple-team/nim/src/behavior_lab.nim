## behavior_lab.nim — Laboratorio D: analisi di comportamenti software.
##
## A differenza di scenarios.nim (che descrive COME costruire un evento),
## questo modulo documenta il comportamento da un punto di vista di
## detection engineering: cosa ci si aspetta, quali segnali produce, quale
## detection dovrebbe scattare, quali falsi positivi sono plausibili e
## quali sono i limiti noti. È un catalogo di DOCUMENTAZIONE strutturata,
## non di generazione di eventi.

import std/json
import ./models

type
  BehaviorProfile* = object
    scenarioId*: string
    expectedBehavior*: string
    signalsProduced*: seq[string]
    telemetryAvailable*: seq[string]
    expectedDetectionId*: string
    possibleFalsePositives*: seq[string]
    limitations*: string

proc newBehaviorProfile*(scenarioId, expectedBehavior: string,
                          signalsProduced, telemetryAvailable: seq[string],
                          expectedDetectionId: string,
                          possibleFalsePositives: seq[string],
                          limitations: string): BehaviorProfile =
  BehaviorProfile(
    scenarioId: scenarioId, expectedBehavior: expectedBehavior,
    signalsProduced: signalsProduced, telemetryAvailable: telemetryAvailable,
    expectedDetectionId: expectedDetectionId,
    possibleFalsePositives: possibleFalsePositives, limitations: limitations
  )

const BuiltinProfiles*: array[1, BehaviorProfile] = [
  newBehaviorProfile(
    "BEHAVIOR-001",
    "Un processo non presente nella whitelist attesa lancia un'utility " &
    "di discovery di sistema (es. uname).",
    @["process_creation event con child_process_name tra le utility di discovery"],
    @["telemetria di processo (Go agent o nim-agent)", "campo parent_process_name"],
    "PROC-001",
    @["automazione legittima (es. Ansible) non ancora presente nella whitelist",
      "script di provisioning interno non catalogato"],
    "La detection dipende interamente dal contenuto della whitelist dei " &
    "parent attesi: un nuovo strumento di automazione legittimo genera un " &
    "falso positivo finché non viene esplicitamente aggiunto alla lista."
  )
]

proc findProfile*(scenarioId: string): Result[BehaviorProfile] =
  for p in BuiltinProfiles:
    if p.scenarioId == scenarioId:
      return ok(p)
  err[BehaviorProfile]("profilo comportamentale non trovato per scenario: " & scenarioId)

proc toDocumentationJson*(p: BehaviorProfile): JsonNode =
  ## A differenza degli altri toTelemetryFields visti finora, qui il JSON
  ## non è "telemetria da inviare al SIEM" ma DOCUMENTAZIONE machine-readable
  ## del comportamento — utile per generare report o alimentare
  ## signal_coverage.nim con i dati attesi da confrontare con l'osservato.
  %*{
    "scenario_id": p.scenarioId,
    "expected_behavior": p.expectedBehavior,
    "signals_produced": p.signalsProduced,
    "telemetry_available": p.telemetryAvailable,
    "expected_detection_id": p.expectedDetectionId,
    "possible_false_positives": p.possibleFalsePositives,
    "limitations": p.limitations
  }
