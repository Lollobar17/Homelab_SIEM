## system_event_lab.nim — Laboratorio B: eventi di avvio e durata.
##
## Genera la sequenza sintetica avvio -> inizializzazione -> caricamento
## componente -> esecuzione -> terminazione, come telemetria strutturata.
##
## Nessun meccanismo di installazione, persistenza o avvio automatico:
## solo modellazione della sequenza e verifica della sua coerenza, per
## studiare come una detection potrebbe correlare "evento iniziale ->
## sequenza di attività -> risultato -> terminazione".

import std/json
import ./models

type
  LifecycleStage* = enum
    lsStartup = "startup"
    lsInit = "init"
    lsComponentLoad = "component_load"
    lsExecution = "execution"
    lsTermination = "termination"

  LifecycleEvent* = object
    stage*: LifecycleStage
    sequenceNumber*: int
      ## Posizione nella sequenza (0, 1, 2, ...): permette a chi consuma
      ## la telemetria di ricostruire l'ordine anche se gli eventi
      ## arrivassero fuori ordine (es. per latenza di rete diversa).
    detail*: string

proc newLifecycleEvent*(stage: LifecycleStage, sequenceNumber: int,
                         detail: string = ""): LifecycleEvent =
  LifecycleEvent(stage: stage, sequenceNumber: sequenceNumber, detail: detail)

proc generateLifecycle*(componentName: string): seq[LifecycleEvent] =
  ## Sequenza fissa e deterministica: stesso componentName -> stessi eventi,
  ## sempre. Utile per test di regressione e per signal_coverage.nim, che
  ## dovrà confrontare "cosa ci si aspetta" con "cosa viene osservato".
  result = @[
    newLifecycleEvent(lsStartup, 0, "avvio del programma sintetico"),
    newLifecycleEvent(lsInit, 1, "inizializzazione delle risorse"),
    newLifecycleEvent(lsComponentLoad, 2, "caricamento componente: " & componentName),
    newLifecycleEvent(lsExecution, 3, "esecuzione della funzione principale"),
    newLifecycleEvent(lsTermination, 4, "terminazione pulita")
  ]

proc validateSequence*(events: seq[LifecycleEvent]): Result[seq[LifecycleEvent]] =
  ## Verifica che la sequenza sia internamente coerente: numerata in ordine
  ## crescente senza salti, e che l'ULTIMO evento sia davvero una
  ## terminazione (altrimenti la sequenza è "a metà", il che di per sé
  ## potrebbe essere interessante per una detection di correlazione).
  if events.len == 0:
    return err[seq[LifecycleEvent]]("sequenza vuota")

  for i, e in events:
    if e.sequenceNumber != i:
      return err[seq[LifecycleEvent]](
        "sequenceNumber fuori ordine alla posizione " & $i &
        " (atteso " & $i & ", trovato " & $e.sequenceNumber & ")")

  if events[^1].stage != lsTermination:
    ## `events[^1]` è l'ultimo elemento del seq: `^1` è l'operatore Nim di
    ## indicizzazione "dalla fine", equivalente a events[events.len - 1].
    return err[seq[LifecycleEvent]]("la sequenza non termina con lsTermination")

  ok(events)

proc toTelemetryFields*(e: LifecycleEvent): JsonNode =
  %*{
    "stage": $e.stage,
    "sequence_number": e.sequenceNumber,
    "detail": e.detail
  }
