## correlation_lab.nim — Laboratorio E: correlazione di segnali.
##
## Genera SEQUENZE di eventi correlati (evento A + evento B + coerenza
## temporale), non singoli eventi isolati. È l'input concettuale per un
## motore di correlazione lato SIEM (siem/correlation_rules.py), che
## guarda più eventi insieme invece di reagire a un singolo indicatore.

import std/json
import ./models

type
  CorrelationEvent* = object
    eventId*: string
    timestampOffsetMs*: int
      ## Offset in millisecondi RELATIVO al primo evento della sequenza,
      ## non un timestamp assoluto: rende gli scenari deterministici e
      ## facilmente testabili, senza dipendere dall'ora di sistema.
    category*: EventCategory
    fields*: JsonNode

  CorrelationSequence* = object
    id*: string
    description*: string
    events*: seq[CorrelationEvent]

proc newCorrelationEvent*(eventId: string, timestampOffsetMs: int,
                           category: EventCategory,
                           fields: JsonNode): CorrelationEvent =
  CorrelationEvent(eventId: eventId, timestampOffsetMs: timestampOffsetMs,
                    category: category, fields: fields)

proc newCorrelationSequence*(id, description: string,
                              events: seq[CorrelationEvent]): CorrelationSequence =
  CorrelationSequence(id: id, description: description, events: events)

proc isTemporallyCoherent*(s: CorrelationSequence, maxSpanMs: int): bool =
  ## Vero se tutti gli eventi della sequenza cadono entro una finestra
  ## temporale larga al massimo maxSpanMs. Una sequenza "corretta" nei
  ## contenuti ma spalmata su ore non rappresenta più lo stesso segnale.
  if s.events.len == 0:
    return true
  var minOffset = s.events[0].timestampOffsetMs
  var maxOffset = s.events[0].timestampOffsetMs
  for e in s.events:
    if e.timestampOffsetMs < minOffset: minOffset = e.timestampOffsetMs
    if e.timestampOffsetMs > maxOffset: maxOffset = e.timestampOffsetMs
  (maxOffset - minOffset) <= maxSpanMs

proc buildDiscoveryAfterUnexpectedParentSequence*(): CorrelationSequence =
  ## Esempio concreto del punto E del quadro concordato: evento A (spawn di
  ## un processo con parent sconosciuto) + evento B (quello stesso processo
  ## lancia un'utility di discovery) entro una finestra temporale breve.
  ## Nessuno dei due eventi preso da solo è necessariamente interessante:
  ## PROC-001 (lato Python) già segnala evento B da solo con parent non
  ## whitelisted; qui il valore aggiunto è la CATENA — lo stesso processo
  ## sconosciuto che compare e poi fa discovery, entro pochi millisecondi.
  let eventA = newCorrelationEvent(
    "evt-001", 0, ecBehavior,
    %*{"action": "spawn", "process_name": "loader_test",
       "parent_process_name": "unknown"}
  )
  let eventB = newCorrelationEvent(
    "evt-002", 150, ecBehavior,
    %*{"action": "spawn", "process_name": "uname",
       "parent_process_name": "loader_test"}
  )
  newCorrelationSequence(
    "CORR-001",
    "Processo con parent sconosciuto seguito a breve da discovery di sistema",
    @[eventA, eventB]
  )

proc toTelemetryFields*(s: CorrelationSequence): JsonNode =
  ## Costruisce un JArray esplicitamente (invece che con %* su un seq
  ## intero) perché ogni CorrelationEvent contiene già un JsonNode
  ## (`fields`) nidificato — serializzarlo con %* diretto è più leggibile
  ## fatto elemento per elemento.
  var eventsJson = newJArray()
  for e in s.events:
    eventsJson.add(%*{
      "event_id": e.eventId,
      "timestamp_offset_ms": e.timestampOffsetMs,
      "category": $e.category,
      "fields": e.fields
    })

  %*{
    "sequence_id": s.id,
    "description": s.description,
    "event_count": s.events.len,
    "events": eventsJson
  }
