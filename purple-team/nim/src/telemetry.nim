## telemetry.nim — Serializzazione: Nim model → JSON.
##
## Responsabilità unica: trasformare i tipi definiti in models.nim (o le
## "fields" grezze degli altri laboratori) nello schema WIRE che il SIEM
## si aspetta in ingresso:
##
##   {timestamp, source, category, event_type, message, fields{...}}
##
## Questo modulo NON apre connessioni HTTP (è compito di sender.nim) e NON
## decide COSA generare (è compito di scenarios.nim e dei laboratori
## didattici). Fa solo da "traduttore" tra modello e JSON.

import std/json
import ./models

proc toIngressPayload*(t: Telemetry): JsonNode =
  ## Equivalente della ToIngressPayload() del Go agent, per la telemetria
  ## di processo. Stessa logica: costruisce un messaggio leggibile, poi un
  ## oggetto "fields" con i campi sempre presenti, aggiungendo quelli
  ## opzionali solo se non vuoti (== "omitempty" in Go).
  let pc = t.processContext
  let ed = t.eventData

  let message = "process_creation pid=" & $pc.pid &
                " ppid=" & $pc.ppid &
                " process=" & pc.processName &
                " parent=" & pc.parentProcessName &
                " action=" & ed.action

  var fields = %*{
    "agent_id": t.agentId,
    "pid": pc.pid,
    "ppid": pc.ppid,
    "process_name": pc.processName,
    "executable_path": pc.executablePath,
    "command_line": pc.commandLine,
    "parent_process_name": pc.parentProcessName,
    "action": ed.action
  }
  ## `fields` è `var`, non `let`: a differenza dell'oggetto Telemetry (che
  ## costruiamo già completo), qui aggiungiamo chiavi condizionalmente dopo
  ## la creazione — serve poterlo modificare.

  if pc.sha256.len > 0:
    fields["sha256"] = %pc.sha256
  if ed.childProcessName.len > 0:
    fields["child_process_name"] = %ed.childProcessName
  if ed.childCommandLine.len > 0:
    fields["child_command_line"] = %ed.childCommandLine

  result = %*{
    "timestamp": t.timestamp,
    "source": t.source,
    "category": $t.category,
    "event_type": t.eventType,
    "message": message,
    "fields": fields
  }

proc buildGenericEvent*(category: EventCategory, eventType, message: string,
                         fields: JsonNode, timestamp: string,
                         source: string = "nim-agent"): JsonNode =
  ## I laboratori didattici che verranno dopo (transform_lab, artifact_analysis,
  ## system_event_lab, behavior_lab, correlation_lab) NON parlano di processi:
  ## non hanno un ProcessContext/EventData sensato. Userranno questa proc più
  ## generica, passando direttamente le proprie "fields" già costruite.
  ##
  ## Questo evita di duplicare qui la logica di assemblaggio dell'envelope
  ## per ogni singolo laboratorio: la responsabilità di "che forma ha
  ## l'envelope finale" resta unica, in questo modulo.
  result = %*{
    "timestamp": timestamp,
    "source": source,
    "category": $category,
    "event_type": eventType,
    "message": message,
    "fields": fields
  }

proc serialize*(payload: JsonNode): string =
  ## Converte il JsonNode in stringa compatta, pronta per il body di una
  ## richiesta HTTP POST (compito di sender.nim, non di questo modulo).
  $payload

proc parseIngressPayload*(raw: string): Result[JsonNode] =
  ## Percorso inverso: da stringa a JsonNode, con gestione esplicita
  ## dell'errore invece di lasciar propagare l'eccezione che std/json
  ## solleva su JSON malformato (JsonParsingError). Usato dai test e da
  ## eventuali laboratori che verificano un round-trip serializza→deserializza.
  try:
    ok(parseJson(raw))
  except JsonParsingError as e:
    err[JsonNode]("JSON non valido: " & e.msg)
