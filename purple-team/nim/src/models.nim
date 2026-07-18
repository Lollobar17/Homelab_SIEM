## models.nim — Tipi dati di telemetria per il laboratorio Purple Team/SIEM.
##
## Responsabilità unica di questo modulo: definire COSA sono i dati.
## Non serializza, non invia, non genera scenari: quello è compito di
## telemetry.nim, sender.nim e scenarios.nim.
##
## Equivalente concettuale di agent/pkg/models/telemetry.go (Go), riscritto
## con i costrutti idiomatici di Nim.

const SchemaVersion* = "1.0"
  ## `const` = valore noto e fissato in fase di compilazione (non a runtime).
  ## Diverso da `let` (valore fissato a runtime, una volta) e da `var`
  ## (modificabile). Qui SchemaVersion non cambierà mai durante l'esecuzione,
  ## quindi `const` è la scelta più corretta e più efficiente delle tre.

type
  EventCategory* = enum
    ## Un `enum` è un insieme CHIUSO di valori. Il compilatore impedisce di
    ## passare una categoria che non esiste — a differenza di una stringa
    ## libera, che potrebbe contenere un refuso mai controllato.
    ##
    ## La sintassi `ecProcess = "process"` assegna a ogni membro anche una
    ## rappresentazione testuale: `$ecProcess` restituirà "process", pronta
    ## per finire in un campo JSON senza bisogno di una tabella di mapping.
    ecProcess = "process"
    ecTransform = "transform"
    ecArtifact = "artifact"
    ecLifecycle = "lifecycle"
    ecSignal = "signal"
    ecBehavior = "behavior"
    ecCorrelation = "correlation"

  ProcessContext* = object
    ## `object` = "struct". Ogni campo ha un tipo esplicito, nessuna inferenza.
    pid*: int
    ppid*: int
    processName*: string
    executablePath*: string
    commandLine*: string
    parentProcessName*: string
    sha256*: string
      ## Stringa vuota "" = campo assente. È l'equivalente Nim del tag Go
      ## `json:"sha256,omitempty"`: la decisione se includerlo nel JSON finale
      ## non si prende qui (models.nim non sa nulla di JSON), ma in
      ## telemetry.nim, che leggerà `sha256.len > 0`.

  EventData* = object
    action*: string
    childProcessName*: string
    childCommandLine*: string
    integrityLevel*: string

  Telemetry* = object
    ## Il modello "envelope" per eventi di tipo processo — equivalente 1:1
    ## della struct Go Telemetry. Gli altri laboratori (transform, artifact,
    ## lifecycle, ...) NON useranno ProcessContext/EventData: avranno il
    ## proprio modello dedicato definito nel loro stesso file, per rispettare
    ## il principio "una responsabilità per modulo". Questo tipo resta quindi
    ## specifico per la telemetria di processo, in parità con il Go agent.
    schemaVersion*: string
    agentId*: string
    hostname*: string
    timestamp*: string
    eventType*: string
    source*: string
      ## "nim-agent", per distinguere lato SIEM gli eventi generati da questo
      ## laboratorio da quelli del Go agent ("go-agent"), pur condividendo
      ## lo stesso schema di detection.
    category*: EventCategory
    processContext*: ProcessContext
    eventData*: EventData

  Result*[T] = object
    ## Generic: lo stesso `Result` funziona per qualsiasi T (Result[int],
    ## Result[Telemetry], Result[string], ...) — il tipo concreto si decide
    ## alla chiamata, non qui.
    ##
    ## `case isOk*: bool` rende questo un "object variante": a seconda del
    ## valore di isOk, l'oggetto ha in memoria SOLO i campi del ramo attivo
    ## (true → value, false → error). Provare a leggere `.error` quando
    ## isOk == true è un errore rilevato a runtime, non un campo "vuoto".
    ## È il modo Nim di dire "questa operazione può fallire, e il chiamante
    ## è OBBLIGATO a gestire entrambi i casi" — niente eccezioni silenziose.
    case isOk*: bool
    of true:
      value*: T
    of false:
      error*: string

proc ok*[T](value: T): Result[T] =
  ## Costruttore per il caso di successo. Il parametro `[T]` è dedotto dal
  ## tipo di `value` passato: `ok(42)` produce un Result[int] senza doverlo
  ## scrivere esplicitamente.
  Result[T](isOk: true, value: value)

proc err*[T](error: string): Result[T] =
  ## Qui invece T NON può essere dedotto (l'unico argomento è una stringa),
  ## quindi va specificato esplicitamente alla chiamata: err[Telemetry]("...").
  Result[T](isOk: false, error: error)

proc newProcessContext*(pid, ppid: int, processName, executablePath,
                         commandLine, parentProcessName: string,
                         sha256: string = ""): ProcessContext =
  ## `sha256: string = ""` è un parametro con valore di default: chi chiama
  ## questa proc può ometterlo, ed è il caso comune (la maggior parte degli
  ## eventi non porta un hash).
  ProcessContext(
    pid: pid, ppid: ppid, processName: processName,
    executablePath: executablePath, commandLine: commandLine,
    parentProcessName: parentProcessName, sha256: sha256
  )

proc newTelemetry*(agentId, hostname, timestamp, eventType: string,
                    category: EventCategory,
                    processContext: ProcessContext,
                    eventData: EventData): Telemetry =
  ## Costruttore esplicito. In Nim non esiste un "new Telemetry(...)"
  ## implicito come in linguaggi OOP classici: si scrive una proc che
  ## restituisce l'object già popolato. Il prefisso `newX` è la convenzione
  ## idiomatica Nim (si vedano newSeq, newString nella libreria standard).
  result = Telemetry(
    schemaVersion: SchemaVersion,
    agentId: agentId,
    hostname: hostname,
    timestamp: timestamp,
    eventType: eventType,
    source: "nim-agent",
    category: category,
    processContext: processContext,
    eventData: eventData
  )
  ## Nota su `result`: in Nim ogni proc con un tipo di ritorno ha una
  ## variabile implicita chiamata `result`, già inizializzata al valore di
  ## default del tipo (per un object, tutti i campi a zero/""). Assegnarla
  ## e non scrivere `return` esplicito è lo stile idiomatico più comune.

proc validate*(t: Telemetry): Result[Telemetry] =
  ## Primo vero utilizzo di Result: alcuni campi non hanno senso vuoti
  ## (un agentId vuoto è quasi certamente un bug a monte). Restituendo
  ## Result invece di sollevare un'eccezione, chi chiama è costretto dal
  ## compilatore a controllare `isOk` prima di usare `.value`.
  if t.agentId.len == 0:
    return err[Telemetry]("agentId non può essere vuoto")
  if t.hostname.len == 0:
    return err[Telemetry]("hostname non può essere vuoto")
  if t.processContext.pid < 0:
    return err[Telemetry]("pid non può essere negativo: " & $t.processContext.pid)
  ok(t)
