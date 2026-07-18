## scenarios.nim — Catalogo dichiarativo di scenari sintetici.
##
## Responsabilità unica: descrivere COSA rappresenta uno scenario (id, nome,
## descrizione, categoria, parametri), NON come costruirne l'evento o come
## inviarlo — quello è compito dei singoli laboratori (transform_lab.nim,
## system_event_lab.nim, ecc.) e di sender.nim.
##
## Tenere gli scenari come puri dati permette di elencarli, filtrarli o
## esportarli (es. per signal_coverage.nim) senza eseguire nulla.

import ./models

type
  ScenarioParam* = object
    key*: string
    value*: string
      ## Rappresentazione sempre come stringa: è il modo più semplice per
      ## restare "dato puro" senza dover creare una variante per ogni tipo
      ## possibile di parametro. Ogni laboratorio converte al tipo che gli
      ## serve (es. parseInt su "50" per ottenere un int).

  Scenario* = object
    id*: string
    name*: string
    description*: string
    category*: EventCategory
    params*: seq[ScenarioParam]
      ## `seq` = dimensione dinamica: scenari diversi hanno un numero
      ## diverso di parametri, e non lo sappiamo a priori in fase di
      ## scrittura del tipo.

proc param*(key, value: string): ScenarioParam =
  ScenarioParam(key: key, value: value)

proc newScenario*(id, name, description: string, category: EventCategory,
                   params: seq[ScenarioParam] = @[]): Scenario =
  ## `@[]` è la sintassi letterale per un seq vuoto (equivalente di `[]byte{}`
  ## o di una slice vuota in Go). Il default vuoto copre gli scenari che non
  ## hanno bisogno di parametri.
  Scenario(id: id, name: name, description: description,
           category: category, params: params)

proc getParam*(s: Scenario, key: string): Result[string] =
  ## Cerca un parametro per chiave. Restituisce Result invece di una
  ## stringa vuota in caso di assenza: una stringa vuota potrebbe essere un
  ## valore legittimo, quindi "non trovato" dev'essere un caso distinto e
  ## gestito esplicitamente da chi chiama.
  for p in s.params:
    if p.key == key:
      return ok(p.value)
  err[string]("parametro '" & key & "' non trovato nello scenario '" & s.id & "'")

const BuiltinScenarios*: array[4, Scenario] = [
  ## `array[4, Scenario]` = dimensione FISSA, nota qui in fase di scrittura
  ## del codice. Se in futuro aggiungo un quinto scenario e dimentico di
  ## aggiornare il "4", il compilatore rifiuta di compilare: a differenza
  ## di un seq, un array è anche una forma (leggera) di documentazione
  ## verificata dal compilatore.
  newScenario(
    "TRANSFORM-001", "Trasformazione reversibile di dato di test",
    "Applica una trasformazione reversibile (XOR) a una stringa di test " &
    "innocua e ne verifica la ricostruzione esatta.",
    ecTransform,
    @[param("payload", "uname -a"), param("xor_key", "90")]
  ),
  newScenario(
    "ARTIFACT-001", "Ispezione di un artefatto compilato",
    "Analizza le stringhe leggibili presenti in un piccolo binario di " &
    "test, distinguendo cosa è visibile staticamente da cosa richiede " &
    "esecuzione per essere osservato.",
    ecArtifact,
    @[param("target_binary", "loader_test")]
  ),
  newScenario(
    "LIFECYCLE-001", "Ciclo di vita minimo di un programma",
    "Genera la sequenza di eventi avvio -> inizializzazione -> " &
    "esecuzione -> terminazione per un programma sintetico.",
    ecLifecycle,
    @[param("duration_ms", "50")]
  ),
  newScenario(
    "BEHAVIOR-001", "Discovery di sistema da processo inatteso",
    "Simula un'utility di discovery (es. uname) lanciata da un parent " &
    "non presente nella whitelist attesa, per studiare falsi positivi " &
    "e limitazioni della detection corrispondente.",
    ecBehavior,
    @[param("child_process", "uname"), param("parent_process", "loader_test")]
  )
]

proc findScenario*(id: string): Result[Scenario] =
  ## Cerca uno scenario nel catalogo predefinito per id.
  for s in BuiltinScenarios:
    if s.id == id:
      return ok(s)
  err[Scenario]("scenario non trovato: " & id)

proc scenariosByCategory*(category: EventCategory): seq[Scenario] =
  ## Restituisce un seq perché il numero di scenari che corrispondono a una
  ## categoria non è noto a priori (potrebbero essere 0, 1, o molti).
  result = @[]
  for s in BuiltinScenarios:
    if s.category == category:
      result.add(s)
