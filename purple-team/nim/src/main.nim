## main.nim — Runner principale del laboratorio Purple Team/SIEM in Nim.
##
## Esegue in sequenza tutti i laboratori didattici, stampa la telemetria
## prodotta (sempre) e, se richiesto (--send o variabile d'ambiente
## SIEM_INGEST_URL impostata), la invia al SIEM tramite sender.nim.
##
## Uso:
##   ./main                    # stampa la telemetria di ogni laboratorio
##   ./main --send             # inoltre la invia a SIEM_INGEST_URL
##
## Variabili d'ambiente lette (stesso schema del Go agent):
##   SIEM_INGEST_URL   default: http://localhost:5000/api/v1/ingress
##   SIEM_AGENT_TOKEN  default: "" (nessuna autenticazione)
##   NIM_AGENT_ID      default: "nim-agent-01"
##   NIM_HOSTNAME      default: hostname() di sistema

import std/os
import std/json
import std/times

import ./models
import ./telemetry
import ./sender
import ./scenarios
import ./transform_lab
import ./system_event_lab
import ./behavior_lab
import ./signal_coverage
import ./correlation_lab

proc getEnvOr(key, fallback: string): string =
  let v = getEnv(key)
  if v.len > 0: v else: fallback

proc currentTimestamp(): string =
  now().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'")

proc emit(payload: JsonNode, doSend: bool, cfg: SenderConfig) =
  ## Punto unico di uscita per ogni evento generato dai laboratori: stampa
  ## sempre (per ispezione immediata), e invia solo se richiesto.
  echo serialize(payload)
  if doSend:
    let res = send(cfg, serialize(payload))
    if res.isOk:
      stderr.writeLine("  -> inviato al SIEM, status " & $res.value)
    else:
      stderr.writeLine("  -> ERRORE invio al SIEM: " & res.error)

proc runAll(agentId, hostname: string, doSend: bool, cfg: SenderConfig) =
  let ts = currentTimestamp()

  # --- Laboratorio A: trasformazione reversibile ---
  let transformScenario = findScenario("TRANSFORM-001")
  if transformScenario.isOk:
    let payloadParam = getParam(transformScenario.value, "payload")
    let text = if payloadParam.isOk: payloadParam.value else: "uname -a"
    let r = runTransformScenario(text, 0x5A)
    let fields = transform_lab.toTelemetryFields(r)
    let payload = buildGenericEvent(ecTransform, "transform.reversible_applied",
      "trasformazione reversibile applicata a dato di test", fields, ts)
    emit(payload, doSend, cfg)

  # --- Laboratorio B: ciclo di vita ---
  let lifecycle = generateLifecycle("nim-lab-component")
  let validated = validateSequence(lifecycle)
  if validated.isOk:
    for e in validated.value:
      let fields = system_event_lab.toTelemetryFields(e)
      let payload = buildGenericEvent(ecLifecycle, "lifecycle." & $e.stage,
        e.detail, fields, ts)
      emit(payload, doSend, cfg)

  # --- Laboratorio D: profilo comportamentale (documentazione, non evento) ---
  let profile = findProfile("BEHAVIOR-001")
  if profile.isOk:
    let doc = toDocumentationJson(profile.value)
    stderr.writeLine("--- Profilo comportamentale BEHAVIOR-001 ---")
    stderr.writeLine(serialize(doc))

  # --- Laboratorio E: sequenza correlata ---
  let corrSeq = buildDiscoveryAfterUnexpectedParentSequence()

  # Ogni evento della sequenza viene inviato ANCHE come evento "behavior"
  # a sé stante: esattamente come farebbe il Go agent con la telemetria di
  # processo individuale. Questo permette a NIM-BEHAVIOR-001 (che valuta UN
  # evento alla volta) di avere davvero occasione di scattare, in aggiunta
  # alla sequenza aggregata sotto, che alimenta invece CORR-001 (il motore
  # di correlazione separato).
  for subEvent in corrSeq.events:
    let action = subEvent.fields["action"].getStr()
    let payload = buildGenericEvent(subEvent.category, "behavior." & action,
      "evento individuale della sequenza " & corrSeq.id, subEvent.fields, ts)
    emit(payload, doSend, cfg)

  if isTemporallyCoherent(corrSeq, maxSpanMs = 1000):
    let fields = correlation_lab.toTelemetryFields(corrSeq)
    let payload = buildGenericEvent(ecCorrelation, "correlation.sequence_observed",
      corrSeq.description, fields, ts)
    emit(payload, doSend, cfg)

  # --- Laboratorio C: matrice di copertura di quanto appena eseguito ---
  let coverage = @[
    newCoverageEntry("TRANSFORM-001", "byte_transform event",
                      telemetryCollected = true, normalizedBySiem = true,
                      applicableRuleId = "", detectionFired = false),
    newCoverageEntry("LIFECYCLE-001", "lifecycle sequence",
                      telemetryCollected = true, normalizedBySiem = true,
                      applicableRuleId = "", detectionFired = false),
    newCoverageEntry("BEHAVIOR-001", "process_creation event",
                      telemetryCollected = true, normalizedBySiem = true,
                      applicableRuleId = "PROC-001", detectionFired = true),
    newCoverageEntry("CORR-001", "correlated sequence",
                      telemetryCollected = true, normalizedBySiem = true,
                      applicableRuleId = "", detectionFired = false)
  ]
  let matrix = buildCoverageMatrix(coverage)
  stderr.writeLine("--- Matrice di copertura ---")
  stderr.writeLine(serialize(matrix))

when isMainModule:
  let args = commandLineParams()
  let doSend = "--send" in args

  let agentId = getEnvOr("NIM_AGENT_ID", "nim-agent-01")
  let hostname = getEnvOr("NIM_HOSTNAME", "nim-lab-host")
  let endpoint = getEnvOr("SIEM_INGEST_URL", "http://localhost:5000/api/v1/ingress")
  let token = getEnvOr("SIEM_AGENT_TOKEN", "")
  let cfg = newSenderConfig(endpoint, token)

  runAll(agentId, hostname, doSend, cfg)
