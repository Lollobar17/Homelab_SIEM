## test_models.nim — Test per src/models.nim
##
## Usa std/unittest, il framework di test incluso nella libreria standard
## di Nim: `suite` raggruppa i test in un blocco con un nome, `test` è un
## singolo caso, `check` è l'assert che, se falso, fa fallire il test
## mostrando l'espressione esatta che non ha funzionato (a differenza di un
## semplice `assert`, `check` continua a eseguire gli altri check nello
## stesso test invece di interrompersi al primo fallimento).

import std/unittest
import std/strutils
import ../src/models

suite "EventCategory (enum)":
  test "ogni categoria ha la rappresentazione stringa attesa":
    check $ecProcess == "process"
    check $ecTransform == "transform"
    check $ecCorrelation == "correlation"

suite "costruzione modelli":
  test "newProcessContext popola tutti i campi richiesti":
    let pc = newProcessContext(
      pid = 1234, ppid = 1,
      processName = "bash", executablePath = "/bin/bash",
      commandLine = "bash -c foo", parentProcessName = "systemd"
    )
    check pc.pid == 1234
    check pc.ppid == 1
    check pc.processName == "bash"
    check pc.sha256 == ""  # valore di default non passato

  test "newProcessContext con sha256 esplicito":
    let pc = newProcessContext(
      pid = 1, ppid = 0, processName = "x", executablePath = "/x",
      commandLine = "x", parentProcessName = "y", sha256 = "abc123"
    )
    check pc.sha256 == "abc123"

  test "newTelemetry assembla correttamente l'envelope":
    let pc = newProcessContext(1, 0, "loader_test", "/tmp/loader_test",
                                "loader_test", "bash")
    let ed = EventData(action: "spawn", childProcessName: "uname")
    let t = newTelemetry("agent-01", "host-01", "2026-07-17T10:00:00Z",
                          "process_creation", ecProcess, pc, ed)

    check t.schemaVersion == SchemaVersion
    check t.source == "nim-agent"
    check t.category == ecProcess
    check t.agentId == "agent-01"
    check t.eventData.action == "spawn"

suite "validate (Result generico + error handling)":
  test "telemetria valida ritorna isOk true":
    let pc = newProcessContext(100, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("agent-01", "host-01", "ts", "et", ecProcess, pc,
                          EventData(action: "spawn"))
    let res = validate(t)
    check res.isOk == true
    check res.value.agentId == "agent-01"

  test "agentId vuoto produce errore":
    let pc = newProcessContext(100, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("", "host-01", "ts", "et", ecProcess, pc,
                          EventData(action: "spawn"))
    let res = validate(t)
    check res.isOk == false
    check "agentId" in res.error

  test "hostname vuoto produce errore":
    let pc = newProcessContext(100, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("agent-01", "", "ts", "et", ecProcess, pc,
                          EventData(action: "spawn"))
    let res = validate(t)
    check res.isOk == false
    check "hostname" in res.error

  test "pid negativo produce errore":
    let pc = newProcessContext(-5, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("agent-01", "host-01", "ts", "et", ecProcess, pc,
                          EventData(action: "spawn"))
    let res = validate(t)
    check res.isOk == false
    check "pid" in res.error

  test "input multipli: piu' telemetrie in sequenza restano indipendenti":
    # Verifica che costruire piu' object in sequenza non condivida stato
    # (nessuna variabile globale mutabile nascosta in models.nim).
    var results: seq[Result[Telemetry]] = @[]
    for i in 0 .. 4:
      let pc = newProcessContext(i, 0, "proc" & $i, "/bin/proc" & $i,
                                  "proc" & $i, "parent")
      let t = newTelemetry("agent-" & $i, "host-" & $i, "ts", "et",
                            ecProcess, pc, EventData(action: "spawn"))
      results.add(validate(t))

    check results.len == 5
    for i, r in results:
      check r.isOk == true
      check r.value.agentId == "agent-" & $i

suite "Result[T] generico (senza Telemetry)":
  test "ok/err funzionano anche con tipi primitivi":
    let goodInt: Result[int] = ok(42)
    let badInt: Result[int] = err[int]("valore non valido")

    check goodInt.isOk == true
    check goodInt.value == 42
    check badInt.isOk == false
    check badInt.error == "valore non valido"

  test "ok/err funzionano con string":
    let r: Result[string] = ok("ciao")
    check r.isOk == true
    check r.value == "ciao"
