## test_system_event_lab.nim — Test per src/system_event_lab.nim

import std/unittest
import std/strutils
import std/json
import ../src/system_event_lab

suite "generateLifecycle — sequenza deterministica":
  test "produce esattamente 5 eventi nell'ordine atteso":
    let events = generateLifecycle("componente-test")
    check events.len == 5
    check events[0].stage == lsStartup
    check events[1].stage == lsInit
    check events[2].stage == lsComponentLoad
    check events[3].stage == lsExecution
    check events[4].stage == lsTermination

  test "stesso componentName produce sempre la stessa sequenza":
    let a = generateLifecycle("x")
    let b = generateLifecycle("x")
    check a == b

  test "il nome del componente compare nel dettaglio del caricamento":
    let events = generateLifecycle("mio-componente")
    check "mio-componente" in events[2].detail

suite "validateSequence — sequenza valida":
  test "una sequenza generata normalmente e' valida":
    let events = generateLifecycle("x")
    let res = validateSequence(events)
    check res.isOk == true
    check res.value.len == 5

suite "validateSequence — sequenza vuota":
  test "seq vuoto produce errore":
    let res = validateSequence(@[])
    check res.isOk == false
    check "vuota" in res.error

suite "validateSequence — sequenza rotta (input costruiti a mano)":
  test "sequenceNumber fuori ordine viene rilevato":
    let broken = @[
      newLifecycleEvent(lsStartup, 0),
      newLifecycleEvent(lsInit, 5),  # salto: dovrebbe essere 1
      newLifecycleEvent(lsTermination, 2)
    ]
    let res = validateSequence(broken)
    check res.isOk == false
    check "fuori ordine" in res.error

  test "sequenza che non termina con lsTermination viene rilevata":
    let incomplete = @[
      newLifecycleEvent(lsStartup, 0),
      newLifecycleEvent(lsInit, 1),
      newLifecycleEvent(lsExecution, 2)
      # manca la terminazione: sequenza "a meta'"
    ]
    let res = validateSequence(incomplete)
    check res.isOk == false
    check "lsTermination" in res.error or "terminazione" in res.error

  test "singolo evento di terminazione e' una sequenza valida (caso limite)":
    let single = @[newLifecycleEvent(lsTermination, 0)]
    let res = validateSequence(single)
    check res.isOk == true

suite "toTelemetryFields":
  test "il campo stage e' la rappresentazione stringa dell'enum":
    let e = newLifecycleEvent(lsExecution, 3, "dettaglio di test")
    let fields = toTelemetryFields(e)
    check fields["stage"].getStr() == "execution"
    check fields["sequence_number"].getInt() == 3
    check fields["detail"].getStr() == "dettaglio di test"
