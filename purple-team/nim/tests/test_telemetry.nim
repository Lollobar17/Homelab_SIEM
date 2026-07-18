## test_telemetry.nim — Test per src/telemetry.nim

import std/unittest
import std/json
import ../src/models
import ../src/telemetry

suite "toIngressPayload — telemetria di processo":
  test "forma base: campi obbligatori sempre presenti":
    let pc = newProcessContext(100, 1, "bash", "/bin/bash", "bash -c x", "systemd")
    let ed = EventData(action: "exec")
    let t = newTelemetry("agent-01", "host-01", "2026-07-17T10:00:00Z",
                          "process_creation", ecProcess, pc, ed)
    let payload = toIngressPayload(t)

    check payload["timestamp"].getStr() == "2026-07-17T10:00:00Z"
    check payload["source"].getStr() == "nim-agent"
    check payload["category"].getStr() == "process"
    check payload["event_type"].getStr() == "process_creation"
    check payload["fields"]["agent_id"].getStr() == "agent-01"
    check payload["fields"]["pid"].getInt() == 100

  test "campi opzionali ASSENTI quando vuoti (omitempty)":
    let pc = newProcessContext(1, 0, "p", "/p", "p", "parent")  # sha256 default ""
    let ed = EventData(action: "spawn")  # childProcessName/CommandLine default ""
    let t = newTelemetry("a", "h", "ts", "et", ecProcess, pc, ed)
    let payload = toIngressPayload(t)

    check not payload["fields"].hasKey("sha256")
    check not payload["fields"].hasKey("child_process_name")
    check not payload["fields"].hasKey("child_command_line")

  test "campi opzionali PRESENTI quando valorizzati":
    let pc = newProcessContext(1, 0, "p", "/p", "p", "parent", sha256 = "deadbeef")
    let ed = EventData(action: "spawn", childProcessName: "uname",
                        childCommandLine: "uname -a")
    let t = newTelemetry("a", "h", "ts", "et", ecProcess, pc, ed)
    let payload = toIngressPayload(t)

    check payload["fields"]["sha256"].getStr() == "deadbeef"
    check payload["fields"]["child_process_name"].getStr() == "uname"
    check payload["fields"]["child_command_line"].getStr() == "uname -a"

suite "buildGenericEvent — laboratori non-processo":
  test "categoria transform con fields arbitrarie":
    let fields = %*{"original_len": 8, "transformed_len": 8, "reversible": true}
    let payload = buildGenericEvent(ecTransform, "byte_transform.applied",
                                     "trasformazione reversibile applicata a dato di test",
                                     fields, "2026-07-17T11:00:00Z")

    check payload["category"].getStr() == "transform"
    check payload["source"].getStr() == "nim-agent"
    check payload["fields"]["original_len"].getInt() == 8
    check payload["fields"]["reversible"].getBool() == true

  test "source personalizzabile (es. per differenziare scenari nello stesso lab)":
    let fields = %*{"note": "test"}
    let payload = buildGenericEvent(ecLifecycle, "lifecycle.start", "avvio",
                                     fields, "ts", source = "nim-lifecycle-lab")
    check payload["source"].getStr() == "nim-lifecycle-lab"

  test "fields vuote (oggetto JSON vuoto) sono accettate":
    let payload = buildGenericEvent(ecSignal, "signal.observed", "segnale osservato",
                                     %*{}, "ts")
    check payload["fields"].kind == JObject
    check payload["fields"].len == 0

suite "serialize + parseIngressPayload (round-trip)":
  test "serialize produce una stringa JSON valida che si ri-parsa identica":
    let pc = newProcessContext(5, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("a", "h", "ts", "et", ecProcess, pc, EventData(action: "exec"))
    let original = toIngressPayload(t)
    let asString = serialize(original)

    let reparsed = parseIngressPayload(asString)
    check reparsed.isOk == true
    check reparsed.value["fields"]["agent_id"].getStr() == "a"
    check reparsed.value["category"].getStr() == "process"

  test "JSON malformato produce errore gestito, non un crash":
    let res = parseIngressPayload("{questo non e' json valido")
    check res.isOk == false
    check res.error.len > 0

  test "stringa vuota e' JSON malformato":
    let res = parseIngressPayload("")
    check res.isOk == false

  test "input multipli: piu' round-trip in sequenza restano indipendenti":
    for i in 0 .. 3:
      let fields = %*{"index": i}
      let payload = buildGenericEvent(ecArtifact, "artifact.inspected",
                                       "ispezione artefatto #" & $i, fields, "ts")
      let reparsed = parseIngressPayload(serialize(payload))
      check reparsed.isOk == true
      check reparsed.value["fields"]["index"].getInt() == i
