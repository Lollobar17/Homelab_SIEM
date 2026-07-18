## test_behavior_lab.nim — Test per src/behavior_lab.nim

import std/unittest
import std/json
import ../src/behavior_lab

suite "findProfile":
  test "trova un profilo esistente":
    let res = findProfile("BEHAVIOR-001")
    check res.isOk == true
    check res.value.expectedDetectionId == "PROC-001"

  test "profilo inesistente produce errore":
    let res = findProfile("NON-ESISTE")
    check res.isOk == false

suite "toDocumentationJson":
  test "tutti i campi documentali sono presenti nel JSON":
    let res = findProfile("BEHAVIOR-001")
    let doc = toDocumentationJson(res.value)

    check doc["scenario_id"].getStr() == "BEHAVIOR-001"
    check doc["expected_detection_id"].getStr() == "PROC-001"
    check doc["signals_produced"].len > 0
    check doc["possible_false_positives"].len > 0
    check doc["limitations"].getStr().len > 0
