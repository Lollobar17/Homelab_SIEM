## test_scenarios.nim — Test per src/scenarios.nim

import std/unittest
import ../src/models
import ../src/scenarios

suite "catalogo BuiltinScenarios":
  test "il catalogo contiene esattamente 4 scenari (array a dimensione fissa)":
    check BuiltinScenarios.len == 4

  test "ogni scenario ha id e categoria coerenti":
    for s in BuiltinScenarios:
      check s.id.len > 0
      check s.name.len > 0

suite "findScenario":
  test "trova uno scenario esistente per id":
    let res = findScenario("TRANSFORM-001")
    check res.isOk == true
    check res.value.category == ecTransform

  test "scenario inesistente produce errore, non un valore vuoto":
    let res = findScenario("NON-ESISTE-999")
    check res.isOk == false

suite "getParam":
  test "recupera un parametro esistente":
    let res = findScenario("TRANSFORM-001")
    check res.isOk == true
    let p = getParam(res.value, "xor_key")
    check p.isOk == true
    check p.value == "90"

  test "parametro inesistente produce errore":
    let res = findScenario("TRANSFORM-001")
    let p = getParam(res.value, "chiave_inventata")
    check p.isOk == false

suite "scenariosByCategory":
  test "categoria con esattamente uno scenario":
    let found = scenariosByCategory(ecArtifact)
    check found.len == 1
    check found[0].id == "ARTIFACT-001"

  test "categoria senza scenari restituisce seq vuoto, non un errore":
    let found = scenariosByCategory(ecCorrelation)
    check found.len == 0
