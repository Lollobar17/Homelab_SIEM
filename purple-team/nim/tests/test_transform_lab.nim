## test_transform_lab.nim — Test per src/transform_lab.nim

import std/unittest
import std/json
import std/strutils
import ../src/transform_lab

suite "toBytes / fromBytes — conversione base":
  test "round-trip stringa -> byte -> stringa restituisce l'originale":
    let original = "uname -a"
    let bytes = toBytes(original)
    check bytes.len == original.len
    check fromBytes(bytes) == original

  test "stringa vuota produce seq di byte vuoto":
    let bytes = toBytes("")
    check bytes.len == 0
    check fromBytes(bytes) == ""

suite "xorTransform — trasformazione reversibile":
  test "applicare la stessa chiave due volte restituisce il dato originale":
    let original = toBytes("test deterministico")
    let once = xorTransform(original, 0x5A)
    let twice = xorTransform(once, 0x5A)
    check twice == original

  test "la trasformazione cambia effettivamente i dati (non e' un no-op)":
    let original = toBytes("dato di prova")
    let transformed = xorTransform(original, 0x5A)
    check transformed != original

  test "chiave diversa NON recupera il dato originale":
    let original = toBytes("dato di prova")
    let transformed = xorTransform(original, 0x5A)
    let wrongRecovery = xorTransform(transformed, 0x11)
    check wrongRecovery != original

  test "seq vuoto resta vuoto dopo la trasformazione":
    let empty: seq[uint8] = @[]
    check xorTransform(empty, 0x5A).len == 0

suite "runTransformScenario — studio completo":
  test "scenario deterministico: stessa chiave e stesso testo ripetuti danno risultato identico":
    let r1 = runTransformScenario("dato di test", 0x5A)
    let r2 = runTransformScenario("dato di test", 0x5A)
    check r1.transformedBytes == r2.transformedBytes
    check r1.reversible == r2.reversible

  test "il risultato e' marcato reversibile e recovered == originale":
    let r = runTransformScenario("uname -a", 0x5A)
    check r.reversible == true
    check r.recoveredText == "uname -a"

  test "testo vuoto e' comunque uno scenario valido (deterministico)":
    let r = runTransformScenario("", 0x5A)
    check r.reversible == true
    check r.originalBytes.len == 0

suite "toTelemetryFields — metadati osservabili":
  test "i campi riportano lunghezza e reversibilita', non il testo in chiaro":
    let r = runTransformScenario("uname -a", 0x5A)
    let fields = toTelemetryFields(r)

    check fields["original_length"].getInt() == 8
    check fields["reversible"].getBool() == true
    check fields["key"].getInt() == 0x5A
    check not fields.hasKey("original_text")  # il testo in chiaro non è un metadato

  test "il prefisso hex e' limitato anche per input lunghi":
    let longText = "x".repeat(100)
    let r = runTransformScenario(longText, 0x5A)
    let fields = toTelemetryFields(r)
    check fields["transformed_hex_prefix"].getStr().len <= 16
