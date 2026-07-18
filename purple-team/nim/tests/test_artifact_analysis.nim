## test_artifact_analysis.nim — Test per src/artifact_analysis.nim
##
## A differenza degli altri test, questi girano contro DUE BINARI VERI,
## già compilati in tests/fixtures/: uno contiene "uname" in chiaro nel
## proprio codice sorgente, l'altro la stessa parola offuscata via XOR
## (stesso schema di purple-team/nim-loaders/loader.nim). Questo verifica
## che analyzeArtifact distingua davvero i due casi, non solo su dati finti.

import std/unittest
import std/os
import std/strutils
import std/json
import ../src/artifact_analysis

const FixturesDir = currentSourcePath().parentDir() / "fixtures"
const PlaintextBinary = FixturesDir / "plaintext_sample"
const ObfuscatedBinary = FixturesDir / "obfuscated_sample"

suite "extractPrintableStrings — funzione base":
  test "estrae solo sequenze abbastanza lunghe":
    let data = "ab\x00\x00\x00cdefgh\x01\x01xy"
    let strs = extractPrintableStrings(data, minLength = 4)
    check "cdefgh" in strs
    check "ab" notin strs   # troppo corta (< 4)
    check "xy" notin strs   # troppo corta (< 4)

  test "input vuoto produce seq vuoto":
    check extractPrintableStrings("").len == 0

  test "dato interamente non stampabile produce seq vuoto":
    check extractPrintableStrings("\x00\x01\x02\x03").len == 0

suite "analyzeArtifact — file inesistente":
  test "path inesistente produce errore, non un report vuoto":
    let res = analyzeArtifact("/percorso/che/non/esiste/xyz", "uname")
    check res.isOk == false
    check "non trovato" in res.error

suite "analyzeArtifact — binario con stringa in chiaro":
  test "'uname' viene trovato in chiaro":
    let res = analyzeArtifact(PlaintextBinary, "uname")
    check res.isOk == true
    check res.value.containsCleartext == true
    check res.value.sizeBytes > 0
    check res.value.extractedStrings.len > 0

suite "analyzeArtifact — binario XOR-offuscato":
  test "'uname' NON viene trovato in chiaro (era offuscato in fase di compilazione)":
    let res = analyzeArtifact(ObfuscatedBinary, "uname")
    check res.isOk == true
    check res.value.containsCleartext == false
    ## Questo e' esattamente cio' che il job CI esistente verifica con
    ## `strings loader_test | grep -qi uname` — qui la stessa verifica
    ## e' una funzione Nim testabile indipendentemente dalla CI.

  test "la ricerca e' case-insensitive":
    let res = analyzeArtifact(PlaintextBinary, "UNAME")
    check res.isOk == true
    check res.value.containsCleartext == true

suite "toTelemetryFields — metadati, non dump completo":
  test "i campi non includono la lista intera delle stringhe estratte":
    let res = analyzeArtifact(PlaintextBinary, "uname")
    let fields = toTelemetryFields(res.value)
    check not fields.hasKey("extracted_strings")
    check fields["extracted_strings_count"].getInt() > 0
    check fields["contains_cleartext"].getBool() == true
