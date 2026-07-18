## artifact_analysis.nim — Analisi statica di artefatti compilati.
##
## Studia: quali stringhe restano leggibili in un binario compilato senza
## eseguirlo (analisi statica), e se un termine cercato compare in chiaro.
## Concettualmente la stessa domanda posta dal check CI già esistente su
## purple-team/nim-loaders/loader_test ("strings | grep uname non deve
## trovarlo"), ma qui come funzione Nim riutilizzabile e testabile invece
## che come singola riga di shell.
##
## Questo modulo LEGGE file dal disco ma non ne esegue mai il contenuto.

import std/os
import std/strutils
import std/json
import ./models

type
  ArtifactReport* = object
    path*: string
    sizeBytes*: int
    extractedStrings*: seq[string]
    containsCleartext*: bool
    searchedTerm*: string

proc extractPrintableStrings*(data: string, minLength: int = 4): seq[string] =
  ## Replica minimale di `strings`(1): individua sequenze contigue di
  ## caratteri ASCII stampabili lunghe almeno `minLength`.
  ##
  ## `{' '..'~'}` è un range di caratteri (da spazio a tilde, cioè tutto lo
  ## stampabile ASCII) usato come "set literal" — l'operatore `in` su un
  ## set di caratteri è O(1), diverso dall'`in` su stringa visto prima.
  result = @[]
  var current = ""
  for ch in data:
    if ch in {' '..'~'}:
      current.add(ch)
    else:
      if current.len >= minLength:
        result.add(current)
      current = ""
  if current.len >= minLength:
    result.add(current)

proc analyzeArtifact*(path: string, searchTerm: string,
                       minLength: int = 4): Result[ArtifactReport] =
  ## Legge un file e verifica se `searchTerm` compare in chiaro tra le
  ## stringhe stampabili estratte. Restituisce Result: un path inesistente
  ## è un errore da gestire esplicitamente, non un report vuoto silenzioso.
  if not fileExists(path):
    return err[ArtifactReport]("file non trovato: " & path)

  let data = readFile(path)
  let strs = extractPrintableStrings(data, minLength)

  var found = false
  let needle = searchTerm.toLowerAscii()
  for s in strs:
    if needle in s.toLowerAscii():
      found = true
      break

  ok(ArtifactReport(
    path: path,
    sizeBytes: data.len,
    extractedStrings: strs,
    containsCleartext: found,
    searchedTerm: searchTerm
  ))

proc toTelemetryFields*(r: ArtifactReport): JsonNode =
  ## Metadati osservabili: dimensione, numero di stringhe estratte, esito
  ## della ricerca. NON il dump completo delle stringhe (rumoroso e in
  ## parte ridondante con il file stesso) — solo ciò che serve a un
  ## analista per giudicare se approfondire.
  %*{
    "size_bytes": r.sizeBytes,
    "extracted_strings_count": r.extractedStrings.len,
    "searched_term": r.searchedTerm,
    "contains_cleartext": r.containsCleartext
  }
