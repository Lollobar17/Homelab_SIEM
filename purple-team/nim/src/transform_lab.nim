## transform_lab.nim — Laboratorio A: rappresentazione di dati in memoria e
## trasformazioni reversibili.
##
## Studia: conversione stringa<->byte, trasformazione reversibile (XOR),
## confronto tra rappresentazione originale e trasformata, metadati
## osservabili. SOLO dati di test innocui — questo modulo non esegue mai
## nulla, produce esclusivamente analisi e telemetria.
##
## Nota di design importante (dal quadro concordato): il fatto che un dato
## sia rappresentato in byte o trasformato NON è di per sé un segnale da
## trasformare in detection lato SIEM — qui produciamo solo metadati
## osservabili; è siem/nim_lab_rules.py a decidere, con altro contesto
## (es. provenienza, comportamento circostante), se e quando questo genere
## di dato diventa interessante per un analista.

import std/strutils
import std/json

type
  ByteTransformResult* = object
    originalText*: string
    originalBytes*: seq[uint8]
    transformedBytes*: seq[uint8]
    key*: uint8
    reversible*: bool
    recoveredText*: string

proc toBytes*(s: string): seq[uint8] =
  ## Conversione stringa -> sequenza di byte. `newSeq[uint8](s.len)` alloca
  ## un seq già della lunghezza corretta, evitando `add()` ripetuti.
  result = newSeq[uint8](s.len)
  for i, c in s:
    result[i] = uint8(c)

proc fromBytes*(data: seq[uint8]): string =
  ## Percorso inverso: byte -> stringa.
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc xorTransform*(data: seq[uint8], key: uint8): seq[uint8] =
  ## XOR è "involutorio": applicarlo due volte con la stessa chiave
  ## restituisce il dato originale. È la trasformazione reversibile più
  ## semplice possibile da studiare, e la stessa usata (con scopo diverso,
  ## offuscamento) nel loader.nim già esistente in purple-team/nim-loaders/.
  result = newSeq[uint8](data.len)
  for i, b in data:
    result[i] = b xor key

proc toHexString*(data: seq[uint8]): string =
  ## Rappresentazione esadecimale leggibile, utile per ispezionare a occhio
  ## una sequenza di byte senza stamparne i caratteri grezzi.
  result = ""
  for b in data:
    result.add(toHex(b.BiggestInt, 2))  # 2 cifre hex per byte, es. "5a"

proc runTransformScenario*(text: string, key: uint8): ByteTransformResult =
  ## Esegue l'intero studio: converte, trasforma, riconverte, confronta.
  let originalBytes = toBytes(text)
  let transformed = xorTransform(originalBytes, key)
  let recoveredBytes = xorTransform(transformed, key)  # stessa chiave -> torna indietro
  let recoveredText = fromBytes(recoveredBytes)

  result = ByteTransformResult(
    originalText: text,
    originalBytes: originalBytes,
    transformedBytes: transformed,
    key: key,
    reversible: recoveredText == text,
    recoveredText: recoveredText
  )

proc toTelemetryFields*(r: ByteTransformResult): JsonNode =
  ## Metadati OSSERVABILI: non il contenuto originale in chiaro, ma
  ## caratteristiche misurabili su di esso — lunghezza, reversibilità,
  ## un prefisso esadecimale limitato per ispezione. Questo è il tipo di
  ## informazione che un sistema di analisi statica potrebbe estrarre da
  ## un artefatto reale, senza eseguirlo.
  let hex = toHexString(r.transformedBytes)
  let hexPrefix = if hex.len > 16: hex[0 ..< 16] else: hex

  result = %*{
    "original_length": r.originalText.len,
    "transformed_length": r.transformedBytes.len,
    "key": r.key.int,
    "reversible": r.reversible,
    "transformed_hex_prefix": hexPrefix
  }
