## loader.nim — Purple team test runner.
## Contiene "uname -a" offuscato via XOR statico (chiave 0x5A).
## A runtime decodifica ed esegue il comando, per validare che il sistema
## di detection lo riconosca via analisi comportamentale (non statica).

import std/osproc

proc xorDecode(data: seq[uint8], key: uint8): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b xor key)

proc main() =
  let encodedCmd: seq[uint8] = @[
    0x2F'u8, 0x34'u8, 0x3B'u8, 0x37'u8, 0x3F'u8, 0x7A'u8, 0x77'u8, 0x3B'u8
  ]
  let key = 0x5A'u8
  let decoded = xorDecode(encodedCmd, key)

  echo "[loader] eseguo comando decodificato a runtime"
  let (output, exitCode) = execCmdEx(decoded)
  echo "[loader] exit code: ", exitCode
  echo "[loader] output:"
  echo output

when isMainModule:
  main()
