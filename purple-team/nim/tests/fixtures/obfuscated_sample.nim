proc xorDecode(data: seq[uint8], key: uint8): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b xor key)

proc main() =
  let encoded: seq[uint8] = @[0x2F'u8, 0x34'u8, 0x3B'u8, 0x37'u8, 0x3F'u8]
  let decoded = xorDecode(encoded, 0x5A'u8)
  echo "decodificato a runtime: ", decoded

main()
