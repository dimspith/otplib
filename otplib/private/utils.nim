import strutils, std/sha1

proc decodeBase32*(s: string): string =
  ## Decodes a base32 string.
  var ch, index, bits, buffer: int = 0

  # The resulting string is 5/8 the length of the original (rounded up)
  let strLen = (s.len * 5) div 8
  result.setLen(strLen)

  # Loop through the string, excluding the padding (=)
  for i in 0 ..< (s.len - s.count('=')):

    # Map character to it's base32 symbol chart value
    ch = s[i].ord
    case ch
    of 65..90:        # A-Z
      ch -= 65
    of 97..122:       # a-z
      ch -= 97
    of 50..55:        # 2-7
      ch -= 24
    else:
      raise newException(ValueError, "Non-base32 digit found: " & $ch)

    # Increase buffer's binary size by 5
    # i.e 10101 -> 1010100000 
    buffer = buffer shl 5

    # Append the character's value
    # i.e 1010100000 + 01110 -> 1010101110
    buffer = buffer or ch

    bits += 5

    if bits >= 8:
      bits -= 8

      # The result is the buffer truncated to 8 bits (1 char)
      result[index] = chr(buffer shr bits and 255)
      index += 1

proc toString(data: openarray[byte], start, stop: int): string =
  ## Slice a raw data blob into a string
  ## This is an inclusive slice
  ## The output string is null-terminated for raw C-compat
  assert start in 0 ..< data.len
  assert stop in 0 ..< data.len

  let len = stop - start + 1
  assert len in 0 .. data.len

  result = newString(len)
  copyMem(result[0].addr, data[start].unsafeAddr, len)

proc int_to_bytestring*(input: int, padding: int = 8): string {.inline.} =
  var input = input

  var arr: seq[char] = @[]
  while input != 0:
    arr.add(char(input and 0xFF))
    input = input shr 8

  while arr.len < padding:
    arr.add('\0')

  result = newString(arr.len)
  for i in 0..arr.len-1:
    result[i] = arr[arr.len - i - 1]


proc hmac_sha1*(key: string, message: string): SecureHash =

  # Default block size for sha1
  const blockSize: int = 64

  var
    newKey: seq[byte]
    outPadKey: seq[byte]
    inPadKey: seq[byte]

  # Shorten keys longer than blockSize by hashing
  if key.len > blockSize:
    for i in $secureHash(key):
      newKey.add(i.byte)
  else:
    for i in key:
      newKey.add(i.byte)

  # Pad key with zeros to the right if shorter than blocksize
  if newKey.len < blockSize:
    for i in 0 ..< blockSize - key.len:
      newKey.add(0.byte)

  # Generate outer padded and inner padded keys
  for i in 0 ..< blockSize:
    outPadKey.add(newKey[i] xor 0x5c)
    inPadKey.add(newKey[i] xor 0x36)

  # Append message bytes to outPadKey
  for bt in secureHash(inPadKey.toString(0, inPadKey.len-1) & message).Sha1Digest:
    outPadKey.add(bt)

  # Calculate the resulting hash
  result = secureHash(outPadKey.toString(0, outPadKey.len-1))

