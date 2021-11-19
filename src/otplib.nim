## This module implements One Time Password library.
import utils, std/sha1, math, std/random
from times import epochTime, getTime, toUnix, nanosecond

# Type definitions of HOTP and TOTP
type
  HOTP = object
    digits: int
    secret: string
  TOTP = object
    hotp: HOTP
    interval: int

proc genRandomSecret*(length: int): string =
  doAssert length > 0, msg="Secret length must not be 0!"

  # Initialize the random number generator
  let now = getTime()
  randomize(now.toUnix * 1_000_000_000 + now.nanosecond)

  # Pick `length` random characters.
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  result = newString(length)
  for i in 0..<length:
    result[i] = chars[rand(range[0..31])]
  

# Generate a HOTP code
func genHOTP(secret: string, counter: int, digits: int): int =

  # Calculate the MAC using the supplied secret/counter
  var hmac = hmac_sha1(decodeBase32(secret), int_to_bytestring(counter)).SHA1Digest

  # Take the 4 LSBs of the MAC and use them as an offset
  let offset = (hmac[19] and 0b1111).int
  
  # Fetch 31 bits starting from hmac[offset]
  let binaryCode: int = (hmac[offset].int   and 0b1111111)  shl 24 or
                        (hmac[offset+1].int and 0b11111111) shl 16 or
                        (hmac[offset+2].int and 0b11111111) shl 8  or
                        (hmac[offset+3].int and 0b11111111)

  result = binaryCode mod 10^digits



# Generate a new HOTP object
func newHOTP*(secret: string, digits: int = 6): HOTP =
  # Length must be 6-10 and 6-8 is recommended
  doAssert digits in 6..10, msg="Digits must be 6-10 (6-8 is recommended)"
  result = HOTP(
    secret: secret,
    digits: digits)

# Generate a new TOTP object
func newTOTP*(secret: string, digits: int = 6, interval: int = 30): TOTP =
  # Length must be 6-10 and 6-8 is recommended
  doAssert digits in 6..10, msg="Digits must be 6-10 (6-8 is recommended)"
  result = TOTP(
    hotp: HOTP(secret: secret, digits: digits),
    interval: interval)


## Generate a new HOTP code.
func gen*(hotp: HOTP, counter: int): int =
  result =  genHOTP(hotp.secret, counter, hotp.digits)

## Generate a new TOTP code.
proc gen*(totp: TOTP): int =
  let period = int(epochTime().int / totp.interval)
  result = genHOTP(totp.hotp.secret, period, totp.hotp.digits)
