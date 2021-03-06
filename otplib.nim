## This library handles generation and usage of One Time Passwords (HOTP & TOTP).
## It aims to be easy to use and easy to read and understand.

runnableExamples:
  let
    secret = genRandomSecret(30)
    totp = newTOTP(secret)
  echo "Current code: ", totp.gen()

runnableExamples:
  let
    secret = genRandomSecret(30)
    hotp = newHOTP(secret)
  echo "Code at iteration 1:", hotp.gen(1)

runnableExamples:
  let
    secret = genRandomSecret(30)
    totp = newTOTP(secret)
  echo "Current code is valid for: ", codeValidFor(totp.interval), " seconds."

import std/sha1, math, std/random
from times import epochTime, getTime, toUnix, nanosecond

import otplib/private/[utils]

# Type definitions of HOTP and TOTP
type
  HOTP = object
    digits: int
    secret: string
  TOTP = object
    hotp: HOTP
    interval*: int

proc genRandomSecret*(length: int): string =
  ## Generate a random secret. Secrets are randomized using the current time down to nanoseconds as a seed.

  doAssert length > 0, msg = "Secret length must not be 0!"

  # Initialize the random number generator
  let now = getTime()
  randomize(now.toUnix * 1_000_000_000 + now.nanosecond)

  # Pick `length` random characters.
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  result = newString(length)
  for i in 0..<length:
    result[i] = chars[rand(range[0..31])]

func genHOTP(secret: string, counter: int, digits: int = 6): int =
  ## Generate a HOTP code. Used for generating both HOTP and TOTP codes.

  # Calculate the MAC using the supplied secret/counter
  var hmac = hmac_sha1(decodeBase32(secret), int_to_bytestring(
      counter)).SHA1Digest

  # Take the 4 LSBs of the MAC and use them as an offset
  let offset = (hmac[19] and 0b1111).int

  # Fetch 31 bits starting from hmac[offset]
  let binaryCode: int = (hmac[offset].int and 0b1111111) shl 24 or
                        (hmac[offset+1].int and 0b11111111) shl 16 or
                        (hmac[offset+2].int and 0b11111111) shl 8 or
                        (hmac[offset+3].int and 0b11111111)

  result = binaryCode mod 10^digits

func newHOTP*(secret: string, digits: int = 6): HOTP =
  ## Generate a new HOTP object.
  ## By default, `digits = 6`.

  # Length must be 6-10 and 6-8 is recommended
  doAssert digits in 6..10, msg = "Digits must be 6-10 (6-8 is recommended)"
  result = HOTP(
    secret: secret,
    digits: digits)

func newTOTP*(secret: string, digits: int = 6, interval: int = 30): TOTP =
  ## Generate a new TOTP object.
  ## By default, `digits = 6` and `interval = 30`.

  # Length must be 6-10 and 6-8 is recommended
  doAssert digits in 6..10, msg = "Digits must be 6-10 (6-8 is recommended)"
  result = TOTP(
    hotp: HOTP(secret: secret, digits: digits),
    interval: interval)

func gen*(hotp: HOTP, counter: int): int =
  ## Generate a new HOTP code with the supplied `counter`.
  result = genHOTP(hotp.secret, counter, hotp.digits)

proc gen*(totp: TOTP): int =
  ## Generate a new TOTP code at current time.
  let period = int(epochTime().int / totp.interval)
  result = genHOTP(totp.hotp.secret, period, totp.hotp.digits)

proc codeValidFor*(interval: int): int =
  ## Based on the `interval`, return the seconds until a TOTP code changes.
  result = 30 - int(epochTime().int mod interval)
