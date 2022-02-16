# OTPLIB - One Time Password Library for Nim [![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](http://unlicense.org/)
[![forthebadge](https://forthebadge.com/images/badges/built-with-love.svg)](https://forthebadge.com)


OTPLIB is a Nim package for generating, managing and verifying one-time passwords.
It can be used to implement 2FA or MFA in web applications and other systems that require users to log in.

Multi-factor Authentication standards are defined in:

- [RFC 4226](https://tools.ietf.org/html/rfc4226) - HOTP
- [RFC 6238](https://tools.ietf.org/html/rfc6238) - TOTP

OTPLIB was inspired by other OTP libraries like [GOTP](https://github.com/xlzd/gotp) and [PyOTP](https://github.com/pyauth/pyotp).

## TODO
- [ ] Handle Google's key URI format
- [ ] Add support for more hash modes

## Installation
To install run:
```bash
$ nimble install otplib
```


To include it in your project add this to your nimble file:
```nim
requires "otplib"
```
and import it:
```nim
import otplib
```

## Usage
**See:** [Documentation](https://dimspith.com/docs/otplib/)

## Contributing, feature requests and bug reports
Contributions are welcome 💕

Make sure to run `nimpretty` on your changes to maintain a consistent style.
