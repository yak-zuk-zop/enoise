# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2025-02-14

### Added
- deferred patterns (nk1, kk1, nx1, kx1, xx1, ix1)
- enoise_connection vital sign check
- tests for Diffie-Hellman on Curve448
### Changed
- made dh-function more robust
- moved all crypto specific functions to enoise_crypto module
- reworked most tests
- replaced hardcoded magic numbers with macros


## [1.3.0] - 2025-01-30

### Added
- Blake2s hash
- Diffie-Hellman on Curve448 (dh448)
- Types & Specs
### Changed
- Upgraded dependencies: enacl 1.2.1, jsx 3.1.0
- Improved automatic checks (stringent compiler options, dialyzer, xref, linter)
- Refactoring
### Removed
- Extra enoise record. Now it is in a single copy
### Fixed
- Replaced deprecated erlang:get_stacktrace/0 call with try/catch


## [1.2.0] - 2021-10-28

### Changed
- Use the new AEAD crypto interface introduced in OTP 22. This makes `enoise` OPT 24 compatible
  but it also means it no longer works on OTP 21 and earlier. You can't win them all.
- Fixed ChaChaPoly20 rekey


## [1.1.0] - 2020-09-24

### Added
- Include [Cacaphony](https://github.com/centromere/cacophony) test vectors.
### Changed
- Updated `enacl` to version [1.1.1](https://github.com/jlouis/enacl/releases/tag/v1.1.1).
- Fixed some imprecise type specifications.


## [1.0.1] - 2018-12-21

### Changed
- Improved argument checks and error handling in handshake (in particular related to empty
hand shake messages).


## [1.0] - 2018-10-09
### Added
- Initial version the following map describe what is supported:
```
#{ hs_pattern => [nn, kn, nk, kk, nx, kx, xn, in, xk, ik, xx, ix]
 , hash       => [blake2b, sha256, sha512]
 , cipher     => ['ChaChaPoly', 'AESGCM']
 , dh         => [dh25519] }
```

[1.4.0]: https://github.com/yak-zuk-zop/enoise/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/yak-zuk-zop/enoise/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/yak-zuk-zop/enoise/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/yak-zuk-zop/enoise/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/yak-zuk-zop/enoise/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/yak-zuk-zop/enoise/releases/tag/v1.0.0
