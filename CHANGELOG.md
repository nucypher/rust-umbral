# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed

- `SecretKey` and `SecretKeyFactory` no longer implement `SerializableToArray`, but implement `SerializableToSecretArray` instead. Correspondingly, in the bindings these objects implement `to_secret_bytes()` instead of `__bytes__()` (for Python), and `toSecretBytes()` instead of `toBytes()` (for WASM). ([#53])
- `SecretKey`, `SecretKeyFactory` and `Signer` do not implement `PartialEq` anymore. Corresponding methods in the bindings were removed as well. ([#53])
- Bumped `k256` to `0.9` and `ecdsa` to `0.12.2`. ([#53])


### Added

- Added separate entry points for Webpack and Node.JS in the WASM bindings, and added examples for both of these scenarios ([#60])
- `SecretBox` struct, a wrapper making operations with secret data explicit and ensuring zeroization on drop ([#53])
- Feature `default-rng` (enabled by default). When disabled, the library can be compiled on targets not supported by `getrandom` (e.g., ARM), but only the functions taking an explicit RNG as a parameter will be available. ([#55])


### Fixed

- Turned off `wasm-bindgen` feature of `getrandom` crate ([#56])
- Multiple internal changes for safe secret data handling using `SecretBox` ([#53])


[#53]: https://github.com/nucypher/rust-umbral/pull/53
[#55]: https://github.com/nucypher/rust-umbral/pull/55
[#56]: https://github.com/nucypher/rust-umbral/pull/56
[#60]: https://github.com/nucypher/rust-umbral/pull/60


## [0.2.0] - 2021-06-14

- Initial release.

[Unreleased]: https://github.com/nucypher/rust-umbral/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.2.0
