# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

### Changed

- `serde` support for types is now gated under the `serde-support` feature (not enabled by default). ([#82])


### Added

- Python bindings are exposed as a feature `bindings-python` in the main crate, to allow dependent crates to create their own Python bindings and re-export some Python-wrapped Umbral types. ([#74])
- `KeyFrag::skip_verification()`, `VerifiedKeyFrag::to_unverified()`, `CapsuleFrag::skip_verification()`, `VerifiedCapsuleFrag::to_unverified()`, and
the corresponding methods in Python and WASM bindings. ([#84])


[#74]: https://github.com/nucypher/rust-umbral/pull/74
[#82]: https://github.com/nucypher/rust-umbral/pull/82
[#84]: https://github.com/nucypher/rust-umbral/pull/84


## [0.3.3] - 2021-12-10

### Added

- Github actions configured for automatic build and push of Python wheels.


### Fixed

- Fixed Python example
- Improved/updated documentation


## [0.3.0] - 2021-09-15

### Changed

- `SecretKey` and `SecretKeyFactory` no longer implement `SerializableToArray`, but implement `SerializableToSecretArray` instead. Correspondingly, in the bindings these objects implement `to_secret_bytes()` instead of `__bytes__()` (for Python), and `toSecretBytes()` instead of `toBytes()` (for WASM). ([#53])
- `SecretKey`, `SecretKeyFactory` and `Signer` do not implement `PartialEq` anymore. Corresponding methods in the bindings were removed as well. ([#53])
- Bumped `k256` to `0.9` and `ecdsa` to `0.12.2`. ([#53])
- Bumped `pyo3` to `0.14`. ([#65])
- Reduced the size of key material in `SecretKeyFactory` from 64 to 32 bytes. ([#64])
- Renamed `num_kfrags` to `shares` in `genereate_kfrags`. ([#69])
- Renamed `SecretKeyFactory::secret_key_by_label()`/`secret_factory_by_label()` to `make_key()`/`make_factory()`. ([#71])
- Renamed remaining instances of `verifying_key` parameter to `verifying_pk`. ([#71])


### Added

- Added separate entry points for Webpack and Node.JS in the WASM bindings, and added examples for both of these scenarios. ([#60])
- `SecretBox` struct, a wrapper making operations with secret data explicit and ensuring zeroization on drop. ([#53])
- Feature `default-rng` (enabled by default). When disabled, the library can be compiled on targets not supported by `getrandom` (e.g., ARM), but only the functions taking an explicit RNG as a parameter will be available. ([#55])
- Added benchmarks for the main usage scenario and a feature `bench-internals` to expose some internals for benchmarking. ([#54])
- Added `VerifiedCapsuleFrag::from_verified_bytes()`. ([#63])
- Added `SecretKeyFactory::secret_key_factory_by_label()`. ([#64])
- Added `SecretKeyFactory::from_secure_randomness()` and `seed_size()`. ([#64])
- `serde` support for `Capsule`, `CapsuleFrag`, `KeyFrag`, `PublicKey`, and `Signature`. ([#67])


### Fixed

- Turned off `wasm-bindgen` feature of `getrandom` crate. ([#56])
- Multiple internal changes for safe secret data handling using `SecretBox`. ([#53])


[#53]: https://github.com/nucypher/rust-umbral/pull/53
[#54]: https://github.com/nucypher/rust-umbral/pull/54
[#55]: https://github.com/nucypher/rust-umbral/pull/55
[#56]: https://github.com/nucypher/rust-umbral/pull/56
[#60]: https://github.com/nucypher/rust-umbral/pull/60
[#63]: https://github.com/nucypher/rust-umbral/pull/63
[#64]: https://github.com/nucypher/rust-umbral/pull/64
[#65]: https://github.com/nucypher/rust-umbral/pull/65
[#67]: https://github.com/nucypher/rust-umbral/pull/67
[#69]: https://github.com/nucypher/rust-umbral/pull/69
[#71]: https://github.com/nucypher/rust-umbral/pull/71


## [0.2.0] - 2021-06-14

- Initial release.

[Unreleased]: https://github.com/nucypher/rust-umbral/compare/v0.3.0...HEAD
[0.2.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.2.0
[0.3.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.3.0
