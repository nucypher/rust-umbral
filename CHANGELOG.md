# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## Unreleased

### Added

- Added `bindings_wasm::SecretKey::equals`. ([#125])
- Update Python bindings. ([#126])

[#125]: https://github.com/nucypher/rust-umbral/pull/125
[#126]: https://github.com/nucypher/rust-umbral/pull/126


## [0.10.0] - 2023-05-29

### Changed

- Bumped MSRV to 1.65. ([#122])
- Bumped `k256` to 0.13 ([#123])


[#122]: https://github.com/nucypher/rust-umbral/pull/122
[#123]: https://github.com/nucypher/rust-umbral/pull/123


## [0.9.2] - 2023-02-18

### Fixed

- Fixed the type signature for `RecoverableSignature.from_be_bytes()` in Python bindings. ([#121])


[#121]: https://github.com/nucypher/rust-umbral/pull/121


## [0.9.1] - 2023-02-17

### Added

- Added `AsRef` and `From` impls for `bindings_wasm::RecoverableSignature` - necessary for the bindings in `nucypher-core`. ([#120])


[#120]: https://github.com/nucypher/rust-umbral/pull/120


## [0.9.0] - 2023-02-17

### Changed

- Bumped MSRV to 1.60. ([#117])
- Bumped `k256` to 0.12 and PyO3 to `0.18`. ([#117])
- Renamed `serde-support` feature to `serde` to match the conventional style. ([#118])
- `serde` implementation for `Signature` now uses fixed-size (r,s) serialization instead of DER. ([#119])


### Added

- Added `ReencryptionEvidence` structure that can be used in e.g. Ethereum contracts to verify the reencryption validity (see its docstring for the list of checks). ([#107])
- Made `Parameters` and `CurvePoint` public (necessary for the evidence to work). Made `Parameters::u` public, and added a public `CurvePoint::coordinates()` method. ([#107])
- Made `hash_to_cfrag_verification()` public. ([#107])
- Added `VerifiedCapsuleFrag::to_bytes_simple()`. ([#107])
- Added `RecoverableSignature` type with limited functionality. ([#117])
- Added `Signature::try_from_be_bytes()`. ([#117])
- Added `PublicKey::recover_from_prehash()`. ([#117])


[#107]: https://github.com/nucypher/rust-umbral/pull/107
[#117]: https://github.com/nucypher/rust-umbral/pull/117
[#118]: https://github.com/nucypher/rust-umbral/pull/118
[#119]: https://github.com/nucypher/rust-umbral/pull/119


## [0.8.1] - 2023-01-17

### Added

- Added `Signature::to_be_bytes()`, `Capsule::to_bytes_simple()`, and `CapsuleFrag::to_bytes_simple()` to use in Ethereum contracts. ([#115])


### Fixed

- Added the missing `VerifiedCapsuleFrag::unverify()` method in WASM bindings. ([#115])
- Added the missing `Signature::to_der_bytes()` and `from_der_bytes()` that were missing in the Rust library but present in the bindings. ([#115])


[#115]: https://github.com/nucypher/rust-umbral/pull/115


## [0.8.0] - 2023-01-15

### Changed

- Removed `HasTypeName` trait. ([#110])
- Removed `DeserializableFromArray`, `RepresentableAsArray`, `SerializableToArray`, `SerializableToSecretArray`. `Caspule`, `(Verified)CapsuleFrag`, `(Verified)KeyFrag` are now serialized via `serde`. ([#110])
- Removed `VerifiedCapsuleFrag::from_verified_bytes()` and `VerifiedKeyFrag::from_verified_bytes()`. For this behavior, deserialize into `CapsuleFrag` or `KeyFrag` and call `skip_verification()`. ([#110])
- `Capsule` no longer implements `Copy`. ([#110])
- Removed default serialization methods for `PublicKey` and `Signature` in the bindings; use `to_compressed_bytes()`/`to_der_bytes()` instead. ([#110])
- Bumped `rmp-serde` to 1, `base64` to 0.21, and `pyo3` to 0.17. ([#114])


### Added

- `DefaultSerialize`/`DefaultDeserialize` for Umbral objects (`Caspule`, `(Verified)CapsuleFrag`, `(Verified)KeyFrag`) which uses MessagePack via `serde` (gated by `default-serialization` feature). This is what the serialization methods in the bindings use. ([#110])
- `to_compressed_bytes()`/`try_from_compressed_bytes()` for `PublicKey` to give access to non-serde representation (just 33 bytes). These are exposed in the bindings in lieu of the "default" methods (e.g. `__bytes__()` or `toBytes()`). ([#110])
- `to_der_bytes()`/`try_from_der_bytes()` for `Signature` to give access to non-serde representation. These are exposed in the bindings in lieu of the "default" methods (e.g. `__bytes__()` or `toBytes()`). ([#110])
- `SecretKeyFactory::make_secret()` to provide a more straightforward replacement of `SecretKeyFactory::make_secret_key()`->`SecretKey::to_secret_bytes()`. ([#110])
- Added `SecretKey::to_be_bytes()` and `try_from_be_bytes()`. ([#112])


### Fixed

- A typo in the error message that could be returned from `CapsuleFrag.verify()` - it erroneously mentioned `KeyFrag`. ([#105])


[#105]: https://github.com/nucypher/rust-umbral/pull/105
[#110]: https://github.com/nucypher/rust-umbral/pull/110
[#112]: https://github.com/nucypher/rust-umbral/pull/112
[#114]: https://github.com/nucypher/rust-umbral/pull/114


## [0.7.0] - 2022-09-30

### Changed

- Replaced `AsBackend`/`FromBackend`, `.inner()`, `.new()`, and `pub backend` with derived `AsRef`/`From`/`Into` where appropriate. ([#103])
- Using a workaround with `wasm-bindgen-derive` to support `Option<&T>` and `&Vec<T>` arguments, and `Vec<T>` return values in WASM bindings. Generating correct TypeScript signatures in all the relevant cases. Affected API: `Capsule.decryptReencrypted()`, `KeyFrag.verify()`, `generate_kfrags()`. ([#103])
- Removed `serde` usage in WASM bindings. ([#103])
- `encrypt()` now returns an actual tuple in WASM bindings instead of a special object. ([#103])


### Added

- `Eq` markers for the types that only had `PartialEq` before. ([#100])


### Fixed

- Added missing parameters to `from_bytes()` methods in Python type stubs. ([#101])
- Fixed the type annotation for `signer` in `generate_kfrags()` in Python type stubs. ([#102])


[#100]: https://github.com/nucypher/rust-umbral/pull/100
[#101]: https://github.com/nucypher/rust-umbral/pull/101
[#102]: https://github.com/nucypher/rust-umbral/pull/102
[#103]: https://github.com/nucypher/rust-umbral/pull/103


## [0.6.0] - 2022-08-15

### Changed

- When serialized to a human-readable format using `serde`, hex-encoded objects now have a `0x` prefix. ([#94])
- Bumped `k256` to 0.11, `sha2` to 0.10, `hkdf` to 0.12, `chacha20poly1305` to 0.10, and `zeroize` to 1.5 (and MSRV to 1.57), so that we could use the new `ZeroizeOnDrop` functionality. In particular, `SecretBox`, `SecretKey`, `Signer`, and `DEM` now implement `ZeroizeOnDrop`. ([#97])
- Removed `CanBeZeroizedOnDrop` trait, since `GenericArray` now supports `Zeroize` natively. ([#97])
- Bumped `pyo3` to 0.16. ([#97])


### Added

- `serde` utility functions to serialize bytestrings as bytes or hex/base64 encoded strings, depending on the target format. Exposed as `serde_bytes` module. ([#94])


### Fixed

- Fixed some typos and added missing `__bytes__()` methods to Python typing stubs. ([#99])


[#94]: https://github.com/nucypher/rust-umbral/pull/94
[#97]: https://github.com/nucypher/rust-umbral/pull/97
[#99]: https://github.com/nucypher/rust-umbral/pull/99


## [0.5.2] - 2022-03-15

### Fixed

- `k256` bumped to 0.10.4 to make use of an important bugfix (see https://github.com/RustCrypto/elliptic-curves/issues/529). Previous 0.5.* versions (using `k256` 0.10.2 with the bug) are yanked.


## [0.5.1] - 2022-01-22 (**YANKED**)

### Added

- WASM bindings are exposed as a feature `bindings-wasm` in the main crate, to allow dependent crates to create their own WASM bindings and re-export some WASM-wrapped Umbral types. ([#78])


[#78]: https://github.com/nucypher/rust-umbral/pull/78


## [0.5.0] - 2022-01-19 (**YANKED**)

### Changed

- `k256` dependency bumped to 0.10 (and to match it, `chacha20poly1305` to 0.9, `elliptic-curve` to 0.11, `ecdsa` to 0.13, `signature` to 1.4, MSRV to 1.56, and Rust edition to 2021). ([#87])
- ABI changed because of the internal change in hashing to scalars (we can hash to non-zero scalars now). Correspondingly, `OpenReencryptedError::ZeroHash` and `SecretKeyFactoryError` have been removed, and `SecretKeyFactory::make_key()` was made infallible. ([#87])
- Internal cloning in the library methods was eliminated, and, as a result, several methods now consume the given objects. Namely: `Signer::new()` consumes the given `SecretKey`,
  `KeyFrag::verify()` and `CapsuleFrag::verify()` consume the given kfrag/cfrag, `reencrypt()` consumes the cfrag (but not the capsule). ([#91])
- As a consequence, `KeyFrag::verify()` and `CapsuleFrag::verify()` return the original frag on error (as a tuple with the error itself), for logging purposes (since the original object is not available anymore). ([#91])
- `VerifiedKeyFrag::to_unverified()` and `VerifiedCapsuleFrag::to_unverified()` were renamed to `unverify()` and consume the corresponding frag. ([#91])
- Using the [IETF standard](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/) to hash to point instead of a custom implementation (and bumps `k256` to 0.10.2). Changes the format of all the library's objects! ([#92])


### Fixed

- Some previously missed potentially secret values are zeroized in drop. ([#87])


[#87]: https://github.com/nucypher/rust-umbral/pull/87
[#91]: https://github.com/nucypher/rust-umbral/pull/91
[#92]: https://github.com/nucypher/rust-umbral/pull/92


## [0.4.0] - 2021-12-24

### Changed

- `serde` support for types is now gated under the `serde-support` feature (not enabled by default). ([#82])


### Added

- Python bindings are exposed as a feature `bindings-python` in the main crate, to allow dependent crates to create their own Python bindings and re-export some Python-wrapped Umbral types. ([#74])
- `KeyFrag::skip_verification()`, `VerifiedKeyFrag::to_unverified()`, `CapsuleFrag::skip_verification()`, `VerifiedCapsuleFrag::to_unverified()`, and
  the corresponding methods in Python and WASM bindings. ([#84])


### Fixed

- Make the source distribution of Python bindings actually usable, by removing a dependency on a workspace directory. ([#86])


[#74]: https://github.com/nucypher/rust-umbral/pull/74
[#82]: https://github.com/nucypher/rust-umbral/pull/82
[#84]: https://github.com/nucypher/rust-umbral/pull/84
[#86]: https://github.com/nucypher/rust-umbral/pull/86


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

[0.2.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.2.0
[0.3.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.3.0
[0.4.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.4.0
[0.5.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.5.0
[0.5.1]: https://github.com/nucypher/rust-umbral/releases/tag/v0.5.1
[0.5.2]: https://github.com/nucypher/rust-umbral/releases/tag/v0.5.2
[0.6.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.6.0
[0.7.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.7.0
[0.8.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.8.0
[0.8.1]: https://github.com/nucypher/rust-umbral/releases/tag/v0.8.1
[0.9.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.9.0
[0.9.1]: https://github.com/nucypher/rust-umbral/releases/tag/v0.9.1
[0.9.2]: https://github.com/nucypher/rust-umbral/releases/tag/v0.9.2
[0.10.0]: https://github.com/nucypher/rust-umbral/releases/tag/v0.10.0
