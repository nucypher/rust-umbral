# Rust implementation of Umbral proxy reencryption algorithm

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![License][license-image]
[![Build Status][build-image]][build-link]
[![Coverage][coverage-image]][coverage-link]

`umbral-pre` is the Rust implementation of the [Umbral][umbral] threshold proxy re-encryption scheme.

Using `umbral-pre`, Alice (the data owner) can delegate decryption rights to Bob for any ciphertext intended to her, through a re-encryption process performed by a set of semi-trusted proxies or Ursulas.
When a threshold of these proxies participate by performing re-encryption, Bob is able to combine these independent re-encryptions and decrypt the original message using his private key.

For more information and usage examples please refer to the documentation.

[Documentation][docs-link]

## Bindings

Bindings for several languages are available:

* [JavaScript (WASM-based)](https://github.com/nucypher/rust-umbral/tree/master/umbral-pre-wasm)
* [Python](https://github.com/nucypher/rust-umbral/tree/master/umbral-pre-python)

[crate-image]: https://img.shields.io/crates/v/umbral-pre.svg
[crate-link]: https://crates.io/crates/umbral-pre
[docs-image]: https://docs.rs/umbral-pre/badge.svg
[docs-link]: https://docs.rs/umbral-pre/
[license-image]: https://img.shields.io/crates/l/umbral-pre
[build-image]: https://github.com/nucypher/rust-umbral/workflows/umbral-pre/badge.svg?branch=master&event=push
[coverage-image]: https://codecov.io/gh/nucypher/rust-umbral/branch/master/graph/badge.svg
[coverage-link]: https://codecov.io/gh/nucypher/rust-umbral
[build-link]: https://github.com/nucypher/rust-umbral/actions?query=workflow%3Aumbral-pre
[umbral]: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf
