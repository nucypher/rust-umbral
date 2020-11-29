# Implementation of Umbral proxy reencryption algorithm

This repo contains Rust implementation of the [Umbral][umbral] threshold proxy re-encryption scheme and bindings to some other languages.

* [Rust](https://github.com/nucypher/rust-umbral/tree/master/umbral-pre) (primary) [![crate][rust-crate-image]][rust-crate-link] [![Docs][rust-docs-image]][rust-docs-link] ![License][rust-license-image] [![Build Status][rust-build-image]][rust-build-link] [![Coverage][rust-coverage-image]][rust-coverage-link]
* [JavaScript](https://github.com/nucypher/rust-umbral/tree/master/umbral-pre-wasm) (WASM-based) [![npm package][js-npm-image]][js-npm-link] ![License][js-license-image]
* [Python](https://github.com/nucypher/rust-umbral/tree/master/umbral-pre-python) (under construction)

[rust-crate-image]: https://img.shields.io/crates/v/umbral-pre.svg
[rust-crate-link]: https://crates.io/crates/umbral-pre
[rust-docs-image]: https://docs.rs/umbral-pre/badge.svg
[rust-docs-link]: https://docs.rs/umbral-pre/
[rust-license-image]: https://img.shields.io/crates/l/umbral-pre
[rust-build-image]: https://github.com/nucypher/rust-umbral/workflows/umbral-pre/badge.svg?branch=master&event=push
[rust-build-link]: https://github.com/nucypher/rust-umbral/actions?query=workflow%3Aumbral-pre
[rust-coverage-image]: https://codecov.io/gh/nucypher/rust-umbral/branch/master/graph/badge.svg
[rust-coverage-link]: https://codecov.io/gh/nucypher/rust-umbral
[js-npm-image]: https://img.shields.io/npm/v/umbral-pre
[js-npm-link]: https://www.npmjs.com/package/umbral-pre
[js-license-image]: https://img.shields.io/npm/l/umbral-pre
[umbral]: https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf
