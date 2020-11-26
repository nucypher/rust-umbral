//! Rust benchmarks are located in an external module, and cannot access private functions.
//! This module re-exports some internals for the purposes of benchmarking.
//! Should not be used by regular users.

pub use crate::hashing::unsafe_hash_to_point;
