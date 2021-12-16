#![allow(clippy::unused_unit)] // Temporarily silence the warnings introduced in wasm-bindgen 0.2.79
#![no_std]

// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern crate alloc;

pub use umbral_pre::bindings_wasm::*;
