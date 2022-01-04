//! Implementation of the IRMAseal stream format. Includes zero-allocation streaming encryption and decryption.

#[cfg(feature = "stream")]
mod rust;

#[cfg(feature = "stream")]
pub use {rust::sealer::seal, rust::unsealer::Unsealer};

#[cfg(feature = "wasm_stream")]
mod web;

#[cfg(feature = "wasm_stream")]
pub use {web::sealer::seal, web::unsealer::Unsealer};

#[cfg(test)]
mod tests;
