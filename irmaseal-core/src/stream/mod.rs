//! Implementation of the IRMAseal stream format.

#[cfg(feature = "stream")]
mod rust;

#[cfg(feature = "stream")]
pub use {rust::sealer::seal, rust::unsealer::Unsealer};

#[cfg(feature = "wasm_stream")]
mod web;

#[cfg(feature = "wasm_stream")]
pub use {web::sealer::seal as web_seal, web::unsealer::Unsealer as WebUnsealer};

#[cfg(test)]
mod tests;
