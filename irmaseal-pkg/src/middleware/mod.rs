//! IRMAseal PKG middleware.
//! It has two functions:
//! 1. Authenticate the user,
//! 2. Derive an identity from the validaten authentication results for a IBKEM to pass to the key
//!    generation service.

pub mod irma;

#[cfg(test)]
pub mod irma_noauth;
