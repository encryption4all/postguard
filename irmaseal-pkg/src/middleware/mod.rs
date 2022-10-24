//! IRMAseal PKG middleware module.
//!
//! Authentication middleware can be used to wrap a (key) service.
//! The middleware has two responsibilities:
//!
//! 1. Authenticate the user from the request. The request can contain authentication-specific
//!    data.
//!
//! 2. Derive an IBE identity from the validated authentication results. This identity is passed to
//!    the wrapped key service. Subsequently the key service generates the associated
//!    [`UserSecretKey`][`irmaseal_core::UserSecretKey].

pub mod irma;

#[cfg(test)]
pub mod irma_noauth;
