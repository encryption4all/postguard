//! IRMAseal PKG middleware module.
//!
//! # Authentication
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
//!
//! # Metrics
//!
//! The metrics middleware collects prometheus metrics.

pub mod irma;
pub mod metrics;

#[cfg(test)]
pub mod irma_noauth;
