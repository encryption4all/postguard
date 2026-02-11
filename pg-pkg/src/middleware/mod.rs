//! PostGuard PKG middleware module.
//!
//! # Authentication
//!
//! Authentication middleware can be used to wrap a (key) service. The middleware has only one
//! responsibility: Authenticate the user from the request. The request can contain
//! authentication-specific data and provide the underlying service with validated authentication
//! results. The key service is responsible for verifying timestamps and expiries.
//!    
//! # Metrics
//!
//! The metrics middleware collects Prometheus metrics.

pub mod auth;
pub mod metrics;

#[cfg(test)]
pub mod irma_noauth;
