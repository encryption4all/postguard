//! Definitions of the PostGuard protocol REST API.

use crate::identity::Attribute;
use alloc::vec::Vec;
use irma::{ProofStatus, SessionStatus};
use serde::{Deserialize, Serialize};

/// The public parameters of the Private Key Generator (PKG).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters<T> {
    /// The formatting version of the Master Public Key.
    pub format_version: u8,

    /// The Master Public Key.
    pub public_key: T,
}

/// An authentication request for a IRMA identity.
#[derive(Debug, Serialize, Deserialize)]
pub struct IrmaAuthRequest {
    /// The conjunction of [`Attribute`].
    pub con: Vec<Attribute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The validity (in seconds) of the JWT response.
    pub validity: Option<u64>,
}

/// The key response from the Private Key Generator (PKG).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyResponse<T> {
    /// The status of the session.
    pub status: SessionStatus,

    /// The status of the IRMA proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_status: Option<ProofStatus>,

    /// The key will remain `None` until the status is `Done` and the proof is `Valid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<T>,
}

/// Signing request body.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignBody {
    /// The subsets.
    pub subsets: Vec<Vec<Attribute>>,
}
