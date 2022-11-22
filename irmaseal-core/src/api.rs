//! Definitions in the IRMAseal REST API protocol.

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::identity::Attribute;
use ibe::kem::IBKEM;
use irma::{ProofStatus, SessionStatus};
use serde::{Deserialize, Serialize};

/// The public parameters of the Private Key Generator (PKG).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound(
    serialize = "PublicKey<K>: Serialize",
    deserialize = "PublicKey<K>: Deserialize<'de>"
))]
pub struct Parameters<K: IBKEM> {
    /// The formatting version of the Master Public Key.
    pub format_version: u8,
    /// The Master Public Key.
    pub public_key: PublicKey<K>,
}

/// A user secret key request for a specific identity.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyRequest {
    /// Conjunction of [`Attribute`]s for which a user requests a user secret key.
    pub con: Vec<Attribute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The validity (in seconds) of the JWT response.
    pub validity: Option<u64>,
}

/// The key response from the Private Key Generator (PKG).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(bound(
    serialize = "UserSecretKey<K>: Serialize",
    deserialize = "UserSecretKey<K>: Deserialize<'de>"
))]
pub struct KeyResponse<K: IBKEM> {
    /// The current IRMA session status.
    pub status: SessionStatus,

    /// The current IRMA session proof status, if there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_status: Option<ProofStatus>,

    /// The key will remain `None` until the `status` is `Done` and the `proofStatus` is `Valid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<UserSecretKey<K>>,
}
