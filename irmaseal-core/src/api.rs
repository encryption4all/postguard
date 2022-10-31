//! Structs that define the IRMAseal REST API protocol.

use crate::*;
use ibe::kem::IBKEM;
use irma::{ProofStatus, SessionStatus};
use serde::{Deserialize, Serialize};

/// Set of public parameters for the Private Key Generator (PKG).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters<K: IBKEM> {
    pub format_version: u8,
    #[serde(bound(
        serialize = "PublicKey<K>: Serialize",
        deserialize = "PublicKey<K>: Deserialize<'de>"
    ))]
    pub public_key: PublicKey<K>,
}

/// A request for the user secret key for an identity.
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyRequest {
    pub con: Vec<Attribute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity: Option<u64>,
}

/// The response to the key request.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyResponse<K: IBKEM> {
    /// The status of the session.
    pub status: SessionStatus,

    /// The status of the IRMA proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_status: Option<ProofStatus>,

    /// The user secret key (if present).
    #[serde(bound(
        serialize = "UserSecretKey<K>: Serialize",
        deserialize = "UserSecretKey<K>: Deserialize<'de>"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<UserSecretKey<K>>,
}
