//! Structs that define the IRMAseal REST API protocol.

use crate::*;
use ibe::kem::IBKEM;
use irma::{ProofStatus, SessionStatus};
use serde::{Deserialize, Serialize};

// TODO: make variant for signing pp.
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
pub struct AuthRequest {
    pub con: Vec<Attribute>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity: Option<u64>,
}

/// The response to a key request (decryption/signing).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyResponse<T> {
    /// The status of the session.
    pub status: SessionStatus,

    /// The status of the IRMA proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_status: Option<ProofStatus>,

    /// The user secret key (if present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<T>,
}

#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "UserSecretKey<K>: Serialize",
    deserialize = "UserSecretKey<K>: Deserialize<'de>"
))]
pub struct DecryptionKeyResponse<K: IBKEM>(KeyResponse<UserSecretKey<K>>);

#[derive(Debug, Serialize, Deserialize)]
pub struct SigningKey {
    /// The signing key.
    key: ibs::gg::UserSecretKey,

    /// The time of issuance of the key by the PKG (also included in the identity).
    iat: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SigningKeyResponse(KeyResponse<SigningKey>);
