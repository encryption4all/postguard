//! Structs that define the IRMAseal REST API protocol.

use crate::*;
use ibe::kem::IBKEM;
use serde::{Deserialize, Serialize};

/// Set of public parameters for the Private Key Generator (PKG).
#[derive(Serialize, Deserialize)]
#[serde(bound(
    serialize = "PublicKey<K>: Serialize",
    deserialize = "PublicKey<K>: Deserialize<'de>"
))]
pub struct Parameters<K: IBKEM> {
    pub format_version: u8,
    pub max_age: u64,
    pub public_key: PublicKey<K>,
}

/// A request for the user secret key for an identity.
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyRequest {
    pub attribute: Attribute,
}

/// The challenge to verify the key request.
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyChallenge<'a> {
    /// The QR code that should be shown to the user,
    /// such that it can be scanned using the IRMA app.
    pub qr: &'a str,

    /// The token that should be used to retrieve the status of the earlier request.
    pub token: &'a str,
}

/// The status of a key request.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyStatus {
    /// The IRMA session has been initialized.
    Initialized,
    /// The IRMA app has connected to the API server.
    Connected,
    /// The IRMA session was cancelled.
    Cancelled,
    /// The IRMA session was completed succesfully, but it did not contain a valid attribute disclosure proof.
    DoneInvalid,
    /// The IRMA session was completed succesfully, and it contains a valid attribute disclosure proof.
    DoneValid,
    /// The IRMA session has timed out.
    Timeout,
}

/// The response to the key request.
#[derive(Serialize, Deserialize)]
pub struct KeyResponse<K: IBKEM> {
    /// The current status of the key request.
    pub status: KeyStatus,
    /// The key will remain `None` until the status is `DoneValid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(bound(
        serialize = "UserSecretKey<K>: Serialize",
        deserialize = "UserSecretKey<K>: Deserialize<'de>"
    ))]
    pub key: Option<UserSecretKey<K>>,
}
