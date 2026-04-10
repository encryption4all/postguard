//! Definitions of the PostGuard protocol REST API.

use crate::{artifacts::SigningKeyExt, identity::Attribute};
use alloc::string::String;
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

/// An attribute in a disclosure request, extending [`Attribute`] with an `optional` flag.
///
/// When `optional` is true, the PKG wraps this attribute in a disjunction with an empty
/// first option, allowing the user to skip disclosing it in the Yivi app.
///
/// This type is only used in API requests (JSON), not in the binary wire format.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DisclosureAttribute {
    /// Attribute type.
    #[serde(rename = "t")]
    pub atype: String,

    /// Attribute value.
    #[serde(rename = "v")]
    pub value: Option<String>,

    /// Whether this attribute is optional in the disclosure session.
    #[serde(default, skip_serializing_if = "crate::util::is_false")]
    pub optional: bool,
}

/// An authentication request for a IRMA identity.
#[derive(Debug, Serialize, Deserialize)]
pub struct IrmaAuthRequest {
    /// The conjunction of attributes for the disclosure request.
    pub con: Vec<DisclosureAttribute>,
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

/// The request Signing key request body.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyRequest {
    /// The public signing identity.
    pub pub_sign_id: Vec<Attribute>,

    /// The private signing identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priv_sign_id: Option<Vec<Attribute>>,
}

/// The signing key response from the Private Key Generator (PKG).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyResponse {
    /// The status of the session.
    pub status: SessionStatus,

    /// The status of the IRMA proof.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_status: Option<ProofStatus>,

    /// The public signing key.
    /// The key will remain `None` until the status is `Done` and the proof is `Valid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pub_sign_key: Option<SigningKeyExt>,

    /// This private signing key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priv_sign_key: Option<SigningKeyExt>,
}
