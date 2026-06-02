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
///
/// Each entry in `con` is either a single attribute ([`ConItem::Single`]) or
/// a Yivi disjunction-of-conjunctions ([`ConItem::Discon`]). The legacy flat
/// `[{t,v?,optional?}, ...]` JSON shape still deserialises, because
/// `ConItem` is `#[serde(untagged)]`.
#[derive(Debug, Serialize, Deserialize)]
pub struct IrmaAuthRequest {
    /// The conjunction of attributes (or disjunctions) for the disclosure request.
    pub con: Vec<ConItem>,
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

/// One entry inside [`IrmaAuthRequest::con`].
///
/// Backwards compatible widening: existing callers post a JSON array of
/// `{t,v?,optional?}` objects, which deserialize into [`ConItem::Single`].
/// New callers may post an inner JSON array-of-arrays for a Yivi
/// disjunction-of-conjunctions (`OR` of `AND`), which deserializes into
/// [`ConItem::Discon`]. An empty inner conjunction marks the discon as
/// optional per Yivi convention.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ConItem {
    /// A single attribute, optionally marked `optional: true`.
    Single(DisclosureAttribute),
    /// A disjunction of conjunctions of attributes.
    Discon(Vec<Vec<DisclosureAttribute>>),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// New shape: a JSON `con` array containing a discon (nested array)
    /// must deserialize into [`ConItem::Discon`] alongside any [`ConItem::Single`] entries.
    #[test]
    fn irma_auth_request_accepts_discon_entry() {
        let body = r#"{
            "con": [
                { "t": "pbdf.sidn-pbdf.email.email" },
                [
                    [ { "t": "pbdf.gemeente.personalData.fullname" } ],
                    [
                        { "t": "pbdf.pbdf.passport.firstName" },
                        { "t": "pbdf.pbdf.passport.lastName" }
                    ]
                ]
            ]
        }"#;

        let req: IrmaAuthRequest =
            serde_json::from_str(body).expect("body should parse with a discon entry");

        assert_eq!(req.con.len(), 2);
        match &req.con[0] {
            ConItem::Single(a) => assert_eq!(a.atype, "pbdf.sidn-pbdf.email.email"),
            other => panic!("expected Single, got {:?}", other),
        }
        match &req.con[1] {
            ConItem::Discon(d) => {
                assert_eq!(d.len(), 2, "two alternatives");
                assert_eq!(d[0].len(), 1, "first alt: one attr");
                assert_eq!(d[1].len(), 2, "second alt: firstName+lastName");
                assert_eq!(d[0][0].atype, "pbdf.gemeente.personalData.fullname");
                assert_eq!(d[1][0].atype, "pbdf.pbdf.passport.firstName");
                assert_eq!(d[1][1].atype, "pbdf.pbdf.passport.lastName");
            }
            other => panic!("expected Discon, got {:?}", other),
        }
    }

    /// Backwards-compat: an old-style flat `con` of `{t,v?,optional?}` objects
    /// must still parse into [`ConItem::Single`] variants.
    #[test]
    fn irma_auth_request_keeps_parsing_flat_con() {
        let body = r#"{
            "con": [
                { "t": "pbdf.sidn-pbdf.email.email" },
                { "t": "pbdf.gemeente.personalData.fullname", "optional": true }
            ]
        }"#;

        let req: IrmaAuthRequest = serde_json::from_str(body).expect("legacy flat con must parse");

        assert_eq!(req.con.len(), 2);
        for item in &req.con {
            assert!(matches!(item, ConItem::Single(_)), "all entries Single");
        }
        if let ConItem::Single(a) = &req.con[1] {
            assert!(a.optional, "optional flag preserved");
        }
    }
}
