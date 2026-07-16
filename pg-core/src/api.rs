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
///
/// Unknown fields are rejected: in a key-issuance request a silently dropped
/// misspelled field (`vaule` for `v`, `optioanl` for `optional`) would *widen*
/// the disclosure the caller intended, so a typo must be a 400, not a
/// reinterpretation.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum ConItem {
    /// A single attribute, optionally marked `optional: true`.
    Single(DisclosureAttribute),
    /// A disjunction of conjunctions of attributes.
    Discon(Vec<Vec<DisclosureAttribute>>),
}

/// Manual [`Deserialize`] instead of `#[serde(untagged)]`: untagged enums
/// swallow the inner error ("data did not match any variant"), which is
/// useless to a client debugging a 400. The JSON shape already discriminates
/// the variants (object vs array), so dispatch on it and let the real error —
/// e.g. ``unknown field `vaule`, expected one of `t`, `v`, `optional``` —
/// propagate.
impl<'de> Deserialize<'de> for ConItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ConItemVisitor;

        impl<'de> serde::de::Visitor<'de> for ConItemVisitor {
            type Value = ConItem;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(
                    "an attribute object like {\"t\": …} or a disjunction \
                        (array of conjunctions, i.e. array of arrays of attributes)",
                )
            }

            fn visit_map<A>(self, map: A) -> Result<ConItem, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                DisclosureAttribute::deserialize(serde::de::value::MapAccessDeserializer::new(map))
                    .map(ConItem::Single)
            }

            fn visit_seq<A>(self, seq: A) -> Result<ConItem, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                Vec::<Vec<DisclosureAttribute>>::deserialize(
                    serde::de::value::SeqAccessDeserializer::new(seq),
                )
                .map(ConItem::Discon)
            }
        }

        deserializer.deserialize_any(ConItemVisitor)
    }
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

    /// Unknown fields in a request are rejected, not silently ignored: a
    /// misspelled `v` would otherwise WIDEN the disclosure the caller
    /// intended. The error must name the offending field so a client
    /// developer can act on the 400.
    #[test]
    fn irma_auth_request_rejects_unknown_attribute_field() {
        let body =
            r#"{ "con": [ { "t": "pbdf.sidn-pbdf.email.email", "vaule": "alice@example.com" } ] }"#;

        let err = serde_json::from_str::<IrmaAuthRequest>(body)
            .expect_err("a misspelled attribute field must be rejected");
        let msg = alloc::string::ToString::to_string(&err);
        assert!(
            msg.contains("vaule"),
            "error must name the unknown field, got: {msg}"
        );
    }

    /// Same at the top level: extra request fields are rejected.
    #[test]
    fn irma_auth_request_rejects_unknown_top_level_field() {
        let body = r#"{ "con": [ { "t": "pbdf.sidn-pbdf.email.email" } ], "validty": 300 }"#;

        let err = serde_json::from_str::<IrmaAuthRequest>(body)
            .expect_err("a misspelled top-level field must be rejected");
        let msg = alloc::string::ToString::to_string(&err);
        assert!(
            msg.contains("validty"),
            "error must name the unknown field, got: {msg}"
        );
    }

    /// The nesting mistake (a one-level array of attributes where a
    /// disjunction needs arrays-of-arrays) yields the visitor's shape hint,
    /// not an inscrutable untagged-enum error.
    #[test]
    fn con_item_nesting_mistake_gets_a_useful_error() {
        let body = r#"{ "con": [ [ { "t": "pbdf.gemeente.personalData.fullname" } ] ] }"#;

        let err = serde_json::from_str::<IrmaAuthRequest>(body)
            .expect_err("attributes directly inside a disjunction must be rejected");
        let msg = alloc::string::ToString::to_string(&err);
        assert!(
            !msg.contains("did not match any variant"),
            "must not surface the untagged-enum catch-all, got: {msg}"
        );
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
