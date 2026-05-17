use crate::util::TranslatedString;

use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

use serde::{Deserialize, Serialize};

/// Basic structure of an IRMA disclosure request, a conjunction of disjunctions of inner conjunctions.
/// Examples on how to use this can be found at irma.app/docs
pub type ConDisCon = Vec<Vec<Vec<AttributeRequest>>>;

fn omit_false(value: &bool) -> bool {
    !value
}

/// Representation of a request for a single specific attribute
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(untagged)]
pub enum AttributeRequest {
    /// Request for any value of the named attribute
    Simple(String),
    /// More complicated request for a value of the named attribute
    Compound {
        /// Which attribute is requested
        #[serde(rename = "type")]
        attr_type: String,
        /// The required value, if any
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<String>,
        /// Is a no-value result is acceptable?
        #[serde(rename = "notNull", skip_serializing_if = "omit_false", default)]
        not_null: bool,
    },
}

impl AttributeRequest {
    /// Create an attribute request for an attribute for which we require at least some value.
    pub fn non_null(attr_type: String) -> AttributeRequest {
        AttributeRequest::Compound {
            attr_type,
            value: None,
            not_null: true,
        }
    }

    /// Create an attribute request where we want a specific value for the attribute to be disclosed
    /// This is useful when using IRMA not to learn something about the user, but instead enforcing
    /// some sort of access control, such as a minimum age.
    pub fn with_value(attr_type: String, value: String) -> AttributeRequest {
        AttributeRequest::Compound {
            attr_type,
            value: Some(value),
            not_null: false,
        }
    }
}

/// Description of an IRMA credential to be issued.
/// The issuing IRMA server requires the private key of the issuer to be present to be able to issue a credential.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Credential {
    /// Identifier of the credential to be issued
    pub credential: String,
    /// Unix timestamp of until when the credential is valid. This is rounded down by the server to the nearest week.
    /// When not present, the server will default the credential to be valid for 6 months
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub validity: Option<u64>,
    /// Values for the attributes in the credential
    pub attributes: HashMap<String, String>,
}

/// Builder for an IRMA credential
pub struct CredentialBuilder {
    cred: Credential,
}

impl CredentialBuilder {
    /// Create a builder for a credential
    pub fn new(credential: String) -> CredentialBuilder {
        CredentialBuilder {
            cred: Credential {
                credential,
                validity: None,
                attributes: HashMap::new(),
            },
        }
    }

    /// Set the validity period
    pub fn validity_period(mut self, period: Duration) -> Self {
        let validity_time = SystemTime::now() + period;
        let timestamp = validity_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("No support for time manipulations before 1-1-1970")
            .as_secs();
        // we let the server do the rounding
        self.cred.validity = Some(timestamp);
        self
    }

    /// Add an indivial attribute
    pub fn attribute(mut self, key: String, value: String) -> Self {
        self.cred.attributes.insert(key, value);
        self
    }

    /// Create the credential
    pub fn build(self) -> Credential {
        self.cred
    }
}

/// Information common between all types of requests
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BaseRequest {
    /// Con-dis-con of attributes to be disclosed
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub disclose: ConDisCon,
    /// For mobile sessions, URL to redirect user to after completion of the session.
    #[serde(rename = "clientReturnUrl", skip_serializing_if = "Option::is_none")]
    pub return_url: Option<String>,
    /// Have the irma server include the session token in the client return url. (see irma.app/docs for more details)
    #[serde(
        rename = "augmentReturnUrl",
        skip_serializing_if = "omit_false",
        default
    )]
    pub augment_return: bool,
    /// Labels for the disjunctions in the disclosure request
    #[serde(
        skip_serializing_if = "HashMap::is_empty",
        default,
        deserialize_with = "crate::util::de_int_key"
    )]
    pub labels: HashMap<usize, TranslatedString>,
}

/// IRMA session requests
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(tag = "@context")]
pub enum IrmaRequest {
    /// Request for the disclosure of some set of attributes
    #[serde(rename = "https://irma.app/ld/request/disclosure/v2")]
    Disclosure {
        #[serde(flatten)]
        base: BaseRequest,
    },
    /// Request for the signing of a message
    #[serde(rename = "https://irma.app/ld/request/signature/v2")]
    Signature {
        message: String,
        #[serde(flatten)]
        base: BaseRequest,
    },
    /// Request for the issuance of one or more credentials
    #[serde(rename = "https://irma.app/ld/request/issuance/v2")]
    Issuance {
        credentials: Vec<Credential>,
        #[serde(flatten)]
        base: BaseRequest,
    },
}

struct BaseRequestBuilder {
    base: BaseRequest,
}

impl BaseRequestBuilder {
    fn new() -> BaseRequestBuilder {
        BaseRequestBuilder {
            base: BaseRequest {
                disclose: vec![],
                return_url: None,
                augment_return: false,
                labels: HashMap::new(),
            },
        }
    }

    fn build(self) -> BaseRequest {
        self.base
    }

    fn add_discons(&mut self, mut discons: ConDisCon) {
        self.base.disclose.append(&mut discons);
    }

    fn add_discon(&mut self, discon: Vec<Vec<AttributeRequest>>) {
        self.base.disclose.push(discon);
    }

    fn add_discon_with_label(
        &mut self,
        discon: Vec<Vec<AttributeRequest>>,
        label: TranslatedString,
    ) {
        let index = self.base.disclose.len();
        self.base.disclose.push(discon);
        self.base.labels.insert(index, label);
    }

    fn return_url(&mut self, return_url: String) {
        debug_assert!(self.base.return_url == None);
        self.base.return_url = Some(return_url);
    }

    fn augmented_return_url(&mut self, return_url: String) {
        debug_assert!(self.base.return_url == None);
        self.base.return_url = Some(return_url);
        self.base.augment_return = true;
    }
}

impl Default for BaseRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Build a disclosure request
#[derive(Default)]
pub struct DisclosureRequestBuilder {
    base: BaseRequestBuilder,
}

impl DisclosureRequestBuilder {
    /// Construct a new builder
    pub fn new() -> DisclosureRequestBuilder {
        DisclosureRequestBuilder::default()
    }

    /// Construct the actual request based on the given information
    pub fn build(self) -> IrmaRequest {
        debug_assert!(!self.base.base.disclose.is_empty());
        IrmaRequest::Disclosure {
            base: self.base.build(),
        }
    }

    /// Add an additional disjunction to the request
    pub fn add_discon(mut self, discon: Vec<Vec<AttributeRequest>>) -> DisclosureRequestBuilder {
        self.base.add_discon(discon);
        self
    }

    /// Add multiple additional disjunctions to the request
    pub fn add_discons(mut self, discons: ConDisCon) -> DisclosureRequestBuilder {
        self.base.add_discons(discons);
        self
    }

    /// Add an additional labeled disjunction to the request
    pub fn add_discon_with_label(
        mut self,
        discon: Vec<Vec<AttributeRequest>>,
        label: TranslatedString,
    ) -> DisclosureRequestBuilder {
        self.base.add_discon_with_label(discon, label);
        self
    }

    /// Set a return URL on the request
    pub fn return_url(mut self, return_url: String) -> DisclosureRequestBuilder {
        self.base.return_url(return_url);
        self
    }

    /// Set an augmented return url on the request
    pub fn augmented_return_url(mut self, return_url: String) -> DisclosureRequestBuilder {
        self.base.augmented_return_url(return_url);
        self
    }
}

/// Build a signature request
pub struct SignatureRequestBuilder {
    message: String,
    base: BaseRequestBuilder,
}

impl SignatureRequestBuilder {
    /// Construct a new builder for a request to sign the given message
    pub fn new(message: String) -> SignatureRequestBuilder {
        SignatureRequestBuilder {
            message,
            base: BaseRequestBuilder::new(),
        }
    }

    /// Construct the actual request based on the given information
    pub fn build(self) -> IrmaRequest {
        debug_assert!(!self.base.base.disclose.is_empty());
        IrmaRequest::Signature {
            message: self.message,
            base: self.base.build(),
        }
    }

    /// Add an additional disjunction to the request
    pub fn add_discon(mut self, discon: Vec<Vec<AttributeRequest>>) -> SignatureRequestBuilder {
        self.base.add_discon(discon);
        self
    }

    /// Add multiple additional disjunctions to the request
    pub fn add_discons(mut self, discons: ConDisCon) -> SignatureRequestBuilder {
        self.base.add_discons(discons);
        self
    }

    /// Add an additional labeled disjunction to the request
    pub fn add_discon_with_label(
        mut self,
        discon: Vec<Vec<AttributeRequest>>,
        label: TranslatedString,
    ) -> SignatureRequestBuilder {
        self.base.add_discon_with_label(discon, label);
        self
    }

    /// Set a return URL on the request
    pub fn return_url(mut self, return_url: String) -> SignatureRequestBuilder {
        self.base.return_url(return_url);
        self
    }

    /// Set an augmented return url on the request
    pub fn augmented_return_url(mut self, return_url: String) -> SignatureRequestBuilder {
        self.base.augmented_return_url(return_url);
        self
    }
}

/// Build a request to issue one or more credentials
#[derive(Default)]
pub struct IssuanceRequestBuilder {
    credentials: Vec<Credential>,
    base: BaseRequestBuilder,
}

impl IssuanceRequestBuilder {
    /// Construct a new builder
    pub fn new() -> IssuanceRequestBuilder {
        IssuanceRequestBuilder {
            credentials: vec![],
            base: BaseRequestBuilder::new(),
        }
    }

    /// Construct the actual request based on the given information
    pub fn build(self) -> IrmaRequest {
        debug_assert!(!self.credentials.is_empty());
        IrmaRequest::Issuance {
            credentials: self.credentials,
            base: self.base.build(),
        }
    }

    /// Add an additional credential to be issued
    pub fn add_credential(mut self, credential: Credential) -> IssuanceRequestBuilder {
        self.credentials.push(credential);
        self
    }

    /// Add an additional disjunction to the request
    pub fn add_discon(mut self, discon: Vec<Vec<AttributeRequest>>) -> IssuanceRequestBuilder {
        self.base.add_discon(discon);
        self
    }

    /// Add multiple additional disjunctions to the request
    pub fn add_discons(mut self, discons: ConDisCon) -> IssuanceRequestBuilder {
        self.base.add_discons(discons);
        self
    }

    /// Add an additional labeled disjunction to the request
    pub fn add_discon_with_label(
        mut self,
        discon: Vec<Vec<AttributeRequest>>,
        label: TranslatedString,
    ) -> IssuanceRequestBuilder {
        self.base.add_discon_with_label(discon, label);
        self
    }

    /// Set a return URL on the request
    pub fn return_url(mut self, return_url: String) -> IssuanceRequestBuilder {
        self.base.return_url(return_url);
        self
    }

    /// Set an augmented return url on the request
    pub fn augmented_return_url(mut self, return_url: String) -> IssuanceRequestBuilder {
        self.base.augmented_return_url(return_url);
        self
    }
}

/// An IRMA request extended with extra information for the server on how to execute it.
/// (Note: this interface is unstable, and might change significantly in the future)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ExtendedIrmaRequest {
    /// How long a session result JWT should be valid once requested, in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validity: Option<u64>,
    /// How long the session remains available for an IRMA client to connect to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    /// URL on which to recieve updates as the session status changes
    #[serde(rename = "callbackUrl", skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    /// Inner request
    pub request: IrmaRequest,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use maplit::hashmap;

    use crate::CredentialBuilder;

    use super::{
        AttributeRequest, Credential, DisclosureRequestBuilder, IssuanceRequestBuilder,
        SignatureRequestBuilder, TranslatedString,
    };

    #[test]
    fn test_attribute_request() {
        let attr1 = AttributeRequest::Simple("a.b.c.d".into());
        assert_eq!("\"a.b.c.d\"", serde_json::to_string(&attr1).unwrap());
        assert_eq!(
            attr1,
            serde_json::from_str(&serde_json::to_string(&attr1).unwrap()).unwrap()
        );

        let attr2 = AttributeRequest::non_null("x.y.z.d".into());
        assert_eq!(
            "{\"type\":\"x.y.z.d\",\"notNull\":true}",
            serde_json::to_string(&attr2).unwrap()
        );
        assert_eq!(
            attr2,
            serde_json::from_str(&serde_json::to_string(&attr2).unwrap()).unwrap()
        );

        let attr3 = AttributeRequest::with_value("f.g.h.i".into(), "testvalue".into());
        assert_eq!(
            "{\"type\":\"f.g.h.i\",\"value\":\"testvalue\"}",
            serde_json::to_string(&attr3).unwrap()
        );
        assert_eq!(
            attr3,
            serde_json::from_str(&serde_json::to_string(&attr3).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_credential() {
        let cred1 = CredentialBuilder::new("a.b.c".into())
            .attribute("d".into(), "e".into())
            .build();
        assert_eq!(
            "{\"credential\":\"a.b.c\",\"attributes\":{\"d\":\"e\"}}",
            serde_json::to_string(&cred1).unwrap()
        );
        assert_eq!(
            cred1,
            serde_json::from_str(&serde_json::to_string(&cred1).unwrap()).unwrap()
        );

        let cred2 = CredentialBuilder::new("a.b.c".into())
            .validity_period(Duration::new(300, 0))
            .attribute("d".into(), "e".into())
            .build();
        assert_eq!(
            format!(
                "{{\"credential\":\"a.b.c\",\"validity\":{},\"attributes\":{{\"d\":\"e\"}}}}",
                cred2.validity.clone().unwrap()
            ),
            serde_json::to_string(&cred2).unwrap()
        );
        assert_eq!(
            cred2,
            serde_json::from_str(&serde_json::to_string(&cred2).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_disclosure_request() {
        let req1 = DisclosureRequestBuilder::new()
            .add_discon(vec![vec![AttributeRequest::Simple("a.b.c.d".into())]])
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/disclosure/v2\",\"disclose\":[[[\"a.b.c.d\"]]]}", serde_json::to_string(&req1).unwrap());
        assert_eq!(
            req1,
            serde_json::from_str(&serde_json::to_string(&req1).unwrap()).unwrap()
        );

        let req2 = DisclosureRequestBuilder::new()
            .add_discon(vec![vec![AttributeRequest::non_null("x.y.z.w".into())]])
            .add_discon_with_label(
                vec![vec![AttributeRequest::Simple("a.b.c.d".into())]],
                TranslatedString {
                    en: "en".into(),
                    nl: "nl".into(),
                },
            )
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/disclosure/v2\",\"disclose\":[[[{\"type\":\"x.y.z.w\",\"notNull\":true}]],[[\"a.b.c.d\"]]],\"labels\":{\"1\":{\"en\":\"en\",\"nl\":\"nl\"}}}", serde_json::to_string(&req2).unwrap());
        assert_eq!(
            req2,
            serde_json::from_str(&serde_json::to_string(&req2).unwrap()).unwrap()
        );

        let req3 = DisclosureRequestBuilder::new()
            .add_discon(vec![vec![AttributeRequest::Simple("a.b.c.d".into())]])
            .return_url("https://example.com".into())
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/disclosure/v2\",\"disclose\":[[[\"a.b.c.d\"]]],\"clientReturnUrl\":\"https://example.com\"}", serde_json::to_string(&req3).unwrap());
        assert_eq!(
            req3,
            serde_json::from_str(&serde_json::to_string(&req3).unwrap()).unwrap()
        );

        let req4 = DisclosureRequestBuilder::new()
            .add_discon(vec![vec![AttributeRequest::Simple("a.b.c.d".into())]])
            .augmented_return_url("https://example.com".into())
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/disclosure/v2\",\"disclose\":[[[\"a.b.c.d\"]]],\"clientReturnUrl\":\"https://example.com\",\"augmentReturnUrl\":true}", serde_json::to_string(&req4).unwrap());
        assert_eq!(
            req4,
            serde_json::from_str(&serde_json::to_string(&req4).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_signature_request() {
        let req1 = SignatureRequestBuilder::new("testmessage".into())
            .add_discon(vec![vec![AttributeRequest::Simple("a.b.c.d".into())]])
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/signature/v2\",\"message\":\"testmessage\",\"disclose\":[[[\"a.b.c.d\"]]]}", serde_json::to_string(&req1).unwrap());
        assert_eq!(
            req1,
            serde_json::from_str(&serde_json::to_string(&req1).unwrap()).unwrap()
        );

        let req2 = SignatureRequestBuilder::new("testmessage".into())
            .add_discon_with_label(
                vec![vec![AttributeRequest::Simple("a.b.c.d".into())]],
                TranslatedString {
                    en: "en".into(),
                    nl: "nl".into(),
                },
            )
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/signature/v2\",\"message\":\"testmessage\",\"disclose\":[[[\"a.b.c.d\"]]],\"labels\":{\"0\":{\"en\":\"en\",\"nl\":\"nl\"}}}", serde_json::to_string(&req2).unwrap());
        assert_eq!(
            req2,
            serde_json::from_str(&serde_json::to_string(&req2).unwrap()).unwrap()
        );

        let req3 = SignatureRequestBuilder::new("testmessage".into())
            .add_discon(vec![vec![AttributeRequest::Simple("a.b.c.d".into())]])
            .return_url("https://example.com".into())
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/signature/v2\",\"message\":\"testmessage\",\"disclose\":[[[\"a.b.c.d\"]]],\"clientReturnUrl\":\"https://example.com\"}", serde_json::to_string(&req3).unwrap());
        assert_eq!(
            req3,
            serde_json::from_str(&serde_json::to_string(&req3).unwrap()).unwrap()
        );

        let req4 = SignatureRequestBuilder::new("testmessage".into())
            .add_discon(vec![vec![AttributeRequest::Simple("a.b.c.d".into())]])
            .augmented_return_url("https://example.com".into())
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/signature/v2\",\"message\":\"testmessage\",\"disclose\":[[[\"a.b.c.d\"]]],\"clientReturnUrl\":\"https://example.com\",\"augmentReturnUrl\":true}", serde_json::to_string(&req4).unwrap());
        assert_eq!(
            req4,
            serde_json::from_str(&serde_json::to_string(&req4).unwrap()).unwrap()
        );
    }

    #[test]
    fn test_issuance_request() {
        let req1 = IssuanceRequestBuilder::new()
            .add_credential(Credential {
                credential: "a.b.c".into(),
                validity: Some(123456789),
                attributes: hashmap![
                    "d".into() => "e".into(),
                ],
            })
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/issuance/v2\",\"credentials\":[{\"credential\":\"a.b.c\",\"validity\":123456789,\"attributes\":{\"d\":\"e\"}}]}", serde_json::to_string(&req1).unwrap());
        assert_eq!(
            req1,
            serde_json::from_str(&serde_json::to_string(&req1).unwrap()).unwrap()
        );

        let req2 = IssuanceRequestBuilder::new()
            .add_discon(vec![vec![AttributeRequest::Simple("x.y.z.w".into())]])
            .add_credential(Credential {
                credential: "a.b.c".into(),
                validity: Some(123456789),
                attributes: hashmap![
                    "d".into() => "e".into(),
                ],
            })
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/issuance/v2\",\"credentials\":[{\"credential\":\"a.b.c\",\"validity\":123456789,\"attributes\":{\"d\":\"e\"}}],\"disclose\":[[[\"x.y.z.w\"]]]}", serde_json::to_string(&req2).unwrap());
        assert_eq!(
            req2,
            serde_json::from_str(&serde_json::to_string(&req2).unwrap()).unwrap()
        );

        let req3 = IssuanceRequestBuilder::new()
            .add_discon_with_label(
                vec![vec![AttributeRequest::Simple("x.y.z.w".into())]],
                TranslatedString {
                    en: "en".into(),
                    nl: "nl".into(),
                },
            )
            .add_credential(Credential {
                credential: "a.b.c".into(),
                validity: Some(123456789),
                attributes: hashmap![
                    "d".into() => "e".into(),
                ],
            })
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/issuance/v2\",\"credentials\":[{\"credential\":\"a.b.c\",\"validity\":123456789,\"attributes\":{\"d\":\"e\"}}],\"disclose\":[[[\"x.y.z.w\"]]],\"labels\":{\"0\":{\"en\":\"en\",\"nl\":\"nl\"}}}", serde_json::to_string(&req3).unwrap());
        assert_eq!(
            req3,
            serde_json::from_str(&serde_json::to_string(&req3).unwrap()).unwrap()
        );

        let req4 = IssuanceRequestBuilder::new()
            .add_credential(Credential {
                credential: "a.b.c".into(),
                validity: Some(123456789),
                attributes: hashmap![
                    "d".into() => "e".into(),
                ],
            })
            .return_url("https://example.com".into())
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/issuance/v2\",\"credentials\":[{\"credential\":\"a.b.c\",\"validity\":123456789,\"attributes\":{\"d\":\"e\"}}],\"clientReturnUrl\":\"https://example.com\"}", serde_json::to_string(&req4).unwrap());
        assert_eq!(
            req4,
            serde_json::from_str(&serde_json::to_string(&req4).unwrap()).unwrap()
        );

        let req5 = IssuanceRequestBuilder::new()
            .add_credential(Credential {
                credential: "a.b.c".into(),
                validity: Some(123456789),
                attributes: hashmap![
                    "d".into() => "e".into(),
                ],
            })
            .augmented_return_url("https://example.com".into())
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/issuance/v2\",\"credentials\":[{\"credential\":\"a.b.c\",\"validity\":123456789,\"attributes\":{\"d\":\"e\"}}],\"clientReturnUrl\":\"https://example.com\",\"augmentReturnUrl\":true}", serde_json::to_string(&req5).unwrap());
        assert_eq!(
            req5,
            serde_json::from_str(&serde_json::to_string(&req5).unwrap()).unwrap()
        );

        let req6 = IssuanceRequestBuilder::new()
            .add_credential(Credential {
                credential: "a.b.c".into(),
                validity: None,
                attributes: hashmap![
                    "d".into() => "e".into(),
                ],
            })
            .build();
        assert_eq!("{\"@context\":\"https://irma.app/ld/request/issuance/v2\",\"credentials\":[{\"credential\":\"a.b.c\",\"attributes\":{\"d\":\"e\"}}]}", serde_json::to_string(&req6).unwrap());
        assert_eq!(
            req6,
            serde_json::from_str(&serde_json::to_string(&req6).unwrap()).unwrap()
        );
    }
}
