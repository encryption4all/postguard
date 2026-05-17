use crate::{irmaclient::SessionToken, util::TranslatedString};

use serde::{Deserialize, Serialize};

/// Status of an disclosed attribute
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttributeStatus {
    Present,
    Extra,
    Null,
}

/// Status of an IRMA proof
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStatus {
    Valid,
    Invalid,
    InvalidTimestamp,
    UnmatchedRequest,
    MissingAttributes,
    Expired,
}

/// Status of an IRMA session
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SessionStatus {
    Initialized,
    Pairing,
    Connected,
    Cancelled,
    Done,
    Timeout,
}

/// Type of an IRMA session
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    Disclosing,
    Signing,
    Issuing,
}

/// A disclosed attribute
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct DisclosedAttribute {
    /// The value of the attribute as encoded in the credential
    #[serde(rename = "rawvalue", skip_serializing_if = "Option::is_none")]
    pub raw_value: Option<String>,
    /// A representation of the value that can be used for displaying in UI's of various languages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<TranslatedString>,
    /// Identifier of the disclosed attribute
    #[serde(rename = "id")]
    pub identifier: String,
    /// Additional information on the role of the disclosed attribute in the complete session result
    pub status: AttributeStatus,
}

/// Results of a session
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SessionResult {
    /// Token of the session
    pub token: SessionToken,
    #[serde(rename = "type")]
    /// Type of the session (disclosure/issuance/signature)
    pub sessiontype: SessionType,
    /// Current state of the session
    pub status: SessionStatus,
    /// Status of the proof provided by the irma client (if it has already provided proofs)
    #[serde(rename = "proofStatus", skip_serializing_if = "Option::is_none")]
    pub proof_status: Option<ProofStatus>,
    /// Attributes disclosed by the irma client to the server
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub disclosed: Vec<Vec<DisclosedAttribute>>,
    /// The full signature, if this was a signing session, as parsed json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use crate::{
        AttributeStatus, DisclosedAttribute, ProofStatus, SessionResult, SessionStatus,
        SessionToken, SessionType, TranslatedString,
    };

    #[test]
    fn test_decode_result() {
        let result = serde_json::from_str::<SessionResult>(
            r#"
        {
            "type" : "disclosing",
            "status" : "DONE",
            "disclosed" : [
              [{
                "status" : "PRESENT",
                "rawvalue" : "yes",
                "id" : "irma-demo.MijnOverheid.ageLower.over18",
                "value" : {
                  "en" : "yes",
                  "nl" : "yes",
                  "" : "yes"
                }
              }]
            ],
            "proofStatus" : "VALID",
            "token" : "ELMExi5iauWYHzbH7gwU"
        }
        "#,
        )
        .unwrap();

        let expected = SessionResult {
            sessiontype: SessionType::Disclosing,
            status: SessionStatus::Done,
            disclosed: vec![vec![DisclosedAttribute {
                status: AttributeStatus::Present,
                raw_value: Some("yes".into()),
                identifier: "irma-demo.MijnOverheid.ageLower.over18".into(),
                value: Some(TranslatedString {
                    en: "yes".into(),
                    nl: "yes".into(),
                }),
            }]],
            proof_status: Some(ProofStatus::Valid),
            token: SessionToken("ELMExi5iauWYHzbH7gwU".into()),
            signature: None,
        };

        assert_eq!(result, expected);
        assert_eq!(
            expected,
            serde_json::from_str(&serde_json::to_string(&expected).unwrap()).unwrap()
        );

        let result = serde_json::from_str::<SessionResult>(
            r#"
        {
            "type" : "disclosing",
            "status" : "CONNECTED",
            "token" : "ELMExi5iauWYHzbH7gwU"
        }
        "#,
        )
        .unwrap();

        let expected = SessionResult {
            sessiontype: SessionType::Disclosing,
            status: SessionStatus::Connected,
            disclosed: vec![],
            proof_status: None,
            token: SessionToken("ELMExi5iauWYHzbH7gwU".into()),
            signature: None,
        };

        assert_eq!(result, expected);
        assert_eq!(
            expected,
            serde_json::from_str(&serde_json::to_string(&expected).unwrap()).unwrap()
        );

        let result = serde_json::from_str::<SessionResult>(
            r#"
        {
            "token":"bVqg9btHRhiMvEWs8axQ",
            "status":"DONE",
            "type":"issuing",
            "proofStatus":"VALID"
        }
        "#,
        )
        .unwrap();

        let expected = SessionResult {
            sessiontype: SessionType::Issuing,
            status: SessionStatus::Done,
            disclosed: vec![],
            proof_status: Some(ProofStatus::Valid),
            token: SessionToken("bVqg9btHRhiMvEWs8axQ".into()),
            signature: None,
        };

        assert_eq!(result, expected);
        assert_eq!(
            expected,
            serde_json::from_str(&serde_json::to_string(&expected).unwrap()).unwrap()
        );

        let mut result = serde_json::from_str::<SessionResult>(
            r#"
            {
                "token": "5bTpPRXctenYGGsZVe3x",
                "status": "DONE",
                "type": "signing",
                "proofStatus": "VALID",
                "disclosed": [
                    [
                        {
                            "rawvalue": "Testtown",
                            "value": {
                                "": "Testtown",
                                "en": "Testtown",
                                "nl": "Testtown"
                            },
                            "id": "irma-demo.gemeente.address.city",
                            "status": "PRESENT",
                            "issuancetime": 1632355200
                        }
                    ]
                ],
                "signature": {
                    "@context": "https://irma.app/ld/signature/v2",
                    "signature": [
                        {
                            "c": "6huXPHk3XEsdKAiVB/z3JWnDk74k044KQdjf3ABOSdA=",
                            "A": "ChiWjymMPhHB/TGYNknx+ka/SsNQ4MgNUYrPwLytX3ptQolLGlanH3UBLd2Ses8z4xBGdn8gh9XAiDYRcIn4azOTKLs/VC8aYqTPFlwqx/IpI6eCsHTRwI7Boqzfl3GCc93mQuHjswmupobX0HarxNlTto3UZZu/ra62/+TDTB4=",
                            "e_response": "rYPv4DSPe+/T85gymucls7UPYP9cvq15DGhcGJWcJxiCqzCo6WX0D0Z7rjvDBVGHZe/fBu9l+vty",
                            "v_response": "90FNfsqcHUgjaDi9kTFYEYhWQ9eR9At+HlaExxLtLx+CuVsAzmm4QlxKDBqreq20mVt15vZP0geMI/IMqOFYTDW+0sT/to08lxicv+Mk5A2tQEYX6HiQ42IQkvVzpddIDtkEMlRlO9KFtWLxR1G5wLGc28pNG8frDyhfiE0lErSnSG+QIAD9XRaFCdjuqUo4VPty+6pwC0qfvVPnxOPZqgTPnQ/Ci9kq02DcwArpLmP5YZtpRTMiUqw4+MUXySP2htDx7nkLzdoUYKppkKXB3py5Y15tTI/B5IWDgzbeTEx5Ucg+/1NwzTUSeU6hsnmKyS6ImavnVrnL0DbEuoU=",
                            "a_responses": {
                                "0": "X/VvAAjkYmLoTK3fjiA3nhgP/OVFAOFjvjbWmFTjMtWJ+c9mhJl6aOBuyeYFFHCqbOrrhLR9uXWv6BgSnQ9Wv2VVjlbWsBPwIoU=",
                                "2": "eD0yflYsAwqBcalnn+vw6iJad+L7XnQ6lOfNibpM8OzLlVhluHdl5dCEaiYb4D5GuY5FlN5x61+76howTAMBeTmK8Kb8ASTKE6U=",
                                "3": "CiP0nUhwZNR37KOX4BMA7Inwtjd7o+A3BjXGrVURWkRhyBu5DfYLufG+72fUylelX03DGxzCmfOC/s3g2hOtB5IJUh9FlRvfCio=",
                                "4": "2p/LHHmbc+TsD27owEfPhlj+dc61BivSTY8l7UzMdp0eBhUw5nyS427I9Lg++bz2SfUiZWJiHhL17KxX3CbKcu+E1rkyvelAUlI=",
                                "5": "gWw0+6hy07KTPR+2B0GoCWD3h9sKEYztaqLzK4bGOCjVrFyrqh62ivRmMaoajzZEKs6CL2vxFZzparsPOxvm5g7HU6ck4t9fUII="
                            },
                            "a_disclosed": {
                                "1": "AwAKiwAZAABN+49oR9DJEejyRUj8yxMB",
                                "6": "qMrm6Oje7t0="
                            },
                            "rangeproofs": null
                        }
                    ],
                    "indices": [
                        [
                            {
                                "cred": 0,
                                "attr": 6
                            }
                        ]
                    ],
                    "nonce": "mO6XOXwetC2zIQ1jQPyKzQ==",
                    "context": "AQ==",
                    "message": "Test message",
                    "timestamp": {
                        "Time": 1636103859,
                        "ServerUrl": "https://keyshare.privacybydesign.foundation/atumd/",
                        "Sig": {
                            "Alg": "ed25519",
                            "Data": "QJ4rO+EOOz+TGKeudFerazn1wXPBV15QjxXz+syxPz4DvZ0LVT74X35XN3V9KuRSYWBG3XkXehIw/EpFqlwpDw==",
                            "PublicKey": "MKdXxJxEWPRIwNP7SuvP0J/M/NV51VZvqCyO+7eDwJ8="
                        }
                    }
                }
            }
        "#,
        )
        .unwrap();

        let expected = SessionResult {
            sessiontype: SessionType::Signing,
            status: SessionStatus::Done,
            disclosed: vec![vec![DisclosedAttribute {
                status: AttributeStatus::Present,
                raw_value: Some("Testtown".into()),
                value: Some(TranslatedString {
                    en: "Testtown".into(),
                    nl: "Testtown".into(),
                }),
                identifier: "irma-demo.gemeente.address.city".into(),
            }]],
            proof_status: Some(ProofStatus::Valid),
            token: SessionToken("5bTpPRXctenYGGsZVe3x".into()),
            signature: None,
        };

        // Ignore signature as we are not fully parsing that
        assert!(result.signature.is_some());
        result.signature = None;

        assert_eq!(result, expected);
        assert_eq!(
            expected,
            serde_json::from_str(&serde_json::to_string(&expected).unwrap()).unwrap()
        );
    }
}
