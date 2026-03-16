use crate::util::{IrmaToken, IrmaUrl};
use crate::Error;
use actix_web::{web::Data, web::Json, HttpResponse};
use irma::*;
use pg_core::api::IrmaAuthRequest;
use serde::Deserialize;

/// Maximum allowed validity (in seconds) of a JWT (1 day).
const MAX_VALIDITY: u64 = 60 * 60 * 24;

/// Default validity if no validity is specified (5 min).
const DEFAULT_VALIDITY: u64 = 60 * 5;

async fn create_irma_session(
    url: &IrmaUrl,
    irma_token: &IrmaToken,
    dr: IrmaRequest,
    validity: Option<u64>,
) -> Result<HttpResponse, Error> {
    let irma_url = url.get_ref().0.clone();
    let irma_token = irma_token.get_ref().0.clone();
    let kr = value.into_inner();

    const EMAIL_ATTR: &str = "pbdf.sidn-pbdf.email.email";

    // Determine whether this is a decryption request (kr.con contains non-email attributes
    // from the encrypted policy) or a signing request (email-only or empty con).
    let has_policy_attrs = kr.con.iter().any(|a| a.atype != EMAIL_ATTR);

    let dr = if has_policy_attrs {
        // Decryption flow: make every attribute from the policy mandatory so the
        // recipient must disclose the exact combination that was used for encryption.
        let discons: Vec<Vec<Vec<AttributeRequest>>> = kr
            .con
            .iter()
            .map(|attr| {
                vec![vec![AttributeRequest::Compound {
                    attr_type: attr.atype.clone(),
                    value: None,
                    not_null: true,
                }]]
            })
            .collect();

        DisclosureRequestBuilder::new().add_discons(discons).build()
    } else {
        // Signing flow: email is required, the rest are optional so the sender can
        // choose what extra attributes to include in their signing identity.
        let mandatory: Vec<Vec<Vec<AttributeRequest>>> =
            vec![vec![vec![AttributeRequest::Compound {
                attr_type: EMAIL_ATTR.to_string(),
                value: None,
                not_null: true,
            }]]];

        // Optional disjunctions: each starts with an empty conjunction so the user may skip it.
        let optional: Vec<Vec<Vec<AttributeRequest>>> = vec![
            // Phone number
            vec![
                vec![],
                vec![AttributeRequest::Compound {
                    attr_type: "pbdf.sidn-pbdf.mobilenumber.mobilenumber".to_string(),
                    value: None,
                    not_null: true,
                }],
            ],
            // Full name: driving licence, ID card, or passport
            vec![
                vec![],
                vec![
                    AttributeRequest::Compound {
                        attr_type: "pbdf.pbdf.drivinglicence.firstName".to_string(),
                        value: None,
                        not_null: true,
                    },
                    AttributeRequest::Compound {
                        attr_type: "pbdf.pbdf.drivinglicence.lastName".to_string(),
                        value: None,
                        not_null: true,
                    },
                ],
                vec![
                    AttributeRequest::Compound {
                        attr_type: "pbdf.pbdf.idcard.firstName".to_string(),
                        value: None,
                        not_null: true,
                    },
                    AttributeRequest::Compound {
                        attr_type: "pbdf.pbdf.idcard.lastName".to_string(),
                        value: None,
                        not_null: true,
                    },
                ],
                vec![
                    AttributeRequest::Compound {
                        attr_type: "pbdf.pbdf.passport.firstName".to_string(),
                        value: None,
                        not_null: true,
                    },
                    AttributeRequest::Compound {
                        attr_type: "pbdf.pbdf.passport.lastName".to_string(),
                        value: None,
                        not_null: true,
                    },
                ],
            ],
            // Date of birth: driving licence, ID card, or passport
            vec![
                vec![],
                vec![AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.drivinglicence.dateOfBirth".to_string(),
                    value: None,
                    not_null: true,
                }],
                vec![AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.idcard.dateOfBirth".to_string(),
                    value: None,
                    not_null: true,
                }],
                vec![AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.passport.dateOfBirth".to_string(),
                    value: None,
                    not_null: true,
                }],
            ],
        ];

        DisclosureRequestBuilder::new()
            .add_discons([mandatory, optional].concat())
            .build()
    };

    log::debug!(
        "disclosure request: {}",
        serde_json::to_string_pretty(&dr).unwrap_or_default()
    );

    let validity = match kr.validity {
        Some(validity) if validity > MAX_VALIDITY => Err(Error::ValidityError),
        Some(validity) => Ok(validity),
        None => Ok(DEFAULT_VALIDITY),
    }?;

    let er = ExtendedIrmaRequest {
        timeout: None,
        callback_url: None,
        validity: Some(validity),
        request: dr,
    };

    let mut builder = IrmaClientBuilder::new(&url.0).map_err(|_e| Error::ClientInvalid)?;
    if let Some(token) = irma_token.0.clone() {
        builder = builder.token_authentication(token);
    }
    let client = builder.build();

    let session = client
        .request_extended(&er)
        .await
        .or(Err(Error::SessionCreationError))?;

    Ok(HttpResponse::Ok().json(session))
}

/// Starts a Yivi disclosure session for decryption.
/// Builds a mandatory disclosure for every attribute in the encrypted file's policy.
pub async fn start(
    url: Data<IrmaUrl>,
    irma_token: Data<IrmaToken>,
    value: Json<IrmaAuthRequest>,
) -> Result<HttpResponse, Error> {
    let kr = value.into_inner();

    let discons: Vec<Vec<Vec<AttributeRequest>>> = kr
        .con
        .iter()
        .map(|attr| {
            vec![vec![AttributeRequest::Compound {
                attr_type: attr.atype.clone(),
                value: None,
                not_null: true,
            }]]
        })
        .collect();

    let dr = DisclosureRequestBuilder::new().add_discons(discons).build();

    log::debug!(
        "decryption disclosure request: {}",
        serde_json::to_string_pretty(&dr).unwrap_or_default()
    );

    create_irma_session(&url, &irma_token, dr, kr.validity).await
}

#[derive(Deserialize, Default)]
pub struct SignStartRequest {
    pub validity: Option<u64>,
}

/// Starts a Yivi disclosure session for signing.
/// Email is mandatory; phone number, full name, and date of birth are optional.
pub async fn start_sign(
    url: Data<IrmaUrl>,
    irma_token: Data<IrmaToken>,
    value: Json<SignStartRequest>,
) -> Result<HttpResponse, Error> {
    const EMAIL_ATTR: &str = "pbdf.sidn-pbdf.email.email";

    let mandatory: Vec<Vec<Vec<AttributeRequest>>> = vec![vec![vec![AttributeRequest::Compound {
        attr_type: EMAIL_ATTR.to_string(),
        value: None,
        not_null: true,
    }]]];

    // Optional disjunctions: each starts with an empty conjunction so the user may skip it.
    let optional: Vec<Vec<Vec<AttributeRequest>>> = vec![
        // Phone number
        vec![
            vec![],
            vec![AttributeRequest::Compound {
                attr_type: "pbdf.sidn-pbdf.mobilenumber.mobilenumber".to_string(),
                value: None,
                not_null: true,
            }],
        ],
        // Full name: driving licence, ID card, or passport
        vec![
            vec![],
            vec![
                AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.drivinglicence.firstName".to_string(),
                    value: None,
                    not_null: true,
                },
                AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.drivinglicence.lastName".to_string(),
                    value: None,
                    not_null: true,
                },
            ],
            vec![
                AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.idcard.firstName".to_string(),
                    value: None,
                    not_null: true,
                },
                AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.idcard.lastName".to_string(),
                    value: None,
                    not_null: true,
                },
            ],
            vec![
                AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.passport.firstName".to_string(),
                    value: None,
                    not_null: true,
                },
                AttributeRequest::Compound {
                    attr_type: "pbdf.pbdf.passport.lastName".to_string(),
                    value: None,
                    not_null: true,
                },
            ],
        ],
        // Date of birth: driving licence, ID card, or passport
        vec![
            vec![],
            vec![AttributeRequest::Compound {
                attr_type: "pbdf.pbdf.drivinglicence.dateOfBirth".to_string(),
                value: None,
                not_null: true,
            }],
            vec![AttributeRequest::Compound {
                attr_type: "pbdf.pbdf.idcard.dateOfBirth".to_string(),
                value: None,
                not_null: true,
            }],
            vec![AttributeRequest::Compound {
                attr_type: "pbdf.pbdf.passport.dateOfBirth".to_string(),
                value: None,
                not_null: true,
            }],
        ],
    ];

    let dr = DisclosureRequestBuilder::new()
        .add_discons([mandatory, optional].concat())
        .build();

    log::debug!(
        "signing disclosure request: {}",
        serde_json::to_string_pretty(&dr).unwrap_or_default()
    );

    create_irma_session(&url, &irma_token, dr, value.validity).await
}
