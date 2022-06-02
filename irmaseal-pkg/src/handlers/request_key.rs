use crate::Error;
use actix_web::{web::Data, web::Path, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use irma::*;
use irmaseal_core::api::KeyResponse;
use irmaseal_core::kem::IBKEM;
use irmaseal_core::{Attribute, Policy, UserSecretKey};
use jsonwebtoken::{decode, errors::ErrorKind, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// Custom claims signed by the IRMA server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Claims {
    // Mandatory JWT fields.
    exp: u64,
    iat: u64,
    iss: String,
    sub: String,

    // Mandatory IRMA claims, always present.
    token: irma::SessionToken,
    status: irma::SessionStatus,
    r#type: irma::SessionType,

    // Optional fields, only present when the session is a finished disclosure session.
    proof_status: Option<irma::ProofStatus>,
    disclosed: Option<Vec<Vec<DisclosedAttribute>>>,
}

/// Fetch identity iff valid, or else yield nothing.
fn fetch_policy(timestamp: u64, disclosed: &[Vec<DisclosedAttribute>]) -> Option<Policy> {
    // Convert disclosed attributes to a Policy
    let res: Result<Vec<Attribute>, _> = disclosed
        .iter()
        .flatten()
        .map(|a| match a.status {
            AttributeStatus::Present => {
                Attribute::new(&a.identifier, a.raw_value.as_deref()).or(Err(Error::Unexpected))
            }
            _ => Err(Error::Unexpected),
        })
        .collect();

    let con = res.ok()?;

    Some(Policy { timestamp, con })
}

pub async fn request_key<K: IBKEM>(
    msk: Data<K::Sk>,
    path: Path<u64>,
    decoding_key: Data<DecodingKey>,
    auth: BearerAuth,
) -> Result<HttpResponse, crate::Error>
where
    UserSecretKey<K>: Serialize,
{
    let sk = msk.get_ref();
    let timestamp = path.into_inner();
    let token = auth.token();

    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;

    // This also checks that the expiry date has not passed.
    let decoded =
        decode::<Claims>(token, &decoding_key, &validation).map_err(|e| match e.into_kind() {
            ErrorKind::ExpiredSignature => Error::ChronologyError,
            _ => Error::DecodingError,
        })?;

    // It is not allowed to ask for USKs with a timestamp beyond the expiry date.
    if timestamp > decoded.claims.exp {
        return Err(Error::ChronologyError);
    }

    let usk = match decoded.claims {
        Claims {
            status: SessionStatus::Done,
            proof_status: Some(ProofStatus::Valid),
            r#type: SessionType::Disclosing,
            disclosed: Some(ref disclosed),
            ..
        } => match fetch_policy(timestamp, disclosed) {
            Some(p) => {
                let k = p.derive::<K>().map_err(|_e| crate::Error::Unexpected)?;
                let mut rng = rand::thread_rng();
                let usk = K::extract_usk(None, sk, &k, &mut rng);

                Some(UserSecretKey::<K>(usk))
            }
            _ => None,
        },
        _ => None,
    };

    Ok(HttpResponse::Ok().json(KeyResponse {
        status: decoded.claims.status,
        proof_status: decoded.claims.proof_status,
        key: usk,
    }))
}
