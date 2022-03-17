use crate::Error;
use actix_web::{web::Data, web::Path, HttpResponse};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use irma::*;
use irmaseal_core::api::{KeyResponse, KeyStatus};
use irmaseal_core::kem::IBKEM;
use irmaseal_core::{Attribute, Policy, UserSecretKey};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// Custom claims
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: u64,
    iat: u64,
    iss: String,
    sub: String,
    token: String,
    status: String,
    r#type: String,
    disclosed: Vec<Vec<DisclosedAttribute>>,
}

/// Fetch identity iff valid, or else yield nothing.
fn fetch_policy(timestamp: u64, disclosed: &[Vec<DisclosedAttribute>]) -> Option<Policy> {
    // Convert disclosed attributes to a Policy
    let res: Result<Vec<Attribute>, _> = disclosed
        .iter()
        .flatten()
        .map(|a| match a.status {
            AttributeStatus::Present => Ok(Attribute {
                atype: a.identifier.clone(),
                value: a.raw_value.clone(),
            }),
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

    // Use the decoding key and JWT encoded data to:
    // - decode the JWT,
    // - check that JWT is still valid,
    // - check the timestamp is between the issuance date and the expiry date,
    // - retrieve the disclosed attributes from the JWT and issue a user secret key.

    let token = auth.token();
    let decoded =
        decode::<Claims>(token, &decoding_key, &Validation::new(Algorithm::RS256)).unwrap();

    if timestamp < decoded.claims.iat || timestamp > decoded.claims.exp {
        return Err(Error::ChronologyError);
    }

    // TODO:
    // - check sub?
    // - check issuer
    // - check status
    // - check type

    let d = |status: KeyStatus| Ok(KeyResponse { status, key: None });

    let kr = match fetch_policy(timestamp, &decoded.claims.disclosed) {
        Some(p) => {
            let k = p.derive::<K>().map_err(|_e| crate::Error::Unexpected)?;
            let mut rng = rand::thread_rng();
            let usk = K::extract_usk(None, sk, &k, &mut rng);

            Ok(KeyResponse {
                status: KeyStatus::DoneValid,
                key: Some(UserSecretKey::<K>(usk)),
            })
        }
        None => d(KeyStatus::DoneInvalid),
    }?;

    Ok(HttpResponse::Ok().json(kr))
}
