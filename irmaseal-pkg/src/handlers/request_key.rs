use actix_web::{web::Data, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use irmaseal_core::kem::IBKEM;

<<<<<<< HEAD
pub async fn request_key<K: IBKEM + 'static>(
    req: HttpRequest,
||||||| 4a51aa9
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
=======
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
            AttributeStatus::Present => Ok(Attribute::new(&a.identifier, a.raw_value.as_deref())),
            _ => Err(Error::Unexpected),
        })
        .collect();

    let con = res.ok()?;

    Some(Policy { timestamp, con })
}

pub async fn request_key<K: IBKEM>(
>>>>>>> refactor-lib
    msk: Data<K::Sk>,
) -> Result<HttpResponse, crate::Error> {
    let sk = msk.get_ref();
    let mut rng = rand::thread_rng();

    let id = req
        .extensions()
        .get::<K::Id>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    req.extensions_mut().clear();

    let usk = K::extract_usk(None, sk, &id, &mut rng);

    let mut res = HttpResponse::Ok().finish();
    res.extensions_mut().insert(usk);

    Ok(res)
}
