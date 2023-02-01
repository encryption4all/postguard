use actix_web::{web::Data, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use irmaseal_core::api::{KeyResponse, SigningKey};
use irmaseal_core::Policy;
use serde::Serialize;

use irmaseal_core::ibs::gg::{keygen, Identity, SecretKey};

use crate::middleware::irma::IrmaAuthResult;
use crate::util::current_time_u64;

pub async fn request_signing_key(
    req: HttpRequest,
    msk: Data<SecretKey>,
) -> Result<HttpResponse, crate::Error>
where
    SecretKey: Serialize,
{
    let sk = msk.get_ref();
    let mut rng = rand::thread_rng();

    let IrmaAuthResult {
        con,
        status,
        proof_status,
        ..
    } = req
        .extensions()
        .get::<IrmaAuthResult>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    req.extensions_mut().clear();

    // The PKG gets to decide the timestamp in the policy.
    let iat = current_time_u64()?;

    let policy = Policy {
        timestamp: iat,
        con,
    };

    let derived = policy
        .derive::<32>()
        .map_err(|_e| crate::Error::Unexpected)?;

    let id = Identity(derived);
    let key = keygen(sk, &id, &mut rng);

    Ok(HttpResponse::Ok().json(KeyResponse {
        status,
        proof_status,
        key: Some(SigningKey { key, iat }),
    }))
}
