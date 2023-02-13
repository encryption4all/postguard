use actix_web::{web::Data, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use pg_core::api::KeyResponse;
use pg_core::artifacts::SigningKey;
use pg_core::identity::RecipientPolicy;
use serde::Serialize;

use pg_core::ibs::gg::{keygen, Identity, SecretKey, IDENTITY_SIZE};

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

    let policy = RecipientPolicy {
        timestamp: iat,
        con,
    };

    let derived = policy
        .derive::<IDENTITY_SIZE>()
        .map_err(|_e| crate::Error::Unexpected)?;

    let id = Identity::from(derived);
    let key = keygen(sk, &id, &mut rng);

    Ok(HttpResponse::Ok().json(KeyResponse {
        status,
        proof_status,
        key: Some(SigningKey { key, iat }),
    }))
}
