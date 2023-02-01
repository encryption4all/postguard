use actix_web::{web::Data, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use irma::SessionResult;
use irmaseal_core::api::{KeyResponse, SigningKey};
use irmaseal_core::{Attribute, Policy};
use serde::Serialize;

use irmaseal_core::ibs::gg::{keygen, Identity, SecretKey};

use crate::util::now;

pub async fn request_signing_key(
    req: HttpRequest,
    msk: Data<SecretKey>,
) -> Result<HttpResponse, crate::Error>
where
    SecretKey: Serialize,
{
    let sk = msk.get_ref();
    let mut rng = rand::thread_rng();

    let validated = req
        .extensions()
        .get::<Option<Vec<Attribute>>>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    let session_result = req
        .extensions()
        .get::<SessionResult>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    req.extensions_mut().clear();

    let iat = now()?;

    if let Some(val) = validated {
        let policy = Policy {
            timestamp: iat,
            con: val,
        };

        let derived = policy
            .derive::<32>()
            .map_err(|_e| crate::Error::Unexpected)?;

        let id = Identity(derived);

        let key = keygen(sk, &id, &mut rng);

        Ok(HttpResponse::Ok().json(KeyResponse {
            status: session_result.status,
            proof_status: session_result.proof_status,
            key: Some(SigningKey { key, iat }),
        }))
    } else {
        Ok(HttpResponse::Forbidden().finish())
    }
}
