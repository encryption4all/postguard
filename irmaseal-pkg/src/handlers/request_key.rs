use actix_web::{web::Data, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use irma::SessionResult;
use irmaseal_core::api::KeyResponse;
use irmaseal_core::kem::IBKEM;
use irmaseal_core::{Attribute, Policy, UserSecretKey};
use serde::Serialize;

pub async fn request_key<K>(
    req: HttpRequest,
    msk: Data<K::Sk>,
) -> Result<HttpResponse, crate::Error>
where
    K: IBKEM + 'static,
    UserSecretKey<K>: Serialize,
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

    let timestamp = req
        .extensions()
        .get::<u64>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    req.extensions_mut().clear();

    if let Some(val) = validated {
        let policy = Policy {
            timestamp,
            con: val,
        };

        let id = policy
            .derive_kem::<K>()
            .map_err(|_e| crate::Error::Unexpected)?;

        let usk = K::extract_usk(None, sk, &id, &mut rng);

        Ok(HttpResponse::Ok().json(KeyResponse {
            status: session_result.status,
            proof_status: session_result.proof_status,
            key: Some(UserSecretKey::<K>(usk)),
        }))
    } else {
        Ok(HttpResponse::Forbidden().finish())
    }
}
