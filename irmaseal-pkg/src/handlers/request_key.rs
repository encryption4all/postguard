use actix_web::{web::Data, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use serde::Serialize;

use irmaseal_core::api::KeyResponse;
use irmaseal_core::kem::IBKEM;
use irmaseal_core::UserSecretKey;

pub async fn request_key<K: IBKEM + 'static>(
    req: HttpRequest,
    msk: Data<K::Sk>,
) -> Result<HttpResponse, crate::Error>
where
    UserSecretKey<K>: Serialize,
{
    let sk = msk.get_ref();
    let mut rng = rand::thread_rng();

    let id = req
        .extensions()
        .get::<K::Id>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    req.extensions_mut().clear();

    let usk = K::extract_usk(None, sk, &id, &mut rng);

    Ok(HttpResponse::Ok().json(KeyResponse {
        key: UserSecretKey::<K>(usk),
    }))
}
