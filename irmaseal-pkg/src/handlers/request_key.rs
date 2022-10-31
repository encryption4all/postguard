use actix_web::{web::Data, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use irmaseal_core::kem::IBKEM;

pub async fn request_key<K: IBKEM + 'static>(
    req: HttpRequest,
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
