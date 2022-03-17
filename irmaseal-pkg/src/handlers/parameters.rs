use actix_web::{web::Data, HttpResponse};
use irmaseal_core::kem::IBKEM;
use irmaseal_core::{api::Parameters, PublicKey};
use serde::Serialize;

pub async fn parameters<K: IBKEM>(mpk: Data<K::Pk>) -> Result<HttpResponse, crate::Error>
where
    PublicKey<K>: Serialize,
{
    let pars = Parameters::<K> {
        format_version: 0x00,
        max_age: 300,
        public_key: PublicKey(mpk.get_ref().clone()),
    };

    Ok(HttpResponse::Ok().json(pars))
}
