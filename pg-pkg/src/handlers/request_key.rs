use actix_web::{web::Data, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use pg_core::api::KeyResponse;
use pg_core::artifacts::UserSecretKey;
use pg_core::identity::RecipientPolicy;
use pg_core::kem::IBKEM;

use crate::middleware::irma::IrmaAuthResult;
use crate::util::current_time_u64;

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

    let timestamp = req
        .match_info()
        .query("timestamp")
        .parse::<u64>()
        .map_err(|_e| crate::Error::NoTimestampError)?;

    let IrmaAuthResult {
        con,
        status,
        proof_status,
        exp,
    } = req
        .extensions()
        .get::<IrmaAuthResult>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    // It is not allowed to ask for USKs with a timestamp in the future.
    let now = current_time_u64()?;
    if timestamp > now {
        return Err(crate::Error::ChronologyError);
    }

    // It is not allowed to ask for USKs with a timestamp beyond the expiry date.
    if let Some(exp) = exp {
        if timestamp > exp {
            return Err(crate::Error::ChronologyError);
        }
    }

    req.extensions_mut().clear();

    let policy = RecipientPolicy { timestamp, con };

    let id = policy
        .derive_kem::<K>()
        .map_err(|_e| crate::Error::Unexpected)?;

    let usk = K::extract_usk(None, sk, &id, &mut rng);

    Ok(HttpResponse::Ok().json(KeyResponse {
        status,
        proof_status,
        key: Some(UserSecretKey::<K>(usk)),
    }))
}
