use actix_web::web::{Data, HttpResponse, Path};
use irmaseal_core::api::{KeyResponse, KeyStatus};
use irmaseal_core::kem::IBKEM;
use irmaseal_core::{Identity, UserSecretKey};

use irma::*;

use crate::server::MasterKeyPair;
use crate::Error;

/// Fetch identity iff valid, or else yield nothing.
fn fetch_identity(timestamp: u64, disclosed: &Vec<Vec<DisclosedAttribute>>) -> Option<Identity> {
    let disclosed = if disclosed.len() == 1 && disclosed[0].len() == 1 {
        &disclosed[0][0]
    } else {
        return None;
    };

    match disclosed.status {
        AttributeStatus::Present => Identity::new(
            timestamp,
            &disclosed.identifier,
            disclosed.raw_value.as_ref().map(|s| &**s),
        )
        .ok(),
        _ => None,
    }
}

pub async fn request_fetch<K: IBKEM>(
    irma: Data<String>,
    mkp: Data<MasterKeyPair<K>>,
    path: Path<(String, u64)>,
) -> Result<HttpResponse, crate::Error> {
    let irma_url = irma.get_ref().clone();
    let kp = mkp.get_ref().clone();
    let (token, timestamp) = path.into_inner();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if timestamp > now {
        Err(Error::ChronologyError)?
    }

    let client = IrmaClientBuilder::new(&irma_url).unwrap().build();
    let result = client.result(&SessionToken(token)).await;

    let d = |status: KeyStatus| KeyResponse { status, key: None };

    let kr = match result {
        Ok(result) => match fetch_identity(timestamp, &result.disclosed) {
            Some(i) => {
                let k = i.derive::<K>().map_err(|_e| crate::Error::Unexpected)?;
                let mut rng = rand::thread_rng();
                let usk = K::extract_usk(Some(&kp.pk), &kp.sk, &k, &mut rng);

                KeyResponse {
                    status: KeyStatus::DoneValid,
                    key: Some(UserSecretKey::<K>(usk)),
                }
            }
            None => d(KeyStatus::DoneInvalid),
        },
        // TODO: map every irma::Error to an associated KeyStatus
        Err(irma::Error::SessionNotFinished) => d(KeyStatus::Connected),
        Err(irma::Error::SessionTimedOut) => d(KeyStatus::Cancelled),
        Err(irma::Error::SessionCancelled) => d(KeyStatus::Connected),
        Err(irma::Error::NetworkError(x)) => {
            println!("NetworkError: {:?}", x);
            d(KeyStatus::Pairing)
        }
        Err(irma::Error::InvalidUrl(_)) => d(KeyStatus::Timeout),
    };

    Ok(HttpResponse::Ok().json(kr))
}
