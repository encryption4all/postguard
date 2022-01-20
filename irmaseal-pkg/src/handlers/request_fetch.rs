use actix_web::web::{Data, HttpResponse, Path};
use irmaseal_core::api::{KeyResponse, KeyStatus};
use irmaseal_core::kem::IBKEM;
use irmaseal_core::{Attribute, Policy, UserSecretKey};

use irma::*;
use serde::Serialize;

use crate::server::MasterKeyPair;
use crate::Error;

/// Fetch identity iff valid, or else yield nothing.
fn fetch_policy(timestamp: u64, disclosed: &Vec<Vec<DisclosedAttribute>>) -> Option<Policy> {
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

pub async fn request_fetch<K: IBKEM>(
    irma: Data<String>,
    mkp: Data<MasterKeyPair<K>>,
    path: Path<(String, u64)>,
) -> Result<HttpResponse, crate::Error>
where
    UserSecretKey<K>: Serialize,
{
    let irma_url = irma.get_ref().clone();
    let kp = mkp.get_ref().clone();
    let (token, timestamp) = path.into_inner();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if timestamp > now {
        return Err(Error::ChronologyError);
    }

    let client = IrmaClientBuilder::new(&irma_url).unwrap().build();
    let result = client.result(&SessionToken(token)).await;

    let d = |status: KeyStatus| Ok(KeyResponse { status, key: None });

    let kr = match result {
        Ok(result) => match fetch_policy(timestamp, &result.disclosed) {
            Some(p) => {
                let k = p.derive::<K>().map_err(|_e| crate::Error::Unexpected)?;
                let mut rng = rand::thread_rng();
                let usk = K::extract_usk(Some(&kp.pk), &kp.sk, &k, &mut rng);

                Ok(KeyResponse {
                    status: KeyStatus::DoneValid,
                    key: Some(UserSecretKey::<K>(usk)),
                })
            }
            None => d(KeyStatus::DoneInvalid),
        },
        Err(irma::Error::SessionNotFinished(status)) => match status {
            irma::SessionStatus::Initialized => d(KeyStatus::Initialized),
            irma::SessionStatus::Pairing => d(KeyStatus::Pairing),
            irma::SessionStatus::Connected => d(KeyStatus::Connected),
            _ => Err(crate::Error::Unexpected),
        },
        Err(irma::Error::SessionTimedOut) => d(KeyStatus::Timeout),
        Err(irma::Error::SessionCancelled) => d(KeyStatus::Cancelled),
        Err(irma::Error::NetworkError(_)) | Err(irma::Error::InvalidUrl(_)) => {
            Err(crate::Error::SessionNotFound)
        }
    }?;

    Ok(HttpResponse::Ok().json(kr))
}
