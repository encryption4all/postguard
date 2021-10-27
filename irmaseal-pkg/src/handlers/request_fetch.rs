use actix_web::web::{Data, HttpResponse, Path};
use actix_web::Responder;
use futures::future::{ok, ready, Future, Ready};
use ibe::kem::IBKEM;
use irmaseal_core::api::{KeyResponse, KeyStatus};
use irmaseal_core::{Identity, UserSecretKey};

use irma::client::Client;
use irma::session::*;

use crate::server::MasterKeyPair;
use crate::Error;

/// Fetch identity iff valid, or else yield nothing.
fn fetch_identity(
    timestamp: u64,
    disclosed: &Option<Vec<Vec<DisclosedAttribute>>>,
) -> Option<Identity> {
    let disclosed = disclosed.as_ref()?;
    let disclosed = if disclosed.len() == 1 && disclosed[0].len() == 1 {
        &disclosed[0][0]
    } else {
        return None;
    };

    if disclosed.status != AttributeProofStatus::Present {
        return None;
    }

    let v = disclosed.rawvalue.as_ref()?;

    Identity::new(timestamp, &disclosed.id, Some(&v)).ok()
}

struct WrappedUserSecretKey<K: IBKEM>(UserSecretKey<K>);

impl<K: IBKEM> Responder for WrappedUserSecretKey<K> {
    type Error = crate::Error;
    type Future = Ready<Result<HttpResponse, crate::Error>>;

    fn respond_to(self, req: &actix_web::HttpRequest) -> Self::Future {
        ready(Ok(HttpResponse::Ok().json(self.0)))
    }
}

pub fn request_fetch<K: IBKEM>(
    state: Data<(String, MasterKeyPair<K>)>,
    path: Path<(String, u64)>,
) -> impl Responder {
    let (token, timestamp) = path.into_inner();
    let (irma_url, mpk) = state.get_ref().clone();

    ok(())
        .and_then(move |_| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if timestamp > now {
                Err(Error::ChronologyError)
            } else {
                Ok(())
            }
        })
        .and_then(move |_| {
            let client = Client::new(irma_url.to_string()).unwrap();
            client
                .result(&SessionToken(token))
                .map_err(|e| match e.status() {
                    Some(irma::client::StatusCode::BAD_REQUEST) => crate::Error::SessionNotFound,
                    _ => crate::Error::UpstreamError,
                })
        })
        .and_then(move |r: SessionResult| {
            let d = |status: KeyStatus| KeyResponse { status, key: None };

            let result = match r.status {
                SessionStatus::Initialized => d(KeyStatus::Initialized),
                SessionStatus::Connected => d(KeyStatus::Connected),
                SessionStatus::Cancelled => d(KeyStatus::Cancelled),
                SessionStatus::Timeout => d(KeyStatus::Timeout),
                SessionStatus::Done => match fetch_identity(timestamp, &r.disclosed) {
                    Some(i) => {
                        let k = i.derive::<K>().map_err(|_e| crate::Error::Unexpected)?;
                        let mut rng = rand::thread_rng();
                        let usk = K::extract_usk(Some(&mpk.pk), &mpk.sk, &k, &mut rng);

                        KeyResponse {
                            status: KeyStatus::DoneValid,
                            key: Some(UserSecretKey::<K>(usk)),
                        }
                    }
                    None => d(KeyStatus::DoneInvalid),
                },
            };

            Ok(HttpResponse::Ok().json(result))
        })
}
