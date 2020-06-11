use actix_web::web::{Data, HttpResponse, Path};
use futures::future::{ok, Future};
use irmaseal_core::api::{KeyResponse, KeyStatus};
use irmaseal_core::Identity;

use irma::client::Client;
use irma::session::*;

use crate::server::AppState;
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

pub fn request_fetch(
    state: Data<AppState>,
    path: Path<(String, u64)>,
) -> impl Future<Item = HttpResponse, Error = crate::Error> {
    let (token, timestamp) = path.into_inner();

    let AppState {
        pk,
        sk,
        irma_server_host,
    } = state.get_ref().clone();

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
            let client = Client::new(irma_server_host).unwrap();
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
                        let mut rng = rand::thread_rng();
                        let usk =
                            ibe::kiltz_vahlis_one::extract_usk(&pk, &sk, &i.derive(), &mut rng);

                        KeyResponse {
                            status: KeyStatus::DoneValid,
                            key: Some(usk.into()),
                        }
                    }
                    None => d(KeyStatus::DoneInvalid),
                },
            };

            Ok(HttpResponse::Ok().header("Access-Control-Allow-Origin", "*").json(result))
        })
}
