use actix_web::{web::Data, web::Json, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use irma::SessionStatus;
use pg_core::api::{SigningKeyRequest, SigningKeyResponse};
use pg_core::artifacts::{SigningKey, SigningKeyExt};
use pg_core::ibs::gg::{keygen, SecretKey};
use pg_core::identity::{Attribute, Policy};

use crate::middleware::auth::{ApiKeySigningInfo, AuthResult};
use crate::util::current_time_u64;

pub async fn signing_key(
    req: HttpRequest,
    msk: Data<SecretKey>,
    body: Json<SigningKeyRequest>,
) -> Result<HttpResponse, crate::Error> {
    let sk = msk.get_ref();
    let mut rng = rand::thread_rng();

    let AuthResult {
        con,
        status,
        proof_status,
        ..
    } = req
        .extensions()
        .get::<AuthResult>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

    // If present, the API key flow determined the pub/priv split server-side.
    let api_key_info = req.extensions().get::<ApiKeySigningInfo>().cloned();

    req.extensions_mut().clear();

    // The PKG gets to decide the timestamp in the policy.
    let iat = current_time_u64()?;
    let body = body.into_inner();

    match status {
        SessionStatus::Done => (),
        _ => {
            return Ok(HttpResponse::Ok().json(SigningKeyResponse {
                status,
                proof_status,
                pub_sign_key: None,
                priv_sign_key: None,
            }))
        }
    }

    // Determine public and private attributes:
    // - API key auth: use the server-side split from the database configuration.
    // - JWT/IRMA auth: use the client-provided SigningKeyRequest body.
    let (pub_con, priv_con): (Vec<Attribute>, Option<Vec<Attribute>>) =
        if let Some(info) = api_key_info {
            let priv_attrs = if info.priv_attributes.is_empty() {
                None
            } else {
                Some(info.priv_attributes)
            };
            (info.pub_attributes, priv_attrs)
        } else {
            let pub_con = con
                .clone()
                .into_iter()
                .filter(|attr| body.pub_sign_id.iter().any(|a| a.atype == attr.atype))
                .collect();

            let priv_con = body.priv_sign_id.as_ref().map(|priv_sign_id| {
                con.into_iter()
                    .filter(|a| priv_sign_id.contains(&Attribute::new(&a.atype, None)))
                    .collect()
            });

            (pub_con, priv_con)
        };

    let policy = Policy {
        timestamp: iat,
        con: pub_con,
    };
    let id = policy.derive_ibs().map_err(|_e| crate::Error::Unexpected)?;
    let key = keygen(sk, &id, &mut rng);

    let pub_sign_key = SigningKeyExt {
        key: SigningKey(key),
        policy,
    };

    let priv_sign_key = priv_con
        .map(|priv_attrs| {
            let policy = Policy {
                timestamp: iat,
                con: priv_attrs,
            };

            let id = policy.derive_ibs().map_err(|_e| crate::Error::Unexpected)?;
            let key = keygen(sk, &id, &mut rng);

            Ok(SigningKeyExt {
                key: SigningKey(key),
                policy,
            })
        })
        .map_or(Ok(None), |r| r.map(Some))?;

    Ok(HttpResponse::Ok().json(SigningKeyResponse {
        status,
        proof_status,
        pub_sign_key: Some(pub_sign_key),
        priv_sign_key,
    }))
}
