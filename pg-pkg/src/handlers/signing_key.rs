use actix_web::{web::Data, web::Json, HttpResponse};
use actix_web::{HttpMessage, HttpRequest};

use irma::SessionStatus;
use pg_core::api::{SigningKeyRequest, SigningKeyResponse};
use pg_core::artifacts::{SigningKey, SigningKeyExt};
use pg_core::ibs::gg::{keygen, SecretKey};
use pg_core::identity::{Attribute, Policy};

use crate::middleware::irma::IrmaAuthResult;
use crate::util::current_time_u64;

pub async fn signing_key(
    req: HttpRequest,
    msk: Data<SecretKey>,
    body: Json<SigningKeyRequest>,
) -> Result<HttpResponse, crate::Error> {
    let sk = msk.get_ref();
    let mut rng = rand::thread_rng();

    let IrmaAuthResult {
        con,
        status,
        proof_status,
        ..
    } = req
        .extensions()
        .get::<IrmaAuthResult>()
        .cloned()
        .ok_or(crate::Error::Unexpected)?;

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

    let pub_con = con
        .clone()
        .into_iter()
        .filter(|attr| {
            body.pub_sign_id
                .iter()
                .map(|a| a.atype.clone())
                .collect::<Vec<String>>()
                .contains(&attr.atype)
        })
        .collect();

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

    let priv_sign_key = body.priv_sign_id.as_ref().map(|priv_sign_id| {
        let priv_con = con
            .clone()
            .into_iter()
            .filter(|a| priv_sign_id.contains(&Attribute::new(&a.atype, None)))
            .collect();
        let policy = Policy {
            timestamp: iat,
            con: priv_con,
        };

        let id = policy.derive_ibs().map_err(|_e| crate::Error::Unexpected)?;
        let key = keygen(sk, &id, &mut rng);

        Ok(SigningKeyExt {
            key: SigningKey(key),
            policy,
        })
    });

    let priv_sign_key = priv_sign_key.map_or(Ok(None), |r| r.map(Some))?;

    Ok(HttpResponse::Ok().json(SigningKeyResponse {
        status,
        proof_status,
        pub_sign_key: Some(pub_sign_key),
        priv_sign_key,
    }))
}
