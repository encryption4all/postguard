use irmaseal_core::kem::{cgw_kv::CGWKV, IBKEM};
use irmaseal_core::Compress;
use irmaseal_core::Error;

use arrayref::array_ref;
use futures::Future;
use paste::paste;
use std::path::Path;

use actix_http::header::HeaderValue;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse},
};

use crate::server::POSTGUARD_CLIENTS;

pub(crate) const PG_CLIENT_HEADER: &str = "X-Postguard-Client-Version";

pub(crate) fn collect_metrics<
    B: MessageBody,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error>,
>(
    req: ServiceRequest,
    srv: &S,
) -> impl Future<Output = Result<ServiceResponse<B>, actix_web::Error>> {
    if let Some(Ok(header)) = req.headers().get(PG_CLIENT_HEADER).map(HeaderValue::to_str) {
        let split: Vec<_> = req.path().split('/').take(4).collect();
        let new_path = split.join("/");
        if let [host, host_version, app, app_version] = header.split(',').collect::<Vec<&str>>()[..]
        {
            POSTGUARD_CLIENTS
                .with_label_values(&[&new_path, host, host_version, app, app_version])
                .inc()
        }
    }

    srv.call(req)
}

pub(crate) fn client_version(req: &ServiceRequest) -> String {
    if let Some(Ok(x)) = req.headers().get(PG_CLIENT_HEADER).map(HeaderValue::to_str) {
        x.to_string()
    } else {
        String::from("unknown")
    }
}

pub fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

macro_rules! read_keypair {
    ($scheme: ident) => {
        paste! {
        pub fn [<$scheme:lower _read_pk>](path: impl AsRef<Path>) -> Result<<$scheme as IBKEM>::Pk, Error> {
            const LENGTH: usize = $scheme::PK_BYTES;

            let bytes = std::fs::read(path).unwrap();
            if bytes.len() != LENGTH {
                return Err(Error::FormatViolation);
            }

            let bytes = array_ref![&bytes, 0, LENGTH];
            open_ct(<$scheme as IBKEM>::Pk::from_bytes(bytes)).ok_or(Error::FormatViolation)
        }

        pub fn [<$scheme:lower _read_sk>](path: impl AsRef<Path>) -> Result<<$scheme as IBKEM>::Sk, Error> {
            const LENGTH: usize = $scheme::SK_BYTES;

            let bytes = std::fs::read(path).unwrap();
            if bytes.len() != LENGTH {
                return Err(Error::FormatViolation);
            }

            let bytes = array_ref![&bytes, 0, LENGTH];
            open_ct(<$scheme as IBKEM>::Sk::from_bytes(bytes)).ok_or(Error::FormatViolation)
        }
        }
    };
}

read_keypair!(CGWKV);
