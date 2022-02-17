pub mod aesgcm;
pub mod sealer;
pub mod unsealer;

use crate::constants::*;
use crate::Error;
use js_sys::Error as JsError;
use wasm_bindgen::JsValue;

fn aead_nonce(nonce: &[u8], counter: u32, last_block: bool) -> [u8; STREAM_IV_SIZE] {
    let mut iv = [0u8; STREAM_IV_SIZE];

    iv[..NONCE_SIZE].copy_from_slice(nonce);
    iv[NONCE_SIZE..STREAM_IV_SIZE - 1].copy_from_slice(&counter.to_be_bytes());
    iv[STREAM_IV_SIZE - 1] = last_block as u8;

    iv
}

impl From<Error> for JsValue {
    fn from(err: Error) -> Self {
        match err {
            Error::NotIRMASEAL => JsError::new("Not IRMASEAL"),
            Error::IncorrectVersion => JsError::new("Incorrect version"),
            Error::ConstraintViolation => JsError::new("Constraint violation"),
            Error::FormatViolation => JsError::new("Format violation"),
            Error::KeyError => JsError::new("Wrong symmetric key size"),
            Error::IncorrectTag => JsError::new("Incorrect tag"),
            Error::StdIO(x) => JsError::new(&format!("IO error: {x}")),
            Error::FuturesIO(x) => JsError::new(&format!("IO error: {x}")),
            Error::Kem(_) => JsError::new("KEM failure"),
        }
        .into()
    }
}
