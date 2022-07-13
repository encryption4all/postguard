mod aesgcm;
mod sealer;
mod unsealer;

#[doc(inline)]
pub use sealer::seal as web_seal;

#[doc(inline)]
pub use unsealer::Unsealer as WebUnsealer;

use crate::constants::*;
use crate::Error;
use js_sys::Error as JsError;
use wasm_bindgen::JsValue;

fn aead_nonce(nonce: &[u8], counter: u32, last_block: bool) -> [u8; STREAM_IV_SIZE] {
    let mut iv = [0u8; STREAM_IV_SIZE];

    iv[..STREAM_NONCE_SIZE].copy_from_slice(nonce);
    iv[STREAM_NONCE_SIZE..STREAM_IV_SIZE - 1].copy_from_slice(&counter.to_be_bytes());
    iv[STREAM_IV_SIZE - 1] = last_block as u8;

    iv
}

impl From<Error> for JsValue {
    fn from(err: Error) -> Self {
        JsError::new(&format!("irmaseal-core error: {err}")).into()
    }
}
