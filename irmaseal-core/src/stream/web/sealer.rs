use crate::constants::*;
use crate::metadata::*;
use crate::Error;
use crate::{util::derive_keys, util::KeySet};
use crate::{Policy, PublicKey};
use futures::{Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::convert::TryInto;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::stream::web::{aead_nonce, aesgcm::encrypt, aesgcm::get_key};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

pub async fn seal<Rng, R, W>(
    pk: &PublicKey<CGWKV>,
    policies: &BTreeMap<String, Policy>,
    rng: &mut Rng,
    mut r: R,
    mut w: W,
) -> Result<(), Error>
where
    Rng: RngCore + CryptoRng,
    R: Stream<Item = Result<JsValue, JsValue>> + Unpin,
    W: Sink<JsValue> + Unpin,
{
    let (meta, ss) = Metadata::new(pk, policies, rng)?;
    let KeySet {
        aes_key,
        mac_key: _,
    } = derive_keys(&ss);

    let key = get_key(&aes_key).await.unwrap();

    let nonce = &meta.iv[..NONCE_SIZE];
    let mut counter: u32 = u32::default();

    let mut meta_vec = Vec::with_capacity(MAX_METADATA_SIZE);
    meta.msgpack_into(&mut meta_vec)?;

    w.feed(Uint8Array::from(&meta_vec[..]).into())
        .await
        .map_err(|_e| Error::ConstraintViolation)?;

    let chunk_size: u32 = meta.chunk_size.try_into().unwrap();
    let mut buf_tail: u32 = 0;
    let buf = Uint8Array::new_with_length(chunk_size);

    while let Some(Ok(data)) = r.next().await {
        let array: Uint8Array = data.dyn_into().unwrap();
        let vec = array.to_vec();
        log(&format!("encrypting: {:?} {}", vec, vec.len()));
        let len = array.byte_length();
        let rem = buf.byte_length() - buf_tail;

        if len < rem {
            buf.set(&array, buf_tail);
            buf_tail += len;
        } else {
            buf.set(&array.slice(0, rem), buf_tail);

            let ct = encrypt(
                &key,
                &aead_nonce(nonce, counter, false),
                &Uint8Array::new_with_length(0),
                &buf,
            )
            .await
            .unwrap();

            w.feed(ct.into())
                .await
                .map_err(|_e| Error::ConstraintViolation)?;

            if len > rem {
                buf.set(&array.slice(rem, len), 0)
            }

            buf_tail = len - rem;
            counter = counter.checked_add(1).unwrap();
        }
    }

    if buf_tail > 0 {
        log(&format!("encrypting: last "));
        let ct = encrypt(
            &key,
            &aead_nonce(nonce, counter, true),
            &Uint8Array::new_with_length(0),
            &buf.slice(0, buf_tail),
        )
        .await
        .unwrap();
        w.feed(ct.into())
            .await
            .map_err(|_e| Error::ConstraintViolation)?;
    }

    w.flush().await.map_err(|_e| Error::ConstraintViolation)
}
