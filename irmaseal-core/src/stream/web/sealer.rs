use crate::constants::*;
use crate::metadata::*;
use crate::Error;
use crate::{Policy, PublicKey};
use futures::{Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use wasm_bindgen::{JsCast, JsValue};

use crate::stream::web::{aead_nonce, aesgcm::encrypt, aesgcm::get_key};

pub async fn seal<Rng, R, W>(
    pk: &PublicKey<CGWKV>,
    policies: &BTreeMap<String, Policy>,
    rng: &mut Rng,
    mut r: R,
    mut w: W,
) -> Result<(), JsValue>
where
    Rng: RngCore + CryptoRng,
    R: Stream<Item = Result<JsValue, JsValue>> + Unpin,
    W: Sink<JsValue, Error = JsValue> + Unpin,
{
    let (meta, ss) = Metadata::new(pk, policies, rng)?;
    let key = get_key(&ss.0[..KEY_SIZE]).await?;

    let nonce = &meta.iv[..NONCE_SIZE];
    let mut counter: u32 = u32::default();

    w.feed(Uint8Array::from(&PRELUDE[..]).into()).await?;
    w.feed(Uint8Array::from(&VERSION_V2.to_be_bytes()[..]).into())
        .await?;

    let mut meta_vec = Vec::with_capacity(MAX_METADATA_SIZE);
    meta.msgpack_into(&mut meta_vec)?;

    w.feed(
        Uint8Array::from(
            &u32::try_from(meta_vec.len())
                .map_err(|_e| Error::ConstraintViolation)?
                .to_be_bytes()[..],
        )
        .into(),
    )
    .await?;

    w.feed(Uint8Array::from(&meta_vec[..]).into()).await?;

    let chunk_size: u32 = meta.chunk_size.try_into().unwrap();
    let mut buf_tail: u32 = 0;
    let buf = Uint8Array::new_with_length(chunk_size);

    while let Some(Ok(data)) = r.next().await {
        let mut array: Uint8Array = data.dyn_into()?;

        while array.byte_length() != 0 {
            let len = array.byte_length();
            let rem = buf.byte_length() - buf_tail;

            if len < rem {
                buf.set(&array, buf_tail);
                array = Uint8Array::new_with_length(0);
                buf_tail += len;
            } else {
                buf.set(&array.slice(0, rem), buf_tail);
                array = array.slice(rem, len);

                let ct = encrypt(
                    &key,
                    &aead_nonce(nonce, counter, false),
                    &Uint8Array::new_with_length(0),
                    &buf,
                )
                .await?;

                w.feed(ct.into()).await?;

                counter = counter.checked_add(1).unwrap();
                buf_tail = 0;
            }
        }
    }

    let final_ct = encrypt(
        &key,
        &aead_nonce(nonce, counter, true),
        &Uint8Array::new_with_length(0),
        &buf.slice(0, buf_tail),
    )
    .await?;

    w.feed(final_ct.into()).await?;

    w.flush().await?;
    w.close().await
}
