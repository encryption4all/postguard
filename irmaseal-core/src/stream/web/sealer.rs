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

use crate::stream::web::{aead_nonce, aesgcm::encrypt, aesgcm::get_key};

pub async fn seal<Rng, R, W>(
    pk: &PublicKey<CGWKV>,
    policies: &BTreeMap<String, Policy>,
    rng: &mut Rng,
    mut r: R,
    mut w: W,
) -> Result<(), Error>
where
    Rng: RngCore + CryptoRng,
    R: Stream<Item = Uint8Array> + Unpin,
    W: Sink<Uint8Array> + Unpin + 'static,
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

    w.feed(Uint8Array::from(&meta_vec[..]))
        .await
        .map_err(|_e| Error::ConstraintViolation)?;

    let chunk_size: u32 = meta.chunk_size.try_into().unwrap();
    let mut buf_tail: u32 = 0;
    let buf = Uint8Array::new_with_length(chunk_size);

    while let Some(data) = r.next().await {
        let len = data.byte_length();
        let rem = buf.byte_length() - buf_tail;

        if len < rem {
            buf.set(&data, buf_tail);
            buf_tail += len;
        } else {
            buf.set(&data.slice(0, rem), buf_tail);

            let ct = encrypt(
                &key,
                &aead_nonce(nonce, counter, false),
                &Uint8Array::new_with_length(0),
                &buf,
            )
            .await
            .unwrap();

            w.feed(ct).await.map_err(|_e| Error::ConstraintViolation)?;

            if len > rem {
                buf.set(&data.slice(rem, len), 0)
            }

            buf_tail = len - rem;

            counter = counter.checked_add(1).unwrap();
        }
    }

    let ct = encrypt(
        &key,
        &aead_nonce(nonce, counter, true),
        &Uint8Array::new_with_length(0),
        &buf.slice(0, buf_tail),
    )
    .await
    .unwrap();

    w.send(ct).await.map_err(|_e| Error::ConstraintViolation)?;

    Ok(())
}
