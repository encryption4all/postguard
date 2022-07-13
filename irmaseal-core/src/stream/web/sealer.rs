use crate::constants::*;
use crate::header::*;
use crate::Error;
use crate::{Policy, PublicKey};
use futures::{Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use wasm_bindgen::{JsCast, JsValue};

use crate::stream::web::{aead_nonce, aesgcm::encrypt, aesgcm::get_key};

#[derive(Debug, Clone)]
pub struct IRMASeal {
    /// The header of the IRMAseal packet.
    header: Header,
    /// The payload (encrypted plaintext).
    payload: Uint8Array,
}

pub async fn seal_with_array<R: RngCore + CryptoRng>(
    pk: &PublicKey<CGWKV>,
    policies: &BTreeMap<String, Policy>,
    rng: &mut R,
    input: impl AsRef<Uint8Array>,
) -> Result<IRMASeal, JsValue> {
    let (header, ss) = Header::new(pk, policies, rng)?;

    let header = header.with_mode(Mode::InMemory {
        size: input.as_ref().length(),
    });

    let key = get_key(&ss.0[..KEY_SIZE]).await?;

    let iv = match header {
        Header {
            algo: Algorithm::Aes128Gcm(iv),
            ..
        } => iv,
        _ => return Err(Error::AlgorithmNotSupported(header.algo).into()),
    };

    let payload = encrypt(&key, &iv.0, &Uint8Array::new_with_length(0), input.as_ref()).await?;

    Ok(IRMASeal { header, payload })
}

/// Seals the contents of a [`Stream<Item = Result<Uint8Array, JsValue>>`][Stream] into a [`Sink<Uint8Array, Error = JsValue>`][Sink].
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
    // TODO: use the stream size hint in the header
    let (header, ss) = Header::new(pk, policies, rng)?;
    let key = get_key(&ss.0[..KEY_SIZE]).await?;

    let (segment_size, _size_hint) = match header {
        Header {
            mode:
                Mode::Streaming {
                    segment_size,
                    size_hint,
                },
            ..
        } => (segment_size, size_hint),
        _ => return Err(Error::ModeNotSupported(header.mode).into()),
    };

    let iv = match header {
        Header {
            algo: Algorithm::Aes128Gcm(iv),
            ..
        } => iv,
        _ => return Err(Error::AlgorithmNotSupported(header.algo).into()),
    };

    let nonce = &iv.0[..STREAM_NONCE_SIZE];
    let mut counter: u32 = u32::default();

    w.feed(Uint8Array::from(&PRELUDE[..]).into()).await?;
    w.feed(Uint8Array::from(&VERSION_V2.to_be_bytes()[..]).into())
        .await?;

    let mut header_vec = Vec::with_capacity(MAX_METADATA_SIZE);
    header.msgpack_into(&mut header_vec)?;

    w.feed(
        Uint8Array::from(
            &u32::try_from(header_vec.len())
                .map_err(|_e| Error::ConstraintViolation)?
                .to_be_bytes()[..],
        )
        .into(),
    )
    .await?;

    w.feed(Uint8Array::from(&header_vec[..]).into()).await?;

    let mut buf_tail: u32 = 0;
    let buf = Uint8Array::new_with_length(segment_size);

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

                counter = counter.checked_add(1).ok_or(Error::Symmetric)?;
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
