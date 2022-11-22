//! Streaming mode.

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::consts::*;
use crate::error::Error;
use crate::header::*;
use crate::identity::Policy;
use crate::util::preamble_checked;
use crate::web::aesgcm::{decrypt, encrypt, get_key};
use crate::{SealConfig, Sealer, UnsealConfig, Unsealer};
use futures::{Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use wasm_bindgen::{JsCast, JsValue};

struct UnsealerConfig {
    size_hint: (u64, Option<u64>),
    segment_size: u32,
    payload: Vec<u8>,
}

impl UnsealConfig for UnsealerConfig {}

// Nonce generation as defined in the STREAM construction.
fn aead_nonce(nonce: &[u8], counter: u32, last_block: bool) -> [u8; STREAM_IV_SIZE] {
    let mut iv = [0u8; STREAM_IV_SIZE];

    iv[..STREAM_NONCE_SIZE].copy_from_slice(nonce);
    iv[STREAM_NONCE_SIZE..STREAM_IV_SIZE - 1].copy_from_slice(&counter.to_be_bytes());
    iv[STREAM_IV_SIZE - 1] = last_block as u8;

    iv
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
    let size_hint = r.size_hint();
    let new_hint = (size_hint.0 as u64, size_hint.1.map(|x| x as u64));
    let segment_size = SYMMETRIC_CRYPTO_DEFAULT_CHUNK;

    let (header, ss) = Header::new(pk, policies, rng)?;
    let header = header.with_mode(Mode::Streaming {
        segment_size,
        size_hint: new_hint,
    });

    let key = get_key(&ss.0[..KEY_SIZE]).await?;

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

    let mut header_vec = Vec::with_capacity(MAX_HEADER_SIZE);
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

impl<R> Unsealer<R, UnsealerConfig>
where
    R: Stream<Item = Result<JsValue, JsValue>> + Unpin,
{
    /// Create a new [`Unsealer`] that starts reading from a [`Stream<Item = Result<Uint8Array, JsValue>>`][Stream].
    ///
    /// Errors if the bytestream is not a legitimate IRMAseal bytestream.
    pub async fn new(mut r: R) -> Result<Self, JsValue> {
        let preamble_len: u32 = PREAMBLE_SIZE.try_into().unwrap();
        let mut read: u32 = 0;

        let mut preamble = Vec::new();
        let mut header_buf = Vec::new();
        let mut payload = Vec::new();

        while let Some(Ok(data)) = r.next().await {
            let array: Uint8Array = data.dyn_into()?;
            let len = array.byte_length();
            let rem = preamble_len - read;
            read += len;

            if len < rem {
                preamble.extend_from_slice(array.to_vec().as_slice());
            } else {
                preamble.extend_from_slice(array.slice(0, rem).to_vec().as_slice());
                header_buf.extend_from_slice(array.slice(rem, len).to_vec().as_slice());
                break;
            }
        }

        if read < preamble_len {
            return Err(JsValue::from(Error::NotIRMASEAL));
        }

        let (version, header_len) = preamble_checked(&preamble[..PREAMBLE_SIZE])?;
        let header_len = u32::try_from(header_len).unwrap();

        if read > preamble_len + header_len {
            // We read into the payload
            payload.extend_from_slice(&header_buf[header_len as usize..]);
            header_buf.truncate(header_len as usize);
        } else {
            while let Some(Ok(data)) = r.next().await {
                let array: Uint8Array = data.dyn_into()?;
                let len = array.byte_length();
                let rem = preamble_len + header_len - read;
                read += len;

                if len < rem {
                    header_buf.extend_from_slice(array.to_vec().as_slice());
                } else {
                    header_buf.extend_from_slice(array.slice(0, rem).to_vec().as_slice());
                    payload.extend_from_slice(array.slice(rem, len).to_vec().as_slice());
                    break;
                }
            }
        }

        let header = Header::msgpack_from(&*header_buf)?;

        let (segment_size, size_hint) = match header {
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

        match header {
            Header {
                algo: Algorithm::Aes128Gcm(_),
                ..
            } => (),
            _ => return Err(Error::AlgorithmNotSupported(header.algo).into()),
        };

        if segment_size > MAX_SYMMETRIC_CHUNK_SIZE {
            return Err(JsValue::from(Error::ConstraintViolation));
        }

        Ok(Unsealer {
            version,
            header,
            config: UnsealerConfig {
                payload,
                segment_size,
                size_hint,
            },
            r,
        })
    }

    /// Unseal the remaining data (which is now only payload) into an [`Sink<Uint8Array, Error = JsValue>`][Sink].
    pub async fn unseal<W>(
        &mut self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
        mut w: W,
    ) -> Result<(), JsValue>
    where
        W: Sink<JsValue, Error = JsValue> + Unpin,
    {
        let rec_info = self
            .header
            .policies
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.derive_keys(usk)?;
        let key = get_key(&ss.0[..KEY_SIZE]).await?;

        let iv = match self.header.algo {
            Algorithm::Aes128Gcm(iv) => iv,
            _ => return Err(Error::AlgorithmNotSupported(self.header.algo).into()),
        };

        let nonce = &iv.0[..STREAM_NONCE_SIZE];
        let mut counter: u32 = u32::default();

        let segment_size: u32 = (self.config.segment_size as usize + TAG_SIZE)
            .try_into()
            .unwrap();

        let buf = Uint8Array::new_with_length(segment_size);
        let mut buf_tail = 0;

        let mut payload = self.config.payload.clone();

        loop {
            // First exhaust whatever of the payload was already read,
            // then, exhaust the rest of the stream.
            let mut array: Uint8Array = if !payload.is_empty() {
                let payload_len: u32 = payload.len().try_into().unwrap();
                let arr = Uint8Array::new_with_length(payload_len);
                arr.copy_from(&payload[..]);
                payload.clear();
                arr
            } else if let Some(Ok(data)) = self.r.next().await {
                data.dyn_into()?
            } else {
                break;
            };

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

                    let plain = decrypt(
                        &key,
                        &aead_nonce(nonce, counter, false),
                        &Uint8Array::new_with_length(0),
                        &buf,
                    )
                    .await?;

                    w.feed(plain.into()).await?;

                    counter = counter.checked_add(1).unwrap();
                    buf_tail = 0;
                }
            }
        }

        let final_plain = decrypt(
            &key,
            &aead_nonce(nonce, counter, true),
            &Uint8Array::new_with_length(0),
            &buf.slice(0, buf_tail),
        )
        .await?;

        w.feed(final_plain.into()).await?;

        w.flush().await?;
        w.close().await
    }
}
