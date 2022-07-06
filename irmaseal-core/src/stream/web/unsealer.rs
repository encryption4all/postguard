use crate::constants::*;
use crate::header::*;
use crate::Error;
use crate::UserSecretKey;
use futures::{Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use std::convert::TryInto;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::stream::web::{aead_nonce, aesgcm::decrypt, aesgcm::get_key};

/// An unsealer is used to decrypt IRMAseal bytestreams.
pub struct Unsealer<R> {
    pub version: u16,
    pub header: Header,
    pub size_hint: (u64, Option<u64>),
    segment_size: u32,
    payload: Vec<u8>,
    r: R,
}

impl<R> Unsealer<R>
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

        if read < preamble_len || preamble[..PRELUDE_SIZE] != PRELUDE {
            return Err(JsValue::from(Error::NotIRMASEAL));
        }

        let version = u16::from_be_bytes(
            preamble[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            return Err(JsValue::from(Error::IncorrectVersion));
        }

        let header_len = u32::from_be_bytes(
            preamble[PREAMBLE_SIZE - METADATA_SIZE_SIZE..PREAMBLE_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if (header_len as usize) > MAX_METADATA_SIZE {
            return Err(JsValue::from(Error::ConstraintViolation));
        }

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

        let (_, segment_size, size_hint) = match header {
            Header {
                policies: _,
                mode:
                    Mode::Streaming {
                        segment_size,
                        size_hint,
                    },
                algo: Algorithm::Aes128Gcm { iv },
            } => (iv, segment_size, size_hint),
            _ => return Err(JsValue::from(Error::NotSupported)),
        };

        if segment_size > MAX_SYMMETRIC_CHUNK_SIZE {
            return Err(JsValue::from(Error::ConstraintViolation));
        }

        Ok(Unsealer {
            version,
            header,
            segment_size,
            size_hint,
            payload,
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
        let rec_info = self.header.policies.get(ident).unwrap();
        let ss = rec_info.derive_keys(usk)?;
        let key = get_key(&ss.0[..KEY_SIZE]).await?;

        let iv = match self.header.algo {
            Algorithm::Aes128Gcm { iv } => iv,
            _ => return Err(JsValue::from(Error::NotSupported)),
        };

        let nonce = &iv[..STREAM_NONCE_SIZE];
        let mut counter: u32 = u32::default();

        let segment_size: u32 = (self.segment_size as usize + TAG_SIZE).try_into().unwrap();

        let buf = Uint8Array::new_with_length(segment_size);
        let mut buf_tail = 0;

        loop {
            // First exhaust whatever of the payload was already read,
            // then, exhaust the rest of the stream.
            let mut array: Uint8Array = if !self.payload.is_empty() {
                let payload_len: u32 = self.payload.len().try_into().unwrap();
                let arr = Uint8Array::new_with_length(payload_len);
                arr.copy_from(&self.payload[..]);
                self.payload.clear();
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
