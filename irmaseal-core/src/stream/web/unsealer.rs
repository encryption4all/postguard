use crate::constants::*;
use crate::metadata::*;
use crate::Error;
use crate::UserSecretKey;
use futures::{stream::iter, Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use std::convert::TryInto;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::stream::web::{aead_nonce, aesgcm::decrypt, aesgcm::get_key};

pub struct Unsealer<R> {
    pub version: u16,
    pub meta: Metadata,
    payload: Vec<u8>,
    r: R,
}

impl<R> Unsealer<R>
where
    R: Stream<Item = Result<JsValue, JsValue>> + Unpin,
{
    pub async fn new(mut r: R) -> Result<Self, JsValue> {
        let preamble_len: u32 = PREAMBLE_SIZE.try_into().unwrap();
        let mut read: u32 = 0;

        let mut preamble = Vec::new();
        let mut meta_buf = Vec::new();
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
                meta_buf.extend_from_slice(array.slice(rem, len).to_vec().as_slice());
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

        let metadata_len = u32::from_be_bytes(
            preamble[PREAMBLE_SIZE - METADATA_SIZE_SIZE..PREAMBLE_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if (metadata_len as usize) > MAX_METADATA_SIZE {
            return Err(JsValue::from(Error::ConstraintViolation));
        }

        if read > preamble_len + metadata_len {
            // We read into the payload
            payload.extend_from_slice(&meta_buf[metadata_len as usize..]);
            meta_buf.truncate(metadata_len as usize);
        } else {
            while let Some(Ok(data)) = r.next().await {
                let array: Uint8Array = data.dyn_into()?;
                let len = array.byte_length();
                let rem = preamble_len + metadata_len - read;
                read += len;

                if len < rem {
                    meta_buf.extend_from_slice(array.to_vec().as_slice());
                } else {
                    meta_buf.extend_from_slice(array.slice(0, rem).to_vec().as_slice());
                    payload.extend_from_slice(array.slice(rem, len).to_vec().as_slice());
                    break;
                }
            }
        }

        let meta = Metadata::msgpack_from(&*meta_buf)?;

        if meta.chunk_size > MAX_SYMMETRIC_CHUNK_SIZE {
            return Err(JsValue::from(Error::ConstraintViolation));
        }

        Ok(Unsealer {
            version,
            meta,
            payload,
            r,
        })
    }

    pub async fn unseal<W>(
        mut self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
        mut w: W,
    ) -> Result<(), JsValue>
    where
        W: Sink<JsValue, Error = JsValue> + Unpin,
    {
        let rec_info = self.meta.policies.get(ident).unwrap();
        let ss = rec_info.derive_keys(usk)?;
        let key = get_key(&ss.0[..KEY_SIZE]).await?;

        let nonce = &self.meta.iv[..NONCE_SIZE];
        let mut counter: u32 = u32::default();

        let chunk_size: u32 = (self.meta.chunk_size + TAG_SIZE).try_into().unwrap();

        let buf = Uint8Array::new_with_length(chunk_size);
        let mut buf_tail = 0;

        let mut stream = iter(if self.payload.is_empty() {
            vec![]
        } else {
            vec![Ok(JsValue::from(Uint8Array::from(&self.payload[..])))]
        })
        .chain(self.r);

        self.payload.clear();

        while let Some(Ok(data)) = stream.next().await {
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
