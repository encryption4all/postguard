use crate::constants::*;
use crate::metadata::*;
use crate::util::KeySet;
use crate::Error;
use crate::UserSecretKey;
use futures::{Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use std::convert::TryInto;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;

use crate::stream::web::{aead_nonce, aesgcm::decrypt, aesgcm::get_key};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

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
    pub async fn new(mut r: R) -> Result<Self, Error> {
        let preamble_size: u32 = PREAMBLE_SIZE.try_into().unwrap();
        let mut read: u32 = 0;
        let mut preamble = Vec::new();
        let mut meta_buf = Vec::new();
        let mut payload = Vec::new();

        while let (Some(Ok(data)), true) = (r.next().await, read < preamble_size) {
            let array: Uint8Array = data.dyn_into().unwrap();
            let len = array.byte_length();
            let rem = preamble_size - read;

            if len < rem {
                preamble.extend_from_slice(array.to_vec().as_slice());
            } else {
                preamble.extend_from_slice(array.slice(0, rem).to_vec().as_slice());
                meta_buf.extend_from_slice(array.slice(rem, len).to_vec().as_slice());
            }
            read += len;
        }

        if read < preamble_size || preamble[..PRELUDE_SIZE] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        log(&format!("got the preamble, after reading {} bytes", read));
        log(&format!("meta_buf: {:?}", meta_buf));

        let version = u16::from_be_bytes(
            preamble[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            return Err(Error::IncorrectVersion);
        }

        let metadata_len = u32::from_be_bytes(
            preamble[6..10]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if (metadata_len as usize) > MAX_METADATA_SIZE {
            return Err(Error::ConstraintViolation);
        }

        log(&format!("retrieved meta len: {}", metadata_len));

        if read > preamble_size + metadata_len {
            log("whoops, read into the payload");
            payload.extend_from_slice(&meta_buf[metadata_len as usize..]);
            meta_buf.truncate(metadata_len as usize);
        }

        while let (Some(Ok(data)), true) = (r.next().await, read < preamble_size + metadata_len) {
            let array: Uint8Array = data.dyn_into().unwrap();
            let len = array.byte_length();
            let rem = preamble_size + metadata_len - read;

            log(&format!("len: {len}, rem: {rem}"));

            if len < rem {
                meta_buf.extend_from_slice(array.to_vec().as_slice());
            } else {
                meta_buf.extend_from_slice(array.slice(0, rem).to_vec().as_slice());
                payload.extend_from_slice(array.slice(rem, len).to_vec().as_slice());
            }
            read += len;
        }

        let meta: Metadata =
            rmp_serde::from_read(&*meta_buf).map_err(|_e| Error::FormatViolation)?;

        log(&format!("metadata: {:?}", meta));

        if meta.chunk_size > MAX_SYMMETRIC_CHUNK_SIZE {
            return Err(Error::ConstraintViolation);
        }

        log(&format!("start done, payload: {:?}", payload));
        log(&format!("total read: {}", read));

        Ok(Unsealer {
            version,
            meta,
            payload,
            r,
        })
    }

    pub async fn unseal<W>(
        &mut self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
        mut w: W,
    ) -> Result<(), Error>
    where
        W: Sink<JsValue> + Unpin,
    {
        let rec_info = self.meta.policies.get(ident).unwrap();
        let KeySet {
            aes_key,
            mac_key: _,
        } = rec_info.derive_keys(usk).unwrap();

        let key = get_key(&aes_key).await.unwrap();

        let nonce = &self.meta.iv[..NONCE_SIZE];
        let mut counter: u32 = u32::default();

        let chunk_size: u32 = (self.meta.chunk_size + TAG_SIZE).try_into().unwrap();
        log(&format!("chunk_size: {chunk_size}"));
        let buf = Uint8Array::new_with_length(chunk_size);
        let mut buf_tail = 0;
        if !self.payload.is_empty() {
            buf.set(&Uint8Array::from(&self.payload[..]), 0);
            buf_tail = self.payload.len().try_into().unwrap();
        }
        log("leggo");

        while let Some(Ok(data)) = self.r.next().await {
            log("leggo, got data");
            let array: Uint8Array = data.dyn_into().unwrap();

            let vec1 = array.to_vec();
            log(&format!("extra data: {vec1:?}"));

            let len = array.byte_length();
            let rem = buf.byte_length() - buf_tail;

            if len < rem {
                buf.set(&array, buf_tail);
                buf_tail += len;
            } else {
                buf.set(&array.slice(0, rem), buf_tail);

                let plain = decrypt(
                    &key,
                    &aead_nonce(nonce, counter, false),
                    &Uint8Array::new_with_length(0),
                    &buf,
                )
                .await
                .unwrap();

                w.feed(plain.into())
                    .await
                    .map_err(|_e| Error::ConstraintViolation)?;

                if len > rem {
                    buf.set(&array.slice(rem, len), 0)
                }

                buf_tail = len - rem;
                counter = counter.checked_add(1).unwrap();
            }
        }
        log(&format!("no more data, buf tail = {}", buf_tail));

        if buf_tail > 0 {
            log(&format!("got some remainder: {buf_tail}"));
            let plain = decrypt(
                &key,
                &aead_nonce(nonce, counter, true),
                &Uint8Array::new_with_length(0),
                &buf.slice(0, buf_tail),
            )
            .await
            .unwrap();

            w.feed(plain.into())
                .await
                .map_err(|_e| Error::ConstraintViolation)?;
        }

        w.flush().await.map_err(|_e| Error::ConstraintViolation)
    }
}
