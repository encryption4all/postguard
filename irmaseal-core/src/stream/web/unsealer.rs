use crate::constants::*;
use crate::metadata::*;
use crate::util::KeySet;
use crate::Error;
use crate::UserSecretKey;
use futures::{Sink, SinkExt, Stream, StreamExt};
use ibe::kem::cgw_kv::CGWKV;
use js_sys::Uint8Array;
use std::convert::TryInto;

use crate::stream::web::{aead_nonce, aesgcm::decrypt, aesgcm::get_key};

pub struct Unsealer<R> {
    pub version: u16,
    pub meta: Metadata,
    spill: Vec<u8>, // payload spilled
    r: R,
}

impl<R> Unsealer<R>
where
    R: Stream<Item = Uint8Array> + Unpin,
{
    pub async fn new(mut r: R) -> Result<Self, Error> {
        let preamble_size: u32 = PREAMBLE_SIZE.try_into().unwrap();
        let tmp = Uint8Array::new_with_length(preamble_size);
        let mut read: u32 = 0;

        let mut meta_buf = Vec::new();

        while let (Some(data), true) = (r.next().await, read < preamble_size) {
            let len = data.byte_length();
            let rem = preamble_size - read;

            if len < rem {
                tmp.set(&data, read);
                read += len;
            } else {
                tmp.set(&data.slice(0, rem), read);
                meta_buf.extend_from_slice(data.slice(rem, len).to_vec().as_slice());
            }
        }

        let preamble = tmp.to_vec();

        if read < preamble_size || preamble[..PRELUDE_SIZE] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let version = u16::from_be_bytes(
            preamble[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            return Err(Error::IncorrectVersion);
        }

        let metadata_len = u32::from_be_bytes(
            preamble[PREAMBLE_SIZE - METADATA_SIZE_SIZE..]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if (metadata_len as usize) > MAX_METADATA_SIZE {
            return Err(Error::ConstraintViolation);
        }

        meta_buf.reserve_exact((metadata_len as usize) - meta_buf.len());
        read = meta_buf.len().try_into().unwrap();

        let mut spill = Vec::new();

        while let (Some(data), true) = (r.next().await, read < metadata_len) {
            let len = data.byte_length();
            let rem = metadata_len - read;

            if len < rem {
                meta_buf.extend_from_slice(data.to_vec().as_slice());
                read += len;
            } else {
                meta_buf.extend_from_slice(data.to_vec().as_slice());
                spill.extend_from_slice(data.slice(rem, len).to_vec().as_slice());
            }
        }

        let meta: Metadata =
            rmp_serde::from_read(&*meta_buf).map_err(|_e| Error::FormatViolation)?;

        if meta.chunk_size > MAX_SYMMETRIC_CHUNK_SIZE {
            return Err(Error::ConstraintViolation);
        }

        Ok(Unsealer {
            version,
            meta,
            spill,
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
        W: Sink<Uint8Array> + Unpin,
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
        let buf = Uint8Array::new_with_length(chunk_size);
        buf.copy_from(&self.spill);
        let mut buf_tail: u32 = self.spill.len().try_into().unwrap();

        while let Some(data) = self.r.next().await {
            let len = data.byte_length();
            let rem = buf.byte_length() - buf_tail;

            if len < rem {
                buf.set(&data, buf_tail);
                buf_tail += len;
            } else {
                buf.set(&data.slice(0, rem), buf_tail);

                let plain = decrypt(
                    &key,
                    &aead_nonce(nonce, counter, false),
                    &Uint8Array::new_with_length(0),
                    &buf,
                )
                .await
                .unwrap();

                w.feed(plain)
                    .await
                    .map_err(|_e| Error::ConstraintViolation)?;

                if len > rem {
                    buf.set(&data.slice(rem, len), 0)
                }

                buf_tail = len - rem;

                counter = counter.checked_add(1).unwrap();
            }
        }

        let plain = decrypt(
            &key,
            &aead_nonce(nonce, counter, true),
            &Uint8Array::new_with_length(0),
            &buf.slice(0, buf_tail),
        )
        .await
        .unwrap();

        w.send(plain)
            .await
            .map_err(|_e| Error::ConstraintViolation)?;

        Ok(())
    }
}
