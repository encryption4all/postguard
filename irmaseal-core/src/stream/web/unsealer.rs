use crate::constants::*;
use crate::metadata::*;
use crate::util::KeySet;
use crate::Error;
use crate::UserSecretKey;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use ibe::kem::cgw_kv::CGWKV;
use std::convert::TryInto;

use crate::stream::web::{aead_nonce, aesgcm::decrypt};

pub struct Unsealer<R> {
    pub version: u16,
    pub meta: Metadata,
    r: R,
}

impl<R> Unsealer<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn new(mut r: R) -> Result<Self, Error> {
        let mut tmp = [0u8; PREAMBLE_SIZE];
        r.read_exact(&mut tmp)
            .map_err(|_e| Error::NotIRMASEAL)
            .await?;

        if tmp[..PRELUDE_SIZE] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let version = u16::from_be_bytes(
            tmp[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            return Err(Error::IncorrectVersion);
        }

        let metadata_len = u32::from_be_bytes(
            tmp[PREAMBLE_SIZE - METADATA_SIZE_SIZE..]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        ) as usize;

        let mut meta_buf = Vec::with_capacity(PREAMBLE_SIZE + metadata_len);

        // Limit reader to not read past metadata
        let mut r = r.take(metadata_len as u64);

        r.read_to_end(&mut meta_buf)
            .map_err(|_e| Error::FormatViolation)
            .await?;

        let meta: Metadata =
            rmp_serde::from_read(&*meta_buf).map_err(|_e| Error::FormatViolation)?;

        Ok(Unsealer {
            version,
            meta,
            r: r.into_inner(), // This (new) reader is locked to the payload.
        })
    }

    pub async fn unseal<W>(
        &mut self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
        mut w: W,
    ) -> Result<(), Error>
    where
        W: AsyncWrite + Unpin,
    {
        let rec_info = self.meta.policies.get(ident).unwrap();
        let KeySet {
            aes_key,
            mac_key: _,
        } = rec_info.derive_keys(usk).unwrap();

        let nonce = &self.meta.iv[..NONCE_SIZE];
        let mut counter: u32 = u32::default();

        let bufsize: usize = self.meta.chunk_size + TAG_SIZE;
        let mut buf = vec![0; bufsize];
        let mut buf_tail = 0;

        loop {
            let read = self.r.read(&mut buf[buf_tail..bufsize]).await?;
            buf_tail += read;

            if buf_tail == bufsize {
                decrypt(&aes_key, &aead_nonce(nonce, counter, false), b"", &mut buf)
                    .await
                    .unwrap();

                w.write_all(&buf[..]).await?;
                buf_tail = 0;
                buf.resize(bufsize, 0);

                counter = counter.checked_add(1).unwrap();
            } else if read == 0 {
                buf.truncate(buf_tail);

                decrypt(&aes_key, &aead_nonce(nonce, counter, true), b"", &mut buf)
                    .await
                    .unwrap();

                w.write_all(&buf[..]).await?;

                break;
            }
        }

        Ok(())
    }
}
