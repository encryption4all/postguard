use crate::constants::*;
use crate::metadata::*;
use crate::util::KeySet;
use crate::Error;
use crate::{PublicKey, UserSecretKey};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use ibe::kem::cgw_fo::CGWFO;
use std::convert::TryInto;

use crate::stream::web::{aead_nonce, aesgcm::decrypt};

pub struct Unsealer<R> {
    pub version: u16,
    pub meta_buf: Vec<u8>,
    pub meta: RecipientMetadata,
    r: R,
}

impl<R> Unsealer<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn new(mut r: R, id: &str) -> Result<Self, Error> {
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
        meta_buf.extend_from_slice(&tmp);

        // Limit reader to not read past metadata
        let mut r = r.take(metadata_len as u64);

        r.read_to_end(&mut meta_buf)
            .map_err(|_e| Error::FormatViolation)
            .await?;

        let recipient_meta = RecipientMetadata::msgpack_from(&*meta_buf, id)?;

        Ok(Unsealer {
            version,
            meta: recipient_meta,
            meta_buf,
            r: r.into_inner(), // This (new) reader is locked to the payload.
        })
    }

    pub async fn unseal<W>(
        &mut self,
        usk: &UserSecretKey<CGWFO>,
        mpk: &PublicKey<CGWFO>,
        mut w: W,
    ) -> Result<(), Error>
    where
        W: AsyncWrite + Unpin,
    {
        let KeySet {
            aes_key,
            mac_key: _,
        } = self.meta.derive_keys(usk, mpk).unwrap();

        let nonce = &self.meta.iv[..NONCE_SIZE];
        let mut counter: u32 = u32::default();

        let mut meta_tag = vec![0u8; TAG_SIZE];
        self.r.read_exact(&mut meta_tag).await?;

        decrypt(
            &aes_key,
            &aead_nonce(nonce, counter, false),
            &self.meta_buf[..],
            &mut meta_tag,
        )
        .await
        .unwrap();

        counter += 1;
        let bufsize: usize = self.meta.chunk_size + TAG_SIZE;
        let mut buf = vec![0; bufsize];
        let mut buf_tail = 0;

        loop {
            let read = self.r.read(&mut buf[buf_tail..bufsize]).await?;
            buf_tail += read;

            if buf_tail == bufsize {
                decrypt(&aes_key, &aead_nonce(&nonce, counter, false), b"", &mut buf)
                    .await
                    .unwrap();

                w.write_all(&buf[..]).await?;
                buf_tail = 0;
                buf.resize(bufsize, 0);
                counter += 1;
            } else if read == 0 {
                buf.truncate(buf_tail);

                decrypt(&aes_key, &aead_nonce(nonce, counter, true), b"", &mut buf)
                    .await
                    .unwrap();

                w.write_all(&buf[..]).await?;
                counter += 1;
                break;
            }
        }

        Ok(())
    }
}
