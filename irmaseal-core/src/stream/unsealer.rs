use crate::metadata::*;
use crate::*;
use crate::{stream::*, util::KeySet};
use aes::Aes128;
use ctr::cipher::{NewCipher, StreamCipher};
use ctr::Ctr64BE;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use ibe::kem::cgw_fo::CGWFO;
use std::convert::TryInto;
use tiny_keccak::{Hasher, Kmac};

pub struct Unsealer<R: AsyncRead + Unpin> {
    meta_buf: Vec<u8>,
    meta: RecipientMetadata,
    r: R,
}

impl<R> Unsealer<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn new(mut r: R, id: &RecipientIdentifier) -> Result<Self, Error> {
        let mut tmp = [0u8; PREAMBLE_SIZE];
        r.read_exact(&mut tmp)
            .map_err(|_e| Error::NotIRMASEAL)
            .await?;

        if tmp[..PRELUDE_SIZE] != PRELUDE {
            Err(Error::NotIRMASEAL)?
        }

        let version = u16::from_be_bytes(
            tmp[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            Err(Error::VersionError)?
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

        let recipient_meta =
            RecipientMetadata::msgpack_from(&*meta_buf, id).map_err(|_e| Error::FormatViolation)?;

        Ok(Unsealer {
            meta: recipient_meta,
            meta_buf,
            r: r.into_inner(), // This (new) reader is locked to the payload.
        })
    }

    pub async fn unseal<W>(
        self,
        usk: &UserSecretKey<CGWFO>,
        mpk: &PublicKey<CGWFO>,
        w: W,
    ) -> Result<(), Error>
    where
        W: AsyncWrite + Unpin,
    {
        self.generic_unseal::<W, Ctr64BE<Aes128>, Kmac>(usk, mpk, w)
            .await
    }

    /// This function is generic over streamciphers and MACs.
    async fn generic_unseal<W, Sym, Mac>(
        mut self,
        usk: &UserSecretKey<CGWFO>,
        mpk: &PublicKey<CGWFO>,
        mut w: W,
    ) -> Result<(), Error>
    where
        Sym: NewCipher + StreamCipher,
        Mac: NewMac + Hasher,
        W: AsyncWrite + Unpin,
    {
        let KeySet { aes_key, mac_key } = self.meta.derive_keys(usk, mpk).unwrap();

        let mut dec =
            Sym::new_from_slices(&aes_key, &self.meta.iv).map_err(|_err| Error::FormatViolation)?;
        let mut mac = Mac::new_with_key(&mac_key);

        mac.update(&self.meta_buf);

        let bufsize: usize = self.meta.chunk_size + TAG_SIZE;
        let mut buf = vec![0u8; bufsize];

        // The input buffer must at least contain enough bytes for a MAC to be included.
        self.r
            .read_exact(&mut buf[..TAG_SIZE])
            .map_err(|_err| Error::FormatViolation)
            .await?;

        let mut buf_tail = TAG_SIZE;
        loop {
            let input_length = self
                .r
                .read(&mut buf[buf_tail..])
                .map_err(|_err| Error::FormatViolation)
                .await?;
            buf_tail += input_length;

            // Start encrypting when our buffer is full or when the input stream
            // is exhausted and we still have data left to decrypt.
            if buf_tail == bufsize || input_length == 0 && buf_tail > TAG_SIZE {
                let mut block = &mut buf[0..buf_tail - TAG_SIZE];

                // Mac-then-decrypt
                mac.update(&mut block);
                dec.apply_keystream(&mut block);

                w.write_all(&mut block)
                    .map_err(|_err| Error::FormatViolation)
                    .await?;

                // Make sure potential tag is shifted to the front of the array.
                let mut tmp = [0u8; TAG_SIZE];
                tmp.copy_from_slice(&buf[buf_tail - TAG_SIZE..buf_tail]);
                buf[..TAG_SIZE].copy_from_slice(&tmp);

                buf_tail = TAG_SIZE;
            }

            if input_length == 0 {
                break;
            }
        }

        let mut computed_tag = [0u8; TAG_SIZE];
        mac.finalize(&mut computed_tag);

        let found_tag = &buf[..TAG_SIZE];
        (computed_tag == found_tag)
            .then(|| ())
            .ok_or(Error::FormatViolation)
    }
}
