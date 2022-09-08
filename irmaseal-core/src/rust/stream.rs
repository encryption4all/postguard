//! Streaming mode.
use crate::artifacts::PublicKey;
use crate::consts::*;
use crate::error::Error;
use crate::header::*;
use crate::identity::Policy;
use crate::UserSecretKey;
use aead::stream::DecryptorBE32;
use aead::stream::EncryptorBE32;
use aes_gcm::{Aes128Gcm, NewAead};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use ibe::kem::cgw_kv::CGWKV;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

pub use crate::stream::Unsealer;

/// Seals the contents of an [`AsyncRead`] into an [`AsyncWrite`].
pub async fn seal<Rng, R, W>(
    pk: &PublicKey<CGWKV>,
    policies: &BTreeMap<String, Policy>,
    rng: &mut Rng,
    mut r: R,
    mut w: W,
) -> Result<(), Error>
where
    Rng: RngCore + CryptoRng,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (header, ss) = Header::new(pk, policies, rng)?;
    let key = &ss.0[..KEY_SIZE];

    let segment_size = match header {
        Header {
            mode: Mode::Streaming { segment_size, .. },
            ..
        } => segment_size,
        _ => return Err(Error::ModeNotSupported(header.mode)),
    };

    let iv = match header {
        Header {
            algo: Algorithm::Aes128Gcm(iv),
            ..
        } => iv,
        _ => return Err(Error::AlgorithmNotSupported(header.algo)),
    };

    let aead = Aes128Gcm::new_from_slice(key).map_err(|_e| Error::KeyError)?;
    let nonce = &iv.0[..STREAM_NONCE_SIZE];

    let mut enc = EncryptorBE32::from_aead(aead, nonce.into());

    w.write_all(&PRELUDE).await?;
    w.write_all(&VERSION_V2.to_be_bytes()).await?;

    let mut header_vec = Vec::with_capacity(MAX_HEADER_SIZE);
    header.msgpack_into(&mut header_vec)?;

    w.write_all(
        &u32::try_from(header_vec.len())
            .map_err(|_e| Error::ConstraintViolation)?
            .to_be_bytes(),
    )
    .await?;

    w.write_all(&header_vec[..]).await?;

    let mut buf = vec![0; segment_size as usize];
    let mut buf_tail: usize = 0;

    buf.reserve(TAG_SIZE);

    loop {
        let read = r.read(&mut buf[buf_tail..segment_size as usize]).await?;
        buf_tail += read;

        if buf_tail == segment_size as usize {
            buf.truncate(buf_tail);
            enc.encrypt_next_in_place(b"", &mut buf)
                .map_err(|_e| Error::Symmetric)?;
            w.write_all(&buf[..]).await?;
            buf_tail = 0;
        } else if read == 0 {
            buf.truncate(buf_tail);
            enc.encrypt_last_in_place(b"", &mut buf)
                .map_err(|_e| Error::Symmetric)?;
            w.write_all(&buf[..]).await?;
            break;
        }
    }

    w.close().await?;
    Ok(())
}

impl<R> Unsealer<R>
where
    R: AsyncRead + Unpin,
{
    /// Create a new [`Unsealer`] that starts reading from an [`AsyncRead`].
    ///
    /// Errors if the bytestream is not a legitimate IRMAseal bytestream.
    pub async fn new(mut r: R) -> Result<Self, Error> {
        let mut tmp = [0u8; PREAMBLE_SIZE];
        r.read_exact(&mut tmp)
            .map_err(|_e| Error::NotIRMASEAL)
            .await?;

        // TODO: dedupe
        if tmp[..PRELUDE_SIZE] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let version = u16::from_be_bytes(
            tmp[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation(String::from("version")))?,
        );

        if version != VERSION_V2 {
            return Err(Error::IncorrectVersion {
                expected: VERSION_V2,
                found: version,
            });
        }

        let header_len = u32::from_be_bytes(
            tmp[PREAMBLE_SIZE - HEADER_SIZE_SIZE..]
                .try_into()
                .map_err(|_e| Error::FormatViolation(String::from("header length")))?,
        ) as usize;

        if header_len > MAX_HEADER_SIZE {
            return Err(Error::ConstraintViolation);
        }

        //
        let mut header_buf = Vec::with_capacity(header_len);

        // Limit reader to not read past header
        let mut r = r.take(header_len as u64);

        r.read_to_end(&mut header_buf)
            .map_err(|_e| Error::ConstraintViolation)
            .await?;

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
            _ => return Err(Error::ModeNotSupported(header.mode)),
        };

        match header {
            Header {
                algo: Algorithm::Aes128Gcm(_),
                ..
            } => (),
            _ => return Err(Error::AlgorithmNotSupported(header.algo)),
        };

        if segment_size > MAX_SYMMETRIC_CHUNK_SIZE {
            return Err(Error::ConstraintViolation);
        }

        Ok(Unsealer {
            version,
            header,
            segment_size,
            size_hint,
            r: r.into_inner(), // This (new) reader is locked to the payload.
        })
    }

    /// Unseal the remaining data (which is now only payload) into an [`AsyncWrite`].
    pub async fn unseal<W>(
        &mut self,
        ident: &str,
        usk: &UserSecretKey<CGWKV>,
        mut w: W,
    ) -> Result<(), Error>
    where
        W: AsyncWrite + Unpin,
    {
        let rec_info = self
            .header
            .policies
            .get(ident)
            .ok_or_else(|| Error::UnknownIdentifier(ident.to_string()))?;

        let ss = rec_info.derive_keys(usk)?;
        let key = &ss.0[..KEY_SIZE];

        let iv = match self.header.algo {
            Algorithm::Aes128Gcm(iv) => iv,
            _ => return Err(Error::AlgorithmNotSupported(self.header.algo)),
        };

        let aead = Aes128Gcm::new_from_slice(key).map_err(|_e| Error::KeyError)?;
        let nonce = &iv.0[..STREAM_NONCE_SIZE];

        let mut dec = DecryptorBE32::from_aead(aead, nonce.into());

        let bufsize: usize = self.segment_size as usize + TAG_SIZE;
        let mut buf = vec![0u8; bufsize];
        let mut buf_tail = 0;

        loop {
            let read = self.r.read(&mut buf[buf_tail..bufsize]).await?;
            buf_tail += read;

            if buf_tail == bufsize {
                dec.decrypt_next_in_place(b"", &mut buf)
                    .map_err(|_e| Error::Symmetric)?;
                w.write_all(&buf[..]).await?;

                buf_tail = 0;
                buf.resize(bufsize, 0);
            } else if read == 0 {
                buf.truncate(buf_tail);
                dec.decrypt_last_in_place(b"", &mut buf)
                    .map_err(|_e| Error::Symmetric)?;
                w.write_all(&buf[..]).await?;
                break;
            }
        }

        w.close().await?;
        Ok(())
    }
}
