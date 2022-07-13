use crate::constants::*;
use crate::header::*;
use crate::Error;
use crate::UserSecretKey;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use ibe::kem::cgw_kv::CGWKV;
use std::convert::TryInto;

use aead::stream::DecryptorBE32;
use aes_gcm::{Aes128Gcm, NewAead};

/// An unsealer is used to unseal IRMAseal bytestreams.
pub struct Unsealer<R> {
    pub version: u16,
    pub header: Header,
    pub size_hint: (u64, Option<u64>),
    segment_size: u32,
    r: R,
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

        if tmp[..PRELUDE_SIZE] != PRELUDE {
            return Err(Error::NotIRMASEAL);
        }

        let version = u16::from_be_bytes(
            tmp[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        );

        if version != VERSION_V2 {
            return Err(Error::IncorrectVersion {
                expected: VERSION_V2,
                found: version,
            });
        }

        let header_len = u32::from_be_bytes(
            tmp[PREAMBLE_SIZE - METADATA_SIZE_SIZE..]
                .try_into()
                .map_err(|_e| Error::FormatViolation)?,
        ) as usize;

        if header_len > MAX_METADATA_SIZE {
            return Err(Error::ConstraintViolation);
        }

        let mut header_buf = Vec::with_capacity(header_len);

        // Limit reader to not read past header
        let mut r = r.take(header_len as u64);

        r.read_to_end(&mut header_buf)
            .map_err(|_e| Error::FormatViolation)
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
