use crate::constants::*;
use crate::header::*;
use crate::Error;
use crate::{Policy, PublicKey};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite};
use ibe::kem::cgw_kv::CGWKV;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use std::convert::TryFrom;

use aead::stream::EncryptorBE32;
use aes_gcm::{Aes128Gcm, NewAead};

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

    let mut header_vec = Vec::with_capacity(MAX_METADATA_SIZE);
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
