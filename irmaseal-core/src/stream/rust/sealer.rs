use crate::constants::*;
use crate::metadata::*;
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
    let (meta, ss) = Metadata::new(pk, policies, rng)?;
    let aes_key = &ss.0[..KEY_SIZE];

    let aes_gcm = Aes128Gcm::new_from_slice(aes_key).map_err(|_e| Error::KeyError)?;
    let nonce = &meta.iv[..NONCE_SIZE];

    let mut enc = EncryptorBE32::from_aead(aes_gcm, nonce.into());

    w.write_all(&PRELUDE).await?;
    w.write_all(&VERSION_V2.to_be_bytes()).await?;

    let mut meta_vec = Vec::with_capacity(MAX_METADATA_SIZE);
    meta.msgpack_into(&mut meta_vec)?;

    w.write_all(
        &u32::try_from(meta_vec.len())
            .map_err(|_e| Error::ConstraintViolation)?
            .to_be_bytes(),
    )
    .await?;

    w.write_all(&meta_vec[..]).await?;

    let mut buf = vec![0; meta.chunk_size];
    let mut buf_tail = 0;

    buf.reserve(TAG_SIZE);

    loop {
        let read = r.read(&mut buf[buf_tail..meta.chunk_size]).await?;
        buf_tail += read;

        if buf_tail == meta.chunk_size {
            buf.truncate(buf_tail);
            enc.encrypt_next_in_place(b"", &mut buf).unwrap();
            w.write_all(&buf[..]).await?;
            buf_tail = 0;
        } else if read == 0 {
            buf.truncate(buf_tail);
            enc.encrypt_last_in_place(b"", &mut buf).unwrap();
            w.write_all(&buf[..]).await?;
            break;
        }
    }

    w.close().await?;
    Ok(())
}
