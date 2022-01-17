use crate::constants::*;
use crate::metadata::*;
use crate::Error;
use crate::{util::derive_keys, util::KeySet};
use crate::{Policy, PublicKey};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite};
use ibe::kem::cgw_fo::CGWFO;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;

use crate::stream::web::{aead_nonce, aesgcm::encrypt};

pub async fn seal<Rng, R, W>(
    pk: &PublicKey<CGWFO>,
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
    let KeySet {
        aes_key,
        mac_key: _,
    } = derive_keys(&ss);

    let nonce = &meta.iv[..NONCE_SIZE];
    let mut counter: u32 = u32::default();

    let mut meta_vec = Vec::with_capacity(MAX_METADATA_SIZE);
    meta.msgpack_into(&mut meta_vec)?;

    let mut aad_tag = Vec::new();

    encrypt(
        &aes_key,
        &aead_nonce(nonce, counter, false),
        &meta_vec[..],
        &mut aad_tag,
    )
    .await
    .unwrap();

    counter = counter.checked_add(1).unwrap();

    w.write_all(&meta_vec[..]).await?;
    w.write_all(&aad_tag[..]).await?;

    let mut buf = vec![0; meta.chunk_size];
    let mut buf_tail = 0;

    buf.reserve(TAG_SIZE);

    loop {
        let read = r.read(&mut buf[buf_tail..meta.chunk_size]).await?;
        buf_tail += read;

        if buf_tail == meta.chunk_size {
            buf.truncate(buf_tail);

            encrypt(&aes_key, &aead_nonce(&nonce, counter, false), b"", &mut buf)
                .await
                .unwrap();

            w.write_all(&buf[..]).await?;
            buf_tail = 0;

            counter = counter.checked_add(1).unwrap();
        } else if read == 0 {
            buf.truncate(buf_tail);

            encrypt(&aes_key, &aead_nonce(nonce, counter, true), b"", &mut buf)
                .await
                .unwrap();

            w.write_all(&buf[..]).await?;

            break;
        }
    }

    Ok(())
}
