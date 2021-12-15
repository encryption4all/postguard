use crate::constants::*;
use crate::metadata::*;
use crate::Error;
use crate::{stream::*, util::derive_keys, util::KeySet};
use crate::{Policy, PublicKey};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::{AsyncRead, AsyncWrite};
use ibe::kem::cgw_fo::CGWFO;
use rand::{CryptoRng, RngCore};
use std::collections::BTreeMap;
use tiny_keccak::{Hasher, Kmac};

#[cfg(feature = "stream")]
use {aes::Aes128, aes_async::AsyncCipher, ctr::Ctr64BE};

#[cfg(feature = "wasm_stream")]
use aes_wasm::Ctr64BEAes128;

pub async fn seal<Rng, R, W>(
    pk: &PublicKey<CGWFO>,
    policies: &BTreeMap<String, Policy>,
    rng: &mut Rng,
    r: R,
    w: W,
) -> Result<(), Error>
where
    Rng: RngCore + CryptoRng,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    #[cfg(feature = "stream")]
    {
        generic_seal::<Rng, AsyncCipher<Ctr64BE<Aes128>>, Kmac, R, W>(pk, policies, rng, r, w).await
    }
    #[cfg(feature = "wasm_stream")]
    {
        generic_seal::<Rng, Ctr64BEAes128, Kmac, R, W>(pk, policies, rng, r, w).await
    }
}

async fn generic_seal<Rng, Sym, Mac, R, W>(
    pk: &PublicKey<CGWFO>,
    policies: &BTreeMap<String, Policy>,
    rng: &mut Rng,
    mut r: R,
    mut w: W,
) -> Result<(), Error>
where
    Rng: RngCore + CryptoRng,
    Sym: AsyncNewCipher + AsyncStreamCipher,
    Mac: NewMac + Hasher,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (meta, ss) = Metadata::new(pk, policies, rng)?;
    let KeySet { aes_key, mac_key } = derive_keys(&ss);

    let mut enc = Sym::new_from_slices(&aes_key, &meta.iv).await?;
    let mut mac = Mac::new_with_key(&mac_key);

    // We have to buffer the entire metadata here, unfortunately.
    // MessagePack does not support AsyncRead/Write and does not plan to do so.
    let mut meta_vec = Vec::new();
    meta.msgpack_into(&mut meta_vec)?;

    mac.update(&meta_vec);
    w.write_all(&meta_vec[..]).await?;

    let mut buf = vec![0u8; meta.chunk_size];
    let mut buf_tail = 0;

    loop {
        let input_length = r.read(&mut buf[buf_tail..]).await?;
        buf_tail += input_length;

        // Start encrypting when our buffer is full or when the input stream
        // is exhausted and we still have data left to encrypt.
        if buf_tail == meta.chunk_size || buf_tail > 0 && input_length == 0 {
            let data = &mut buf[..buf_tail];

            // Encrypt-then-MAC
            enc.apply_keystream(data).await;
            mac.update(data);

            w.write_all(data).await?;

            buf_tail = 0;
        }

        if input_length == 0 {
            break;
        }
    }

    let mut tag = [0u8; TAG_SIZE];
    mac.finalize(&mut tag);
    w.write_all(&tag).await?;

    Ok(())
}
