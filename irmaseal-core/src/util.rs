use crate::*;
use digest::{Digest, FixedOutput};
use ibe::kiltz_vahlis_one::SymmetricKey;
use rand::{CryptoRng, Rng};

#[derive(Clone)]
pub struct KeySet {
    pub aes_key: [u8; KEYSIZE],
    pub mac_key: [u8; KEYSIZE],
}

pub(crate) fn open_ct<T>(x: subtle::CtOption<T>) -> Option<T> {
    if bool::from(x.is_some()) {
        Some(x.unwrap())
    } else {
        None
    }
}

pub(crate) fn derive_keys(key: &SymmetricKey) -> KeySet {
    let mut h = sha3::Sha3_512::new();
    h.input(key.to_bytes().as_ref());
    let buf = h.fixed_result();

    let mut aes_key = [0u8; KEYSIZE];
    let mut mac_key = [0u8; KEYSIZE];

    let (a, b) = buf.as_slice().split_at(KEYSIZE);
    aes_key.copy_from_slice(&a);
    mac_key.copy_from_slice(&b);

    KeySet {
        aes_key: aes_key,
        mac_key: mac_key,
    }
}

pub(crate) fn generate_iv<R: Rng + CryptoRng>(r: &mut R) -> [u8; IVSIZE] {
    let mut res = [0u8; IVSIZE];
    r.fill_bytes(&mut res);
    res
}
