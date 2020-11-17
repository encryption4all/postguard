use digest::{Digest, FixedOutput};
use ibe::kiltz_vahlis_one::SymmetricKey;
use rand::{CryptoRng, Rng};

use crate::stream::*;

pub(crate) fn derive_keys(key: &SymmetricKey) -> ([u8; KEYSIZE], [u8; KEYSIZE]) {
    let mut h = sha3::Sha3_512::new();
    h.input(key.to_bytes().as_ref());
    let buf = h.fixed_result();

    let mut aeskey = [0u8; KEYSIZE];
    let mut mackey = [0u8; KEYSIZE];

    let (a, b) = buf.as_slice().split_at(KEYSIZE);
    aeskey.copy_from_slice(&a);
    mackey.copy_from_slice(&b);

    (aeskey, mackey)
}

pub(crate) fn generate_iv<R: Rng + CryptoRng>(r: &mut R) -> [u8; IVSIZE] {
    let mut res = [0u8; IVSIZE];
    r.fill_bytes(&mut res);
    res
}
