use arrayvec::{Array, ArrayVec};
use digest::{Digest, FixedOutput};
use ibe::kiltz_vahlis_one::SymmetricKey;
use rand::{CryptoRng, Rng};

use crate::*;

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

/// Nested Reader that archives all bytes passing through in buf.
pub(crate) struct ArchiveReader<R: Readable, A: Array> {
    buf: ArrayVec<A>,
    r: R,
}

impl<R: Readable, A: Array> ArchiveReader<R, A> {
    pub fn new(r: R) -> ArchiveReader<R, A> {
        ArchiveReader {
            buf: ArrayVec::<A>::new(),
            r,
        }
    }

    pub fn disclose(self) -> (ArrayVec<A>, R) {
        (self.buf, self.r)
    }
}

impl<R: Readable, A: Array<Item = u8>> Readable for ArchiveReader<R, A> {
    fn read_byte(&mut self) -> Result<u8, Error> {
        let res = self.r.read_byte()?;
        self.buf.push(res);
        Ok(res)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&[u8], Error> {
        let res = self.r.read_bytes(n)?;
        self.buf.write(res)?;
        Ok(res)
    }
}
