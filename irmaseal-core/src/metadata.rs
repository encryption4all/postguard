use crate::*;
use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]
pub(crate) const KEYSIZE: usize = 32;
pub(crate) const IVSIZE: usize = 16;
#[allow(dead_code)]
pub(crate) const MACSIZE: usize = 32;
pub(crate) const CIPHERTEXT_SIZE: usize = 144;
pub(crate) const VERSION_V1: u16 = 0;

/// Metadata which contains the version
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Metadata {
    pub ciphertext: ArrayVec<[u8; CIPHERTEXT_SIZE]>,
    pub iv: ArrayVec<[u8; IVSIZE]>,
    pub identity: Identity,
}

impl Metadata {
    /// Conveniently construct a new Metadata. It is also possible to directly construct this object.
    ///
    /// Throws a ConstraintViolation when the type or value strings are too long..
    pub fn new(
        ciphertext: &[u8; CIPHERTEXT_SIZE],
        iv: &[u8; IVSIZE],
        identity: Identity,
    ) -> Result<Self, Error> {
        let ciphertext = ciphertext
            .iter()
            .cloned()
            .collect::<ArrayVec<[u8; CIPHERTEXT_SIZE]>>();
        let iv = iv.iter().cloned().collect::<ArrayVec<[u8; IVSIZE]>>();

        Ok(Metadata {
            ciphertext,
            iv,
            identity,
        })
    }
}
