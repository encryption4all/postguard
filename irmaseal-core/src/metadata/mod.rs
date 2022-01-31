mod de;
mod ser;

#[cfg(test)]
mod tests;

use crate::artifacts::UserSecretKey;
use crate::util::{derive_keys, KeySet};
use crate::{Error, HiddenPolicy, IV_SIZE};
use core::convert::TryFrom;
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::mr::{MultiRecipient, MultiRecipientCiphertext};
use ibe::kem::SharedSecret;
use ibe::Compress;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeMap;
use std::fmt::Debug;

impl From<std::io::Error> for crate::Error {
    fn from(e: std::io::Error) -> Self {
        Error::StdIO(e)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecipientInfo {
    /// The hidden policy associated with this identifier.
    #[serde(rename = "p")]
    pub policy: HiddenPolicy,

    /// Ciphertext for this specific recipient.
    #[serde(with = "BigArray")]
    pub ct: [u8; MultiRecipientCiphertext::<CGWKV>::OUTPUT_SIZE],
}

/// This struct containts metadata for _ALL_ recipients.  It only needs to be in memory for
/// encoding purposes, for decoding for specific recipient see [`RecipientMetadata`].
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(rename = "rs")]
    pub policies: BTreeMap<String, RecipientInfo>,

    /// The initializion vector used for symmetric encryption.
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    #[serde(rename = "cs")]
    pub chunk_size: usize,
}

impl RecipientInfo {
    /// Derives a [`KeySet`] from a [`RecipientMetadata`].
    ///
    /// This keyset can be used for AEAD.
    pub fn derive_keys(&self, usk: &UserSecretKey<CGWKV>) -> Result<KeySet, Error> {
        let c = crate::util::open_ct(MultiRecipientCiphertext::<CGWKV>::from_bytes(&self.ct))
            .ok_or(Error::FormatViolation)?;
        let ss = CGWKV::multi_decaps(None, &usk.0, &c).map_err(Error::Kem)?;

        Ok(derive_keys(&ss))
    }
}
