mod de;
mod ser;

#[cfg(test)]
mod tests;

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::util::{derive_keys, KeySet};
use crate::{Error, HiddenPolicy, IV_SIZE};
use core::convert::TryFrom;
use ibe::kem::cgw_fo::{CGWFO, CT_BYTES as CGWFO_CT_BYTES};
use ibe::kem::SharedSecret;
use ibe::{kem::IBKEM, Compress};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::BTreeMap;
use std::fmt::Debug;

impl From<std::io::Error> for crate::Error {
    fn from(e: std::io::Error) -> Self {
        Error::StdIOError(e)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecipientInfo {
    /// The hidden policy associated with this identifier.
    #[serde(rename = "p")]
    pub policy: HiddenPolicy,

    /// Ciphertext for this specific recipient.
    #[serde(with = "BigArray")]
    pub ct: [u8; CGWFO_CT_BYTES],
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RecipientMetadata {
    /// Info specific to one recipient, i.e., a policy and associated ciphertext.
    pub recipient_info: RecipientInfo,

    /// The initializion vector used for symmetric encryption.
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    pub chunk_size: usize,
}

impl RecipientMetadata {
    /// Derives a [`KeySet`] from a [`RecipientMetadata`].
    ///
    /// This keyset can be used for AEAD.
    pub fn derive_keys(
        &self,
        usk: &UserSecretKey<CGWFO>,
        pk: &PublicKey<CGWFO>,
    ) -> Result<KeySet, Error> {
        let c = crate::util::open_ct(<CGWFO as IBKEM>::Ct::from_bytes(&self.recipient_info.ct))
            .ok_or(Error::FormatViolation)?;
        let ss = CGWFO::decaps(Some(&pk.0), &usk.0, &c).map_err(|e| Error::KemError(e))?;

        Ok(derive_keys(&ss))
    }
}
