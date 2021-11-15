mod de;
mod ser;

#[cfg(test)]
mod tests;

use crate::artifacts::{PublicKey, UserSecretKey};
use crate::util::{derive_keys, KeySet};
use crate::{Attribute, Error, Identity, IV_SIZE};
use alloc::fmt::Debug;
use arrayvec::ArrayString;
use ibe::kem::cgw_fo::{CGWFO, CT_BYTES as CGWFO_CT_BYTES};
use ibe::kem::SharedSecret;
use ibe::{kem::IBKEM, Compress};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// An IRMAseal policy.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct Policy {
    #[serde(rename = "t")]
    pub timestamp: u64,
    #[serde(rename = "c")]
    pub con: Vec<Attribute>,
}

// We split them by type to ensure no mixups!
/// An IRMAseal AttributeRequest.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Copy, Default)]
pub struct HiddenAttribute {
    #[serde(rename = "t")]
    pub atype: ArrayString<255>,
    #[serde(rename = "v")]
    pub hidden_value: Option<ArrayString<254>>,
}

/// An IRMAseal hidden policy.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct HiddenPolicy {
    #[serde(rename = "t")]
    pub timestamp: u64,
    #[serde(rename = "c")]
    pub con: Vec<HiddenAttribute>,
}

/// EXAMPLE!!!! DO NOT USE!!! DOESN'T HIDE ANYTHING
impl From<&Policy> for HiddenPolicy {
    fn from(p: &Policy) -> Self {
        Self {
            timestamp: p.timestamp,
            con: p
                .con
                .iter()
                .map(|a| HiddenAttribute {
                    atype: a.atype,
                    hidden_value: a.value,
                })
                .collect(),
        }
    }
}

use core::convert::TryFrom;
use ibe::Derive;
use tiny_keccak::{Hasher, Sha3};

impl Policy {
    /// Derives an identity to be used in IBE (specificly, CGWFO).
    pub fn derive(&self) -> <CGWFO as IBKEM>::Id {
        // This method implement domain separation as follows:
        // let policy(id = con[0..n-1]) = H(0 || h_0 || h_1 || .. | h_{n-1}),
        // where h_i = H(i + 1 || con[i]).

        let mut buf = [0u8; 65];
        let mut sha3 = Sha3::v512();

        for (i, ar) in self.con.iter().enumerate() {
            let id = Identity::new(self.timestamp, &ar.atype, ar.value.as_deref())
                .unwrap()
                .derive::<CGWFO>()
                .unwrap();

            buf[0] = u8::try_from(i + 1).unwrap(); // fails for > 255 attributes
            buf[1..].copy_from_slice(&id.0);
            sha3.update(&buf);
        }

        buf[0] = 0x00;
        sha3.finalize(&mut buf[1..]);
        <CGWFO as IBKEM>::Id::derive(&buf)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RecipientIdentifier(pub ArrayString<255>);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RecipientInfo {
    /// (Public) Identifier of the recipient.
    /// Used to find the associated policy and ciphertext.
    #[serde(rename = "id")]
    pub identifier: RecipientIdentifier,

    /// The hidden policy associated with this identifier.
    #[serde(rename = "p")]
    pub policy: HiddenPolicy,

    /// Ciphertext for this specific recipient
    #[serde(with = "BigArray")]
    pub ct: [u8; CGWFO_CT_BYTES],
}

/// This struct _never_ needs to be in memory, unless you require the full metadata
/// containing info for all recipients, otherwise see [`RecipientMetadata`].
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(rename = "rs")]
    pub recipient_info: Vec<RecipientInfo>,

    /// The initializion vector used for symmetric encryption.
    #[serde(rename = "iv")]
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    #[serde(rename = "cs")]
    pub chunk_size: usize,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RecipientMetadata {
    /// Info specific to one recipient, i.e., a policy and associated ciphertext.
    pub recipient_info: RecipientInfo,

    /// The initializion vector used for symmetric encryption.
    pub iv: [u8; IV_SIZE],

    /// The size of the chunks in which to process symmetric encryption.
    pub chunk_size: usize,
}

impl PartialEq for RecipientInfo {
    fn eq(&self, other: &Self) -> bool {
        self.identifier == other.identifier
    }
}

impl RecipientIdentifier {
    pub fn new<'a>(s: &'a str) -> Result<Self, Error> {
        ArrayString::<255>::from(s)
            .map(|x| Self(x))
            .map_err(|_e| Error::FormatViolation)
    }
}

impl RecipientMetadata {
    fn default_with_id(id: &RecipientIdentifier) -> Self {
        Self {
            recipient_info: RecipientInfo {
                identifier: id.clone(),
                policy: HiddenPolicy::default(),
                ct: [0u8; CGWFO_CT_BYTES],
            },
            iv: [0u8; IV_SIZE],
            chunk_size: 0 as usize,
        }
    }

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
        let ss = CGWFO::decaps(Some(&pk.0), &usk.0, &c).map_err(|_e| Error::DecapsulationError)?;

        Ok(derive_keys(&ss))
    }
}
