use crate::*;
use base64;
use arrayvec::{ArrayString, ArrayVec};
use serde::{Deserialize, Serialize, Deserializer, Serializer};

#[allow(dead_code)]
pub(crate) const KEYSIZE: usize = 32;
pub(crate) const IVSIZE: usize = 16;
pub(crate) const IVSIZE_B64: usize = 24;
#[allow(dead_code)]
pub(crate) const MACSIZE: usize = 32;
pub(crate) const CIPHERTEXT_SIZE: usize = 144;
pub(crate) const CIPHERTEXT_SIZE_B64: usize = 192;

/// The version of the encrypted data
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Version {
    V1_0
}

/// Metadata which contains the version
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Metadata {
    pub version: Version,
    pub media_type: ArrayString<[u8; 255]>,
    pub media_metadata: serde_json::Value,
    #[serde(serialize_with = "to_base64_ciphertext", deserialize_with = "from_base64_ciphertext")]
    pub ciphertext: ArrayVec<[u8; CIPHERTEXT_SIZE]>,
    #[serde(serialize_with = "to_base64_iv", deserialize_with = "from_base64_iv")]
    pub iv: ArrayVec<[u8; IVSIZE]>,
    pub identity: Identity,
}

// Can't have natural at the type level(yet). so just use to_base64 twice with different sizes.
fn to_base64_ciphertext<S>(ciphertext: &ArrayVec<[u8; CIPHERTEXT_SIZE]>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    let mut b64_encoded = ArrayVec::<[u8; CIPHERTEXT_SIZE_B64]>::new();

    for _ in 0..CIPHERTEXT_SIZE_B64 {
        b64_encoded.push(0);
    }

    base64::encode_config_slice(ciphertext.as_slice(), base64::STANDARD, b64_encoded.as_mut_slice());

    b64_encoded.serialize(serializer)
}

fn from_base64_ciphertext<'de, D>(deserializer: D) -> Result<ArrayVec<[u8; CIPHERTEXT_SIZE]>, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;

    let mut result = ArrayVec::<[u8; CIPHERTEXT_SIZE]>::new();

    for _ in 0..CIPHERTEXT_SIZE {
        result.push(0);
    }

    ArrayVec::<[u8; CIPHERTEXT_SIZE_B64]>::deserialize(deserializer)
        .and_then(|avec| base64::decode_config_slice(&avec, base64::STANDARD, result.as_mut_slice())
                             .map_err(|_| Error::custom("Ciphertext contains invalid Base64")))?;

    Ok(result)
}

fn to_base64_iv<S>(ciphertext: &ArrayVec<[u8; IVSIZE]>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    let mut b64_encoded = ArrayVec::<[u8; IVSIZE_B64]>::new();

    for _ in 0..IVSIZE_B64 {
        b64_encoded.push(0);
    }

    base64::encode_config_slice(&ciphertext, base64::STANDARD, b64_encoded.as_mut_slice());

    b64_encoded.serialize(serializer)
}

fn from_base64_iv<'de, D>(deserializer: D) -> Result<ArrayVec<[u8; IVSIZE]>, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;

    let mut result = ArrayVec::<[u8; IVSIZE]>::new();

    for _ in 0..IVSIZE {
        result.push(0);
    }

    ArrayVec::<[u8; IVSIZE_B64]>::deserialize(deserializer)
        .and_then(|avec| base64::decode_config_slice(&avec, base64::STANDARD, result.as_mut_slice())
                             .map_err(|_| Error::custom("Ciphertext contains invalid Base64")))?;

    Ok(result)
}

impl Metadata {
    /// Conveniently construct a new Metadata. It is also possible to directly construct this object.
    ///
    /// Throws a ConstraintViolation when the type or value strings are too long..
    pub fn new(
        version: Version,
        media_type: &str,
        media_metadata: serde_json::Value,
        ciphertext: &[u8; CIPHERTEXT_SIZE],
        iv: &[u8; IVSIZE],
        identity: &Identity
    ) -> Result<Self, Error> {
        let media_type = ArrayString::<[u8; 255]>::from(media_type).or(Err(Error::ConstraintViolation))?;
        let ciphertext = ciphertext.iter().cloned().collect::<ArrayVec::<[u8; CIPHERTEXT_SIZE]>>();
        let iv = iv.iter().cloned().collect::<ArrayVec::<[u8; IVSIZE]>>();
        let identity = identity.clone();

        Ok(Metadata { version, media_type, media_metadata, ciphertext, iv, identity })
    }
}
