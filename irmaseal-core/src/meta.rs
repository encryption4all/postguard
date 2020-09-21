use super::stream::*;
use crate::Identity;
use super::{Error};
use base64;
use arrayvec::{ArrayString, ArrayVec};
use serde::{Deserialize, Serialize, Deserializer, Serializer};

/// The version of the encrypted data
#[derive(Serialize, Deserialize, Debug, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Version {
    V1_0,
}

/// Metadata which contains the version
#[derive(Serialize, Deserialize, Debug, PartialEq)]
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

    base64::encode_config_slice(&ciphertext, base64::STANDARD, b64_encoded.as_mut_slice());

    b64_encoded.serialize(serializer)
}

fn from_base64_ciphertext<'de, D>(deserializer: D) -> Result<ArrayVec<[u8; CIPHERTEXT_SIZE]>, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;

    let mut result = ArrayVec::<[u8; CIPHERTEXT_SIZE]>::new();

    ArrayVec::<[u8; CIPHERTEXT_SIZE_B64]>::deserialize(deserializer)
        .and_then(|avec| base64::decode_config_slice(&avec, base64::STANDARD, result.as_mut_slice())
                             .map_err(|_| Error::custom("Ciphertext contains invalid Base64")))?;

    Ok(result)
}

fn to_base64_iv<S>(ciphertext: &ArrayVec<[u8; IVSIZE]>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
{
    let mut b64_encoded = ArrayVec::<[u8; IVSIZE_B64]>::new();

    base64::encode_config_slice(&ciphertext, base64::STANDARD, b64_encoded.as_mut_slice());

    b64_encoded.serialize(serializer)
}

fn from_base64_iv<'de, D>(deserializer: D) -> Result<ArrayVec<[u8; IVSIZE]>, D::Error>
    where D: Deserializer<'de>
{
    use serde::de::Error;

    let mut result = ArrayVec::<[u8; IVSIZE]>::new();

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
        identity: Identity
    ) -> Result<Self, Error> {
        let media_type = ArrayString::<[u8; 255]>::from(media_type).or(Err(Error::ConstraintViolation))?;
        let ciphertext = ciphertext.iter().cloned().collect::<ArrayVec::<[u8; CIPHERTEXT_SIZE]>>();
        let iv = iv.iter().cloned().collect::<ArrayVec::<[u8; IVSIZE]>>();

        Ok(Metadata { version, media_type, media_metadata, ciphertext, iv, identity })
    }
}
