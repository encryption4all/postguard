use crate::*;
use arrayvec::ArrayVec;
use serde::de::Visitor;
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use core::fmt;

#[allow(dead_code)]
pub(crate) const KEYSIZE: usize = 32;
pub(crate) const IVSIZE: usize = 16;
#[allow(dead_code)]
pub(crate) const MACSIZE: usize = 32;
pub(crate) const CIPHERTEXT_SIZE: usize = 144;
pub(crate) const VERSION_SIZE: usize = 2;
pub(crate) const VERSION_V1_BUF: [u8; VERSION_SIZE] = [0x00, 0x01];

//= The version of the encrypted data
#[derive(Debug, PartialEq, Clone)]
pub enum Version {
    V1_0,
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Version::V1_0 => serializer.serialize_bytes(&VERSION_V1_BUF),
        }
    }
}

struct VersionVisitor;

impl<'de> Visitor<'de> for VersionVisitor {
    type Value = Version;

    fn visit_bytes<E>(self, buf: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if buf == &VERSION_V1_BUF {
            return Ok(Version::V1_0);
        } else {
            return Err(E::custom("Invalid version byte string"));
        }
    }

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a byte buffer with 2 bytes indicating the IRMASEAL version.")
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Version, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(VersionVisitor)
    }
}

pub fn version_tobytes(v: &Version) -> ArrayVec<[u8; VERSION_SIZE]> {
    match v {
        Version::V1_0 => ArrayVec::from([0x00, 0x01]),
    }
}

pub fn version_frombytes(buf: &ArrayVec<[u8; VERSION_SIZE]>) -> Result<Version, Error> {
    if &buf[..] == &[0x00, 0x01] {
        return Ok(Version::V1_0);
    } else {
        return Err(Error::FormatViolation);
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ser_deser_version() {
        let v = Version::V1_0;

        let mut ser_buf = [0; 512];

        let buf = postcard::to_slice(&v, &mut ser_buf).unwrap();

        let v2 = postcard::from_bytes(buf).unwrap();

        assert_eq!(v, v2);
    }

    #[test]
    fn ser_deser_version_error() {
        let v = Version::V1_0;

        let mut ser_buf = [0; 512];

        let buf = postcard::to_slice(&v, &mut ser_buf).unwrap();
        buf[0] = 0xff;

        let v2: Result<Version, postcard::Error> = postcard::from_bytes(buf);

        assert_eq!(v2.is_err(), true);
    }
}
