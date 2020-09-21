use super::{Error, Writable};
use arrayvec::{ArrayString, ArrayVec};
use serde::{Deserialize, Serialize};

const IDENTITY_UNSET: u8 = 0xFF;

// Must be at least 8+255+1+254 = 518
#[allow(dead_code)]
type IdentityBuf = ArrayVec<[u8; 1024]>;

/// An IRMAseal Attribute, which is a simple case of an IRMA ConDisCon.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Attribute {
    #[serde(rename = "type")]
    pub atype: ArrayString<[u8; 255]>,
    pub value: Option<ArrayString<[u8; 254]>>,
}

/// An IRMAseal identity, from which internally a Waters identity can be derived.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Identity {
    #[serde(with = "crate::util::u64_ser")]
    pub timestamp: u64,
    pub attribute: Attribute,
}

impl Attribute {
    /// Conveniently construct a new attribute. It is also possible to directly construct this object.
    ///
    /// Throws a ConstraintViolation when the type or value strings are too long.
    pub fn new(atype: &str, value: Option<&str>) -> Result<Self, Error> {
        let atype = ArrayString::<[u8; 255]>::from(atype).or(Err(Error::ConstraintViolation))?;
        let value = value
            .map(|v| Ok(ArrayString::<[u8; 254]>::from(v).or(Err(Error::ConstraintViolation))?))
            .transpose()?;

        Ok(Attribute { atype, value })
    }
}

impl Identity {
    /// Conveniently construct a new identity. It is also possible to directly construct this object.
    ///
    /// Throws a ConstraintViolation when the attribute or identity strings are too long.
    pub fn new(timestamp: u64, atype: &str, value: Option<&str>) -> Result<Identity, Error> {
        Ok(Identity {
            timestamp,
            attribute: Attribute::new(atype, value)?,
        })
    }

    /// Derive the corresponding Waters identity in a deterministic way.
    /// Uses `ibe::kiltz_vahlis_one::Identity:derive` internally.
    pub fn derive(&self) -> Result<ibe::kiltz_vahlis_one::Identity, Error> {
        let mut buf = IdentityBuf::new();

        buf.write(&self.timestamp.to_be_bytes())?;

        buf.write(self.attribute.atype.as_bytes())?;

        match self.attribute.value {
            None => buf.write(&[IDENTITY_UNSET]),
            Some(i) => {
                let i = i.as_bytes();

                if i.len() >= usize::from(IDENTITY_UNSET) {
                    return Err(Error::ConstraintViolation);
                }

                buf.write(i)
            }
        }?;

        Ok(ibe::kiltz_vahlis_one::Identity::derive(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::SliceReader;

    #[test]
    fn eq_write_read() {
        let mut buf = IdentityBuf::new();

        let i = Identity::new(
            1566722350,
            "pbdf.pbdf.email.email",
            Some("w.geraedts@sarif.nl"),
        )
        .unwrap();

        buf.write(serde_json::to_vec(&i).unwrap().as_slice()).unwrap();

        let i2 = serde_json::from_slice(buf.as_slice()).unwrap();

        assert_eq!(i, i2);
    }
}
