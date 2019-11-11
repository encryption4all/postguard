use super::{Error, Readable, Writable};
use arrayref::array_ref;
use arrayvec::{ArrayString, ArrayVec};
use serde::{Deserialize, Serialize};

const IDENTITY_UNSET: u8 = 0xFF;

// Must be at least 8+1+255+1+254 = 519
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

    /// Write the byte representation of this attribute as a bytestream.
    pub fn write_to<W: Writable>(&self, w: &mut W) -> Result<(), Error> {
        use core::convert::TryFrom;

        let at = self.atype.as_bytes();
        // ArrayString cannot be larger than 255.
        let at_len = u8::try_from(at.len()).unwrap();
        w.write(&[at_len.to_be()])?;
        w.write(at)?;

        match self.value {
            None => w.write(&[IDENTITY_UNSET])?,
            Some(i) => {
                let i = i.as_bytes();

                if i.len() >= usize::from(IDENTITY_UNSET) {
                    return Err(Error::ConstraintViolation);
                }

                // ArrayString cannot be larger than 254.
                let i_len = u8::try_from(i.len()).unwrap();
                w.write(&[i_len.to_be()])?;
                w.write(i)?;
            }
        }

        Ok(())
    }

    /// Construct an attribute from a bytestream.
    pub fn read_from<R: Readable>(r: &mut R) -> Result<Self, Error> {
        let at_len = u8::from_be(r.read_byte()?);
        let at_len = usize::from(at_len);
        let atype = core::str::from_utf8(r.read_bytes(at_len)?).or(Err(Error::FormatViolation))?;

        // Unwrap is valid because it impossible to not fit given u8.
        let atype = ArrayString::<[u8; 255]>::from(atype).unwrap();

        let i_len = u8::from_be(r.read_byte()?);
        let value = if i_len == IDENTITY_UNSET {
            None
        } else {
            let i_len = usize::from(i_len);
            let value =
                core::str::from_utf8(r.read_bytes(i_len)?).or(Err(Error::FormatViolation))?;

            // Unwrap is valid because it impossible to not fit given u8.
            let value = ArrayString::<[u8; 254]>::from(value).unwrap();
            Some(value)
        };

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

    /// Write the byte representation of this identity as a bytestream.
    pub fn write_to<W: Writable>(&self, w: &mut W) -> Result<(), Error> {
        w.write(&self.timestamp.to_be_bytes())?;
        self.attribute.write_to(w)
    }

    /// Construct an identity from a bytestream.
    pub fn read_from<R: Readable>(r: &mut R) -> Result<Identity, Error> {
        let timestamp = r.read_bytes(8)?;
        let timestamp = u64::from_be_bytes(*array_ref![timestamp, 0, 8]);

        Ok(Identity {
            timestamp,
            attribute: Attribute::read_from(r)?,
        })
    }

    /// Derive the corresponding Waters identity in a deterministic way.
    /// Uses `self.write_to` and `ibe::kiltz_vahlis_one::Identity:derive` internally.
    pub fn derive(&self) -> ibe::kiltz_vahlis_one::Identity {
        let mut buf = IdentityBuf::new();
        self.write_to(&mut buf).unwrap();
        ibe::kiltz_vahlis_one::Identity::derive(&buf)
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
        i.write_to(&mut buf).unwrap();

        let mut reader = SliceReader::new(&buf);
        let i2 = Identity::read_from(&mut reader).unwrap();

        assert_eq!(i, i2);
    }
}
