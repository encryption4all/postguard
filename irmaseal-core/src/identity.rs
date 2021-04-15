use super::Error;
use arrayvec::{ArrayString, ArrayVec};
use serde::{Deserialize, Serialize};
use core::convert::TryFrom;

const IDENTITY_UNSET: u8 = 0xFF;

// Must be at least 8+255+254 = 517
#[allow(dead_code)]
type IdentityBuf = ArrayVec<[u8; 1024]>;

/// An IRMAseal Attribute, which is a simple case of an IRMA ConDisCon.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Attribute {
    #[serde(rename = "type")]
    pub atype: ArrayString<[u8; 255]>,
    pub value: Option<ArrayString<[u8; 254]>>,
}

/// An IRMAseal identity, from which internally a Waters identity can be derived.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
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

        buf.try_extend_from_slice(&self.timestamp.to_be_bytes())
            .map_err(|_| Error::ConstraintViolation)?;

        let at = self.attribute.atype.as_bytes();
        let at_len = u8::try_from(at.len())
            .map_err(|_| Error::ConstraintViolation)?;

        buf.try_extend_from_slice(&[at_len])
            .map_err(|_| Error::ConstraintViolation)?;

        buf.try_extend_from_slice(&at)
            .map_err(|_| Error::ConstraintViolation)?;

        match self.attribute.value {
            None => buf
                .try_extend_from_slice(&[IDENTITY_UNSET])
                .map_err(|_| Error::ConstraintViolation),
            Some(i) => {
                let i = i.as_bytes();
                let i_len = i.len();

                if i_len >= usize::from(IDENTITY_UNSET) {
                    return Err(Error::ConstraintViolation);
                }

                let i_len_u8 = u8::try_from(i_len)
                    .map_err(|_| Error::ConstraintViolation)?;
        
                buf.try_extend_from_slice(&[i_len_u8])
                    .map_err(|_| Error::ConstraintViolation)?;

                buf.try_extend_from_slice(&i)
                    .map_err(|_| Error::ConstraintViolation)
            }
        }?;

        Ok(ibe::kiltz_vahlis_one::Identity::derive(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_write_read() {
        let mut buf = IdentityBuf::new();

        // using the arrayvec as a slice uses amount
        // of valid elements in the arrayvec as the slice
        // slice length. Since we want to write into it
        // using postcard we fill it with dummy data
        // first. Alternative is to use unsafe and
        // force the capacity to a certain size.
        for _ in 0..buf.capacity() {
            buf.push(0);
        }

        unsafe {
            buf.set_len(buf.capacity());
        }

        let i = Identity::new(
            1566722350,
            "pbdf.pbdf.email.email",
            Some("w.geraedts@sarif.nl"),
        )
        .unwrap();

        let identity_bytes = postcard::to_slice(&i, buf.as_mut_slice()).unwrap();

        let i2 = postcard::from_bytes(identity_bytes).unwrap();

        assert_eq!(i, i2);
    }
}
