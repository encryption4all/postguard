use super::Error;
use ibe::kem::IBKEM;
use ibe::Derive;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

const IDENTITY_UNSET: u64 = u64::MAX;
const MAX_CON: usize = (IDENTITY_UNSET as usize - 1) >> 1;

/// An IRMAseal Attribute(Request), which is a simplest case of an IRMA ConDisCon.
// TODO: consider implementing Ord ourselves.
#[derive(Serialize, Deserialize, Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Default)]
pub struct Attribute {
    #[serde(rename = "t")]
    pub atype: String,
    #[serde(rename = "v")]
    pub value: Option<String>,
    // TODO: not null bool?
}

/// An IRMAseal policy.
///
/// Contains a timestamp and a conjuction of Attribute(Requests).
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct Policy {
    #[serde(rename = "t")]
    pub timestamp: u64,
    #[serde(rename = "c")]
    pub con: Vec<Attribute>,
}

/// An IRMAseal AttributeRequest.
///
/// We split this from Attribut by type to ensure no mixups!
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct HiddenAttribute {
    #[serde(rename = "t")]
    pub atype: String,
    #[serde(rename = "v")]
    pub hidden_value: Option<String>,
}

/// An IRMAseal hidden policy.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct HiddenPolicy {
    #[serde(rename = "t")]
    pub timestamp: u64,
    #[serde(rename = "c")]
    pub con: Vec<HiddenAttribute>,
}

impl Policy {
    /// Completely hides the attribute value.
    pub fn to_hidden(&self) -> HiddenPolicy {
        HiddenPolicy {
            timestamp: self.timestamp,
            con: self
                .con
                .iter()
                .map(|a| HiddenAttribute {
                    atype: a.atype.clone(),
                    hidden_value: Some("".to_string()),
                })
                .collect(),
        }
    }
}

impl Policy {
    pub fn derive<K: IBKEM>(&self) -> Result<<K as IBKEM>::Id, Error> {
        // This method implements domain separation as follows:
        // Suppose we have the following policy:
        //  - con[0..n - 1] consisting of n conjunctions.
        //  - timestamp
        // = H(0 || f_0 || f'_0 ||  .. || f_{n-1} || f'_{n-1} || timestamp),
        // where f_i  = H(2i + 1 || a.typ.len() || a.typ),
        // and   f'_i = H(2i + 2 || a.val.len() || a.val).
        //
        // Conjunction is sorted. This requires that Attribute implements a stable Ord.
        // Since lengths encoded as usize are not platform-agnostic, we convert all
        // usize to u64.

        if self.con.len() > MAX_CON {
            Err(Error::ConstraintViolation)?
        }

        let mut tmp = [0u8; 64];

        let mut pre_h = Sha3::v512();
        pre_h.update(&[0x00]);

        let mut copy = self.con.clone();
        copy.sort();

        for (i, ar) in copy.iter().enumerate() {
            let mut f = Sha3::v512();

            f.update(&((2 * i + 1) as u64).to_be_bytes());
            let at_bytes = ar.atype.as_bytes();
            f.update(&(at_bytes.len() as u64).to_be_bytes());
            f.update(&at_bytes);
            f.finalize(&mut tmp);

            pre_h.update(&tmp);

            // Initialize a new hash, f'
            f = Sha3::v512();
            f.update(&((2 * i + 2) as u64).to_be_bytes());

            match &ar.value {
                None => f.update(&IDENTITY_UNSET.to_be_bytes()),
                Some(val) => {
                    let val_bytes = val.as_bytes();
                    f.update(&(val_bytes.len() as u64).to_be_bytes());
                    f.update(&val_bytes);
                }
            }

            f.finalize(&mut tmp);

            pre_h.update(&tmp);
        }

        pre_h.update(&self.timestamp.to_be_bytes());
        pre_h.finalize(&mut tmp);

        // This hash is superfluous in theory, but derive does not support incremental hashing.
        // As a practical considerion we use an extra hash here.
        Ok(<K as IBKEM>::Id::derive(&tmp))
    }
}

impl Attribute {
    /// Conveniently construct a new attribute. It is also possible to directly construct this object.
    pub fn new(atype: &str, value: Option<&str>) -> Result<Self, Error> {
        let atype = atype.to_owned();
        let value = value.map(|s| s.to_owned());
        Ok(Attribute { atype, value })
    }
}

#[cfg(test)]
mod tests {
    use ibe::kem::cgw_fo::CGWFO;

    use crate::test_common::TestSetup;

    #[test]
    fn test_ordering() {
        // Test that symantically equivalent policies map to the same IBE identity.
        let setup = TestSetup::default();

        let p1_derived = setup.policies[1].derive::<CGWFO>().unwrap();

        let mut reversed = setup.policies[1].clone();
        reversed.con.reverse();
        assert_eq!(&p1_derived, &reversed.derive::<CGWFO>().unwrap());

        // The timestamp should matter, and therefore map to a different IBE identity.
        reversed.timestamp += 1;
        assert_ne!(&p1_derived, &reversed.derive::<CGWFO>().unwrap());
    }
}
