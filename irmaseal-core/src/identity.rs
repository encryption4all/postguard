//! Identity definitions and utilities.

use crate::error::Error;
use alloc::collections::BTreeMap;
use ibe::kem::IBKEM;
use ibe::Derive;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3, Shake};

const IDENTITY_UNSET: u64 = u64::MAX;
const MAX_CON: usize = (IDENTITY_UNSET as usize - 1) >> 1;
const AMOUNT_CHARS_TO_HIDE: usize = 4;
const HINT_TYPES: &[&str] = &[
    "pbdf.sidn-pbdf.mobilenumber.mobilenumber",
    "pbdf.pbdf.surfnet-2.id",
    "pbdf.nuts.agb.agbcode",
    "irma-demo.sidn-pbdf.mobilenumber.mobilenumber",
    "irma-demo.nuts.agb.agbcode",
];

/// The complete encryption policy for all recipients.
pub type Policy = BTreeMap<String, RecipientPolicy>;

/// An IRMAseal AttributeRequest, which is a simple case of an IRMA ConDisCon.
#[derive(Serialize, Deserialize, Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Default)]
pub struct Attribute {
    #[serde(rename = "t")]
    /// Attribute type.
    pub atype: String,

    /// Attribute value.
    #[serde(rename = "v")]
    pub value: Option<String>,
}

/// An IRMAseal policy used to encapsulate a shared secret for one recipient.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct RecipientPolicy {
    /// Timestamp (UNIX time).
    #[serde(rename = "ts")]
    pub timestamp: u64,

    /// A conjunction of attributes.
    pub con: Vec<Attribute>,
}

/// An IRMAseal hidden policy.
///
/// A policy where (part of) the value of the attributes is hidden.
/// This type is safe for usage in (public) [Header][`crate::Header`] alongside the ciphertext.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct HiddenRecipientPolicy {
    /// Timestamp (UNIX time).
    #[serde(rename = "ts")]
    pub timestamp: u64,

    /// A conjunction of attributes, with redacted values.
    pub con: Vec<Attribute>,
}

impl Attribute {
    fn hintify_value(&self) -> Attribute {
        let hidden_value = self.value.as_ref().map(|v| {
            if HINT_TYPES.contains(&&self.atype[..]) {
                let (begin, end) = v.split_at(v.len().saturating_sub(AMOUNT_CHARS_TO_HIDE));
                format!("{begin}{}", "*".repeat(end.len()))
            } else {
                "".to_string()
            }
        });

        Attribute {
            atype: self.atype.clone(),
            value: hidden_value,
        }
    }
}

impl RecipientPolicy {
    /// Completely hides the attribute value, or provides a hint for certain attribute types
    pub fn to_hidden(&self) -> HiddenRecipientPolicy {
        HiddenRecipientPolicy {
            timestamp: self.timestamp,
            con: self.con.iter().map(Attribute::hintify_value).collect(),
        }
    }

    /// Derives an N-byte identity from a [`Policy`].
    pub fn derive<const N: usize>(&self) -> Result<[u8; N], Error> {
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
            return Err(Error::ConstraintViolation);
        }

        let mut tmp = [0u8; 64];
        let mut pre_h = Shake::v256();

        // 0 indicates the IRMA authentication method.
        pre_h.update(&[0x00]);

        let mut copy = self.con.clone();
        copy.sort();

        for (i, ar) in copy.iter().enumerate() {
            let mut f = Sha3::v512();

            f.update(&((2 * i + 1) as u64).to_be_bytes());
            let at_bytes = ar.atype.as_bytes();
            f.update(&(at_bytes.len() as u64).to_be_bytes());
            f.update(at_bytes);
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
                    f.update(val_bytes);
                }
            }

            f.finalize(&mut tmp);
            pre_h.update(&tmp);
        }

        pre_h.update(&self.timestamp.to_be_bytes());
        let mut res = [0u8; N];
        pre_h.finalize(&mut res);

        Ok(res)
    }

    /// Derive a KEMs associated identity from a [`Policy`].
    pub fn derive_kem<K: IBKEM>(&self) -> Result<<K as IBKEM>::Id, Error> {
        // This hash is superfluous in theory, but derive does not support incremental hashing.
        // As a practical considerion we use an extra hash here.
        Ok(<K as IBKEM>::Id::derive(&self.derive::<64>()?))
    }
}

impl Attribute {
    /// Construct a new attribute request.
    pub fn new(atype: &str, value: Option<&str>) -> Self {
        let atype = atype.to_string();
        let value = value.map(|s| s.to_owned());

        Attribute { atype, value }
    }
}

#[cfg(test)]
mod tests {
    use crate::identity::{Attribute, RecipientPolicy};
    use crate::test::TestSetup;
    use ibe::kem::cgw_kv::CGWKV;

    #[test]
    fn test_ordering() {
        // Test that symantically equivalent policies map to the same IBE identity.
        let setup = TestSetup::default();

        let policies: Vec<RecipientPolicy> = setup.policy.into_values().collect();
        let p1_derived = policies[1].derive_kem::<CGWKV>().unwrap();

        let mut reversed = policies[1].clone();
        reversed.con.reverse();
        assert_eq!(&p1_derived, &reversed.derive_kem::<CGWKV>().unwrap());

        // The timestamp should matter, and therefore map to a different IBE identity.
        reversed.timestamp += 1;
        assert_ne!(&p1_derived, &reversed.derive_kem::<CGWKV>().unwrap());
    }

    #[test]
    fn test_hints() {
        let attr = Attribute {
            atype: "pbdf.sidn-pbdf.mobilenumber.mobilenumber".to_string(),
            value: Some("123456789".to_string()),
        };
        let hinted = attr.hintify_value();
        assert_eq!(hinted.value, Some("12345****".to_string()));

        let attr_short = Attribute {
            atype: "pbdf.sidn-pbdf.mobilenumber.mobilenumber".to_string(),
            value: Some("123".to_string()),
        };
        let hinted_short = attr_short.hintify_value();
        assert_eq!(hinted_short.value, Some("***".to_string()));

        let attr_not_whitelisted = Attribute {
            atype: "pbdf.sidn-pbdf.mobilenumber.test".to_string(),
            value: Some("123456789".to_string()),
        };
        let hinted_empty = attr_not_whitelisted.hintify_value();
        assert_eq!(hinted_empty.value, Some("".to_string()));
    }
}
