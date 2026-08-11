//! Identity definitions and utilities.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use ibs::gg::Identity;

use crate::error::Error;
use ibe::kem::IBKEM;
use ibe::Derive;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Sha3};

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
pub type EncryptionPolicy = BTreeMap<String, Policy>;

/// A canonicalization rule for an attribute value.
///
/// The canonical form is not ours to choose: the PKG derives a user secret key
/// from the value Yivi discloses, so a sender's policy only decrypts when its
/// bytes match that disclosure exactly. These rules mirror the form Yivi
/// stores; they do not define it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// Trim surrounding whitespace and lowercase. Yivi stores email addresses
    /// in lower case, which is why a capitalized address fails to decrypt.
    Email,

    /// Remove grouping separators and map an international `00` prefix to `+`.
    /// Yivi stores mobile numbers in canonical E.164.
    Phone,
}

/// Attribute types carrying a canonicalization rule, keyed by the
/// credential-and-attribute *tail* of the type rather than the whole string, so
/// that every scheme — `pbdf.`, `irma-demo.` and any future one — matches the
/// same entry. Keying on full literals is how [`HINT_TYPES`] above ended up
/// covering `irma-demo` for mobile numbers but not for email.
const RULES: &[(&str, Rule)] = &[
    ("sidn-pbdf.email.email", Rule::Email),
    ("sidn-pbdf.mobilenumber.mobilenumber", Rule::Phone),
];

/// Characters used to group the digits of a written phone number.
const PHONE_SEPARATORS: &[char] = &[
    ' ', '\u{00a0}', '\u{202f}', '-', '\u{2011}', '\u{2013}', '(', ')', '.', '/',
];

/// The rule for an attribute type, if it has one.
fn rule_for(atype: &str) -> Option<Rule> {
    RULES.iter().find_map(|(tail, rule)| {
        let is_match = atype == *tail
            || (atype.len() > tail.len()
                && atype.ends_with(tail)
                && atype.as_bytes()[atype.len() - tail.len() - 1] == b'.');

        is_match.then_some(*rule)
    })
}

/// Canonicalizes an attribute value for the given attribute type.
///
/// Values of a type that carries no rule are returned unchanged. This function
/// is **total**: a value it cannot bring into canonical form is passed through
/// untouched rather than rejected, because the same rule runs on the PKG's side
/// over a Yivi disclosure, where a rejection would lock a recipient out of
/// their own message. A bare national phone number is the case that stays
/// unfixed — resolving it needs a country, which this crate does not have. Use
/// [`is_canonical`] to detect it and report it to the user.
///
/// The rule is idempotent: `canonicalize(t, canonicalize(t, v))` equals
/// `canonicalize(t, v)`.
///
/// ```
/// use pg_core::identity::canonicalize;
///
/// let t = "pbdf.sidn-pbdf.email.email";
/// assert_eq!(canonicalize(t, " Alice@Example.COM "), "alice@example.com");
///
/// let t = "pbdf.sidn-pbdf.mobilenumber.mobilenumber";
/// assert_eq!(canonicalize(t, "+31 6 1234 5678"), "+31612345678");
/// ```
pub fn canonicalize(atype: &str, value: &str) -> String {
    match rule_for(atype) {
        Some(Rule::Email) => value.trim().to_lowercase(),
        Some(Rule::Phone) => {
            // "+31 (0)6 ..." writes the national trunk prefix in parentheses,
            // and E.164 drops it. Remove the whole group before separators are
            // stripped: strip the parentheses first and the 0 survives into a
            // number that looks valid but dials nowhere.
            let value = value.replace("(0)", "");

            let compact: String = value
                .chars()
                .filter(|c| !PHONE_SEPARATORS.contains(c))
                .collect();

            match compact.strip_prefix("00") {
                Some(rest) => {
                    let mut e164 = String::with_capacity(rest.len() + 1);
                    e164.push('+');
                    e164.push_str(rest);
                    e164
                }
                None => compact,
            }
        }
        None => value.to_string(),
    }
}

/// Whether a value is already in the canonical form its attribute type expects.
///
/// Types without a rule are always canonical. For a phone number this is
/// stricter than "[`canonicalize`] would not change it": the result must also
/// be valid E.164, which is what lets a client reject the bare national number
/// that [`canonicalize`] cannot repair.
///
/// ```
/// use pg_core::identity::is_canonical;
///
/// let t = "pbdf.sidn-pbdf.mobilenumber.mobilenumber";
/// assert!(is_canonical(t, "+31612345678"));
/// assert!(!is_canonical(t, "0612345678")); // needs a country to resolve
/// ```
pub fn is_canonical(atype: &str, value: &str) -> bool {
    match rule_for(atype) {
        Some(Rule::Phone) => is_e164(value) && canonicalize(atype, value) == value,
        Some(_) => canonicalize(atype, value) == value,
        None => true,
    }
}

/// Whether a string is a valid E.164 number: `+`, a non-zero leading digit, and
/// 1 to 15 digits in total.
fn is_e164(value: &str) -> bool {
    let Some(digits) = value.strip_prefix('+') else {
        return false;
    };

    let len = digits.len();

    (1..=15).contains(&len)
        && !digits.starts_with('0')
        && digits.bytes().all(|b| b.is_ascii_digit())
}

/// A PostGuard IRMA attribute, which is a simple case of an IRMA ConDisCon.
#[derive(Serialize, Deserialize, Debug, Ord, PartialOrd, PartialEq, Eq, Clone, Default)]
pub struct Attribute {
    #[serde(rename = "t")]
    /// Attribute type.
    pub atype: String,

    /// Attribute value.
    #[serde(rename = "v")]
    pub value: Option<String>,
}

/// An PostGuard policy used to encapsulate a shared secret for one recipient.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct Policy {
    /// Timestamp (UNIX time).
    #[serde(rename = "ts")]
    pub timestamp: u64,

    /// A conjunction of attributes.
    pub con: Vec<Attribute>,
}

/// An PostGuard hidden policy.
///
/// A policy where (part of) the value of the attributes is hidden.
/// This type is safe for usage in (public) [Header][`crate::client::Header`] alongside the ciphertext.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct HiddenPolicy {
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

    /// Rewrites this attribute's value into the canonical form for its type.
    ///
    /// See [`canonicalize`] for what each type's rule does.
    pub fn canonicalize(&mut self) {
        if let Some(value) = &self.value {
            let canonical = canonicalize(&self.atype, value);

            if canonical != *value {
                self.value = Some(canonical);
            }
        }
    }
}

impl Policy {
    /// Rewrites every attribute value in this policy into its canonical form.
    ///
    /// See [`canonicalize`] for what each type's rule does.
    pub fn canonicalize(&mut self) {
        for attribute in &mut self.con {
            attribute.canonicalize();
        }
    }

    /// Returns a copy of this policy with every attribute value canonicalized.
    pub fn canonical(&self) -> Policy {
        let mut policy = self.clone();
        policy.canonicalize();

        policy
    }

    /// Completely hides the attribute value, or provides a hint for certain attribute types
    pub fn to_hidden(&self) -> HiddenPolicy {
        HiddenPolicy {
            timestamp: self.timestamp,
            con: self.con.iter().map(Attribute::hintify_value).collect(),
        }
    }

    /// Derives an 64-byte identity from a [`Policy`].
    ///
    /// Attribute values are canonicalized first (see [`canonicalize`]), so a
    /// sender who typed `Alice@Example.com` and a PKG holding Yivi's
    /// `alice@example.com` arrive at the same identity. Because both sides
    /// apply the same function, this only ever merges identities that used to
    /// differ — it cannot split one that already matched.
    pub fn derive(&self) -> Result<[u8; 64], Error> {
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
        let mut pre_h = Sha3::v512();

        // 0 indicates the IRMA authentication method.
        pre_h.update(&[0x00]);

        // Canonicalize before sorting: a rule can change a value, and therefore
        // the ordering. Doing this here rather than only at construction means
        // a policy assembled by hand, deserialized, or built by the PKG from a
        // Yivi disclosure derives the same identity as one the sealer wrote —
        // there is no construction site left to forget.
        let mut copy = self.con.clone();
        for ar in &mut copy {
            ar.canonicalize();
        }
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
        let mut res = [0u8; 64];
        pre_h.finalize(&mut res);

        Ok(res)
    }

    /// Derive a KEM identity from a [`Policy`].
    pub fn derive_kem<K: IBKEM>(&self) -> Result<<K as IBKEM>::Id, Error> {
        Ok(<K as IBKEM>::Id::derive(&self.derive()?))
    }

    /// Derive an IBS identity from a [`Policy`].
    pub fn derive_ibs(&self) -> Result<ibs::gg::Identity, Error> {
        Ok(Identity::from(&self.derive()?))
    }
}

impl Attribute {
    /// Construct a new attribute request.
    pub fn new(atype: &str, value: Option<&str>) -> Self {
        let atype = atype.to_string();
        let value = value.map(|s| s.to_string());

        Attribute { atype, value }
    }
}

#[cfg(test)]
mod tests {
    use crate::identity::{canonicalize, is_canonical, Attribute, Policy};
    use crate::test::TestSetup;
    use alloc::string::ToString;
    use alloc::vec::Vec;
    use ibe::kem::cgw_kv::CGWKV;

    const EMAIL: &str = "pbdf.sidn-pbdf.email.email";
    const PHONE: &str = "pbdf.sidn-pbdf.mobilenumber.mobilenumber";

    /// The canonicalization contract: `(attribute type, input, canonical form)`.
    ///
    /// Every row is also asserted to be idempotent. That property is
    /// load-bearing rather than incidental: the rule runs once when the sealer
    /// stores a policy and again when `derive` hashes it, so a rule that moved
    /// a value on the second application would break the very identities it
    /// exists to align.
    const VECTORS: &[(&str, &str, &str)] = &[
        // Email: trim, then lowercase. Yivi stores addresses in lower case.
        (EMAIL, "Alice@Example.COM", "alice@example.com"),
        (EMAIL, "  alice@example.com  ", "alice@example.com"),
        (EMAIL, "\u{00a0}Alice@Example.com\n", "alice@example.com"),
        (EMAIL, "alice@example.com", "alice@example.com"),
        // Email: the local part is lowercased too. RFC 5321 calls it
        // case-sensitive, but Yivi does not, and Yivi is what the PKG sees.
        (
            EMAIL,
            "AliceCarroll@example.com",
            "alicecarroll@example.com",
        ),
        // Phone: strip grouping separators, map an international 00 prefix.
        (PHONE, "+31 6 1234 5678", "+31612345678"),
        (PHONE, "+31-6-1234-5678", "+31612345678"),
        // The trunk-prefix group goes, rather than just its parentheses: a
        // surviving 0 yields "+310612345678", which passes an E.164 shape
        // check and dials nowhere.
        (PHONE, "+31 (0)6 12345678", "+31612345678"),
        (PHONE, "0031612345678", "+31612345678"),
        (PHONE, "+31612345678", "+31612345678"),
        // Phone: a bare national number needs a country to resolve, which this
        // crate does not have. It passes through untouched rather than being
        // rejected — `is_canonical` is what reports it.
        (PHONE, "0612345678", "0612345678"),
        (PHONE, "06 1234 5678", "0612345678"),
        // A type with no rule is never touched, whatever its value looks like.
        ("pbdf.gemeente.personalData.name", "Bob", "Bob"),
        ("pbdf.gemeente.personalData.name", "  Bob  ", "  Bob  "),
        ("test.test.email", "Alice@Example.COM", "Alice@Example.COM"),
    ];

    #[test]
    fn test_canonicalization_vectors() {
        for (atype, input, expected) in VECTORS {
            let once = canonicalize(atype, input);
            assert_eq!(&once, expected, "canonicalize({atype}, {input:?})");

            // Idempotence, asserted for every row rather than a chosen few.
            let twice = canonicalize(atype, &once);
            assert_eq!(twice, once, "canonicalize is not idempotent on {input:?}");
        }
    }

    #[test]
    fn test_canonicalization_matches_every_scheme() {
        // Keying on the type's tail is what makes the rule apply in irma-demo
        // and any future scheme, rather than only in the one someone remembered
        // to list. `HINT_TYPES` above is keyed on full literals and is missing
        // its irma-demo email row for exactly that reason.
        for scheme in ["pbdf", "irma-demo", "some-future-scheme"] {
            let atype = alloc::format!("{scheme}.sidn-pbdf.email.email");
            assert_eq!(
                canonicalize(&atype, "Alice@Example.COM"),
                "alice@example.com"
            );
        }

        // A tail match is not a substring match: the boundary must be a dot.
        assert_eq!(
            canonicalize("pbdf.notsidn-pbdf.email.email", "Alice@Example.COM"),
            "Alice@Example.COM"
        );
    }

    #[test]
    fn test_is_canonical() {
        // Types without a rule are canonical by definition.
        assert!(is_canonical("pbdf.gemeente.personalData.name", "  Bob  "));

        assert!(is_canonical(EMAIL, "alice@example.com"));
        assert!(!is_canonical(EMAIL, "Alice@Example.com"));

        // Phone is stricter than "canonicalize would not change it": a bare
        // national number is a fixed point of the rule but not valid E.164,
        // which is the case a client has to be able to report.
        assert!(is_canonical(PHONE, "+31612345678"));
        assert!(!is_canonical(PHONE, "0612345678"));
        assert_eq!(canonicalize(PHONE, "0612345678"), "0612345678");

        // E.164 bounds: at most 15 digits, no leading zero after the +.
        assert!(is_canonical(PHONE, "+123456789012345"));
        assert!(!is_canonical(PHONE, "+1234567890123456"));
        assert!(!is_canonical(PHONE, "+0612345678"));
        assert!(!is_canonical(PHONE, "+"));
        assert!(!is_canonical(PHONE, "31612345678"));
    }

    #[test]
    fn test_canonicalization_merges_identities_never_splits_them() {
        // The property the whole design rests on: because the sender and the
        // PKG apply the same function, canonicalization is a coarsening of
        // equality. Values that used to derive differently can now agree; two
        // values that already agreed cannot be pulled apart.
        let raw = Policy {
            timestamp: 1_700_000_000,
            con: alloc::vec![Attribute::new(EMAIL, Some("Alice@Example.COM"))],
        };
        let canonical = Policy {
            timestamp: 1_700_000_000,
            con: alloc::vec![Attribute::new(EMAIL, Some("alice@example.com"))],
        };

        assert_eq!(raw.derive().unwrap(), canonical.derive().unwrap());

        // An untouched type still separates what it always separated.
        let bob = Policy {
            timestamp: 1_700_000_000,
            con: alloc::vec![Attribute::new(
                "pbdf.gemeente.personalData.name",
                Some("Bob")
            )],
        };
        let bob_upper = Policy {
            timestamp: 1_700_000_000,
            con: alloc::vec![Attribute::new(
                "pbdf.gemeente.personalData.name",
                Some("BOB")
            )],
        };

        assert_ne!(bob.derive().unwrap(), bob_upper.derive().unwrap());
    }

    #[test]
    fn test_policy_canonicalization_reaches_the_wire() {
        // `derive` canonicalizing is not enough on its own: the policy the
        // sealer stores is what an older verifier reads, so the stored value
        // has to move too.
        let mut policy = Policy {
            timestamp: 1_700_000_000,
            con: alloc::vec![
                Attribute::new(EMAIL, Some(" Alice@Example.COM ")),
                Attribute::new(PHONE, Some("+31 6 1234 5678")),
            ],
        };
        policy.canonicalize();

        assert_eq!(policy.con[0].value.as_deref(), Some("alice@example.com"));
        assert_eq!(policy.con[1].value.as_deref(), Some("+31612345678"));

        // An attribute with no value is left alone rather than gaining one.
        let mut valueless = Policy {
            timestamp: 0,
            con: alloc::vec![Attribute::new(EMAIL, None)],
        };
        valueless.canonicalize();
        assert_eq!(valueless.con[0].value, None);
    }

    #[test]
    fn test_ordering() {
        let mut rng = rand::thread_rng();
        // Test that symantically equivalent policies map to the same IBE identity.
        let setup = TestSetup::new(&mut rng);

        let policies: Vec<Policy> = setup.policy.into_values().collect();
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

    #[test]
    fn test_regression() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        // Make sure that the policies in the TestSetup map to identical KEM/IBS identities.
        let kem_ids: [[u8; 64]; 5] = [
            [
                243, 215, 91, 185, 176, 144, 186, 190, 101, 135, 237, 186, 47, 183, 76, 243, 182,
                195, 213, 35, 18, 38, 203, 7, 53, 157, 78, 193, 99, 141, 169, 0, 13, 112, 111, 32,
                172, 75, 5, 106, 165, 47, 53, 111, 177, 2, 8, 107, 242, 252, 49, 241, 67, 229, 5,
                191, 13, 17, 246, 216, 119, 186, 227, 119,
            ],
            [
                245, 162, 197, 104, 15, 166, 248, 109, 79, 173, 252, 30, 92, 165, 193, 237, 255,
                228, 162, 5, 42, 227, 151, 207, 97, 134, 20, 41, 20, 142, 220, 5, 234, 222, 45,
                199, 163, 191, 112, 167, 52, 193, 120, 143, 245, 8, 24, 46, 8, 77, 183, 255, 32,
                196, 251, 247, 233, 114, 16, 114, 69, 19, 88, 105,
            ],
            [
                55, 240, 138, 50, 172, 20, 36, 194, 154, 137, 247, 125, 112, 215, 118, 219, 172,
                226, 21, 87, 116, 226, 44, 228, 62, 148, 86, 82, 119, 154, 209, 89, 219, 49, 115,
                130, 187, 57, 252, 108, 239, 118, 210, 165, 13, 53, 96, 200, 55, 211, 229, 32, 59,
                140, 234, 87, 124, 64, 128, 223, 6, 248, 172, 238,
            ],
            [
                224, 26, 15, 201, 109, 47, 252, 119, 219, 216, 15, 186, 65, 123, 47, 131, 130, 196,
                248, 145, 241, 235, 13, 216, 182, 74, 236, 81, 198, 67, 28, 7, 114, 158, 252, 90,
                123, 131, 138, 155, 56, 93, 46, 93, 160, 8, 72, 122, 193, 229, 123, 36, 69, 50,
                189, 38, 183, 208, 7, 102, 249, 33, 219, 46,
            ],
            [
                199, 241, 225, 34, 158, 92, 56, 128, 249, 122, 93, 192, 132, 106, 3, 247, 209, 109,
                66, 92, 203, 108, 184, 198, 208, 254, 255, 150, 116, 17, 225, 112, 114, 121, 189,
                231, 19, 215, 46, 246, 250, 211, 61, 254, 172, 44, 242, 18, 170, 49, 37, 56, 140,
                217, 127, 97, 247, 210, 224, 181, 220, 246, 126, 140,
            ],
        ];

        let ibs_ids: [[u8; 32]; 5] = [
            [
                180, 14, 93, 181, 36, 29, 110, 232, 226, 36, 52, 230, 202, 168, 128, 63, 18, 200,
                133, 234, 142, 171, 42, 130, 204, 102, 83, 232, 69, 19, 188, 40,
            ],
            [
                28, 98, 33, 83, 107, 211, 195, 182, 119, 220, 223, 113, 224, 225, 193, 22, 200,
                249, 124, 48, 182, 122, 0, 65, 241, 201, 164, 104, 236, 175, 50, 108,
            ],
            [
                254, 181, 235, 14, 113, 97, 93, 200, 45, 48, 184, 245, 237, 118, 89, 250, 199, 105,
                213, 208, 27, 41, 189, 166, 246, 1, 105, 163, 244, 239, 78, 122,
            ],
            [
                165, 205, 240, 238, 241, 135, 30, 175, 42, 99, 93, 112, 171, 40, 249, 246, 133,
                162, 228, 144, 133, 77, 246, 199, 134, 77, 78, 182, 224, 66, 111, 239,
            ],
            [
                22, 61, 147, 117, 0, 147, 225, 164, 134, 216, 244, 108, 165, 173, 205, 236, 24,
                185, 73, 128, 9, 95, 91, 162, 155, 120, 67, 252, 138, 112, 249, 217,
            ],
        ];

        for (p, (kem, ibs)) in setup
            .policies
            .iter()
            .zip(kem_ids.iter().zip(ibs_ids.iter()))
        {
            let kem2 = p.derive_kem::<CGWKV>().unwrap();
            let ibs2 = p.derive_ibs().unwrap();

            assert_eq!(&kem[..], &kem2.0);
            assert_eq!(&ibs::gg::Identity::from(&ibs), &ibs2);
        }
    }
}
