//! Test helpers.

use crate::artifacts::{PublicKey, SigningKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use crate::identity::{Attribute, EncryptionPolicy, Policy};
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::IBKEM;
use rand::{CryptoRng, Rng};

use alloc::string::String;
use alloc::vec::Vec;

/// A test setup.
#[derive(Debug)]
pub struct TestSetup {
    /// The encryption public key.
    pub ibe_pk: PublicKey<CGWKV>,

    /// The IBS public key.
    pub ibs_pk: VerifyingKey,

    /// All policies.
    pub policies: Vec<Policy>,

    /// Associated USKs for all policies.
    pub usks: Vec<UserSecretKey<CGWKV>>,

    /// Associated signing keys for all policies.
    pub signing_keys: Vec<SigningKeyExt>,

    /// An example encryption policy.
    pub policy: EncryptionPolicy,
}

impl TestSetup {
    /// Create a new test setup.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let (ibe_pk, ibe_msk) = ibe::kem::cgw_kv::CGWKV::setup(rng);
        let (ibs_pk, ibs_sk) = ibs::gg::setup(rng);

        let ibe_pk = PublicKey::<CGWKV>(ibe_pk);
        let ibs_pk = VerifyingKey(ibs_pk);

        // Some recipient identifiers.
        let id2 = String::from("Bob");
        let id3 = String::from("Charlie");

        // Some example policies.
        let policies = vec![
            // Alice just email
            Policy {
                timestamp: 1566722350,
                con: vec![Attribute::new(
                    "pbdf.sidn-pbdf.email.email",
                    Some("alice@example.com"),
                )],
            }, // Alice just BSN
            Policy {
                timestamp: 1566722350,
                con: vec![Attribute::new(
                    "pbdf.gemeente.personalData.bsn",
                    Some("<Alice's social security number>"),
                )],
            }, // Bob name + email
            Policy {
                timestamp: 1566722350,
                con: vec![
                    Attribute::new("pbdf.gemeente.personalData.name", Some("Bob")),
                    Attribute::new("pbdf.sidn-pbdf.email.email", Some("bob@example.com")),
                ],
            }, // Charlie name + email
            Policy {
                timestamp: 1566722350,
                con: vec![
                    Attribute::new("pbdf.gemeente.personalData.name", Some("Charlie")),
                    Attribute::new("pbdf.sidn-pbdf.email.email", Some("charlie@example.com")),
                ],
            }, // Charlie just name
            Policy {
                timestamp: 1566722350,
                con: vec![Attribute::new(
                    "pbdf.gemeente.personalData.name",
                    Some("Charlie"),
                )],
            },
        ];

        // Encrypts for Bob (email + name) and Charlie (email + name).
        let policy =
            EncryptionPolicy::from([(id2, policies[2].clone()), (id3, policies[3].clone())]);

        // Make USKs (decryption) for all policies.
        let usks = policies
            .iter()
            .map(|pol| {
                let derived = pol.derive_kem::<CGWKV>().unwrap();
                let usk = CGWKV::extract_usk(Some(&ibe_pk.0), &ibe_msk, &derived, rng);
                UserSecretKey::<CGWKV>(usk)
            })
            .collect();

        // Also make signing keys for all policies.
        let signing_keys = policies
            .iter()
            .map(|pol| {
                let derived = pol.derive_ibs().unwrap();
                let signing_key = ibs::gg::keygen(&ibs_sk, &derived, rng);

                SigningKeyExt {
                    key: SigningKey(signing_key),
                    policy: pol.clone(),
                }
            })
            .collect();

        TestSetup {
            ibe_pk,
            ibs_pk,
            policies,
            usks,
            signing_keys,
            policy,
        }
    }
}
