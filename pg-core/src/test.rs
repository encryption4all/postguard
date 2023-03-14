//! Test helpers.

use crate::artifacts::{PublicKey, SigningKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use crate::identity::{Attribute, EncryptionPolicy, Policy};
use alloc::collections::BTreeMap;
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::IBKEM;
use ibs::gg::IDENTITY_BYTES as IBS_ID_BYTES;
use rand::{CryptoRng, Rng};

use alloc::string::String;

/// A test setup.
#[derive(Debug)]
pub struct TestSetup {
    /// The encryption public key.
    pub mpk: PublicKey<CGWKV>,
    /// An example encryption policy.
    pub policies: BTreeMap<String, Policy>,
    /// Users and their associated usk.
    pub usks: BTreeMap<String, UserSecretKey<CGWKV>>,
    /// The IBS public key.
    pub ibs_pk: VerifyingKey,
    /// Users and their associated signing keys.
    pub signing_keys: BTreeMap<String, SigningKeyExt>,
}

impl TestSetup {
    /// Create a new test setup.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let (ibe_pk, ibe_msk) = ibe::kem::cgw_kv::CGWKV::setup(rng);
        let (ibs_pk, ibs_sk) = ibs::gg::setup(rng);

        let ibe_pk = PublicKey::<CGWKV>(ibe_pk);
        let ibs_pk = VerifyingKey(ibs_pk);

        let id1 = String::from("Alice");
        let id2 = String::from("Bob");
        let id3 = String::from("Charlie");

        let p1 = Policy {
            timestamp: 1566722350,
            con: vec![Attribute::new(
                "pbdf.gemeente.personalData.bsn",
                Some("<Alice's social security number>"),
            )],
        };

        let p2 = Policy {
            timestamp: 1566722350,
            con: vec![
                Attribute::new("pbdf.gemeente.personalData.name", Some("Bob")),
                Attribute::new("pbdf.sidn-pbdf.email.email", Some("bob@example.com")),
            ],
        };

        let p3 = Policy {
            timestamp: 1566722350,
            con: vec![
                Attribute::new("pbdf.gemeente.personalData.name", Some("Charlie")),
                Attribute::new("pbdf.sidn-pbdf.email.email", Some("charlie@example.com")),
            ],
        };

        let policies = EncryptionPolicy::from([(id1, p1), (id2, p2), (id3, p3)]);

        let usks = policies
            .iter()
            .map(|(id, pol)| {
                let derived = pol.derive_kem::<CGWKV>().unwrap();
                let usk =
                    UserSecretKey(CGWKV::extract_usk(Some(&ibe_pk.0), &ibe_msk, &derived, rng));
                (id.clone(), usk)
            })
            .collect();

        let signing_keys: BTreeMap<String, SigningKeyExt> = policies
            .iter()
            .map(|(id, pol)| {
                let derived = ibs::gg::Identity::from(pol.derive::<IBS_ID_BYTES>().unwrap());
                let signing_key = ibs::gg::keygen(&ibs_sk, &derived, rng);
                let key = SigningKeyExt {
                    key: SigningKey(signing_key),
                    policy: pol.clone(),
                };
                (id.clone(), key)
            })
            .collect();

        TestSetup {
            mpk: ibe_pk,
            policies,
            usks,
            ibs_pk,
            signing_keys,
        }
    }
}
