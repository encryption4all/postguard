use crate::artifacts::{PublicKey, UserSecretKey};
use crate::identity::{Attribute, EncryptionPolicy, Policy};
use alloc::collections::BTreeMap;
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::IBKEM;
use rand::{CryptoRng, Rng};

#[derive(Debug)]
pub struct TestSetup {
    pub mpk: PublicKey<CGWKV>,
    pub policy: EncryptionPolicy,
    pub usks: BTreeMap<String, UserSecretKey<CGWKV>>,
}

impl TestSetup {
    /// Create a new test setup.
    pub fn new<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let id1 = String::from("j.doe@example.com");
        let id2 = String::from("john.doe@example.com");

        let p1 = Policy {
            timestamp: 1566722350,
            con: vec![Attribute::new(
                "pbdf.gemeente.personalData.bsn",
                Some("123456789"),
            )],
        };
        let p2 = Policy {
            timestamp: 1566722350,
            con: vec![
                Attribute::new("pbdf.gemeente.personalData.name", Some("john")),
                Attribute::new("pbdf.sidn-pbdf.email.email", Some("john.doe@example.com")),
            ],
        };

        let policies = EncryptionPolicy::from([(id1, p1), (id2, p2)]);

        let (tmpk, msk) = ibe::kem::cgw_kv::CGWKV::setup(rng);
        let mpk = PublicKey::<CGWKV>(tmpk);

        let usks = policies
            .iter()
            .map(|(id, pol)| {
                let derived = pol.derive_kem::<CGWKV>().unwrap();
                let usk = UserSecretKey(CGWKV::extract_usk(Some(&mpk.0), &msk, &derived, rng));
                (id.clone(), usk)
            })
            .collect();

        TestSetup {
            mpk,
            policy: policies,
            usks,
        }
    }
}
