use crate::artifacts::{PublicKey, UserSecretKey};
use crate::identity::{Attribute, Policy, RecipientPolicy};
use alloc::collections::BTreeMap;
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::IBKEM;

#[derive(Debug)]
pub struct TestSetup {
    pub mpk: PublicKey<CGWKV>,
    pub policy: Policy,
    pub usks: BTreeMap<String, UserSecretKey<CGWKV>>,
}

impl Default for TestSetup {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        let id1 = String::from("j.doe@example.com");
        let id2 = String::from("john.doe@example.com");

        let p1 = RecipientPolicy {
            timestamp: 1566722350,
            con: vec![Attribute::new(
                "pbdf.gemeente.personalData.bsn",
                Some("123456789"),
            )],
        };
        let p2 = RecipientPolicy {
            timestamp: 1566722350,
            con: vec![
                Attribute::new("pbdf.gemeente.personalData.name", Some("john")),
                Attribute::new("pbdf.sidn-pbdf.email.email", Some("john.doe@example.com")),
            ],
        };

        let policies = Policy::from([(id1, p1), (id2, p2)]);

        let (tmpk, msk) = ibe::kem::cgw_kv::CGWKV::setup(&mut rng);
        let mpk = PublicKey::<CGWKV>(tmpk);

        let usks = policies
            .iter()
            .map(|(id, pol)| {
                let derived = pol.derive_kem::<CGWKV>().unwrap();
                let usk = UserSecretKey(CGWKV::extract_usk(Some(&mpk.0), &msk, &derived, &mut rng));
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
