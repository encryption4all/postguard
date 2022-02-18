use crate::{Attribute, Policy, PublicKey, UserSecretKey};
use ibe::kem::cgw_kv::CGWKV;
use ibe::kem::IBKEM;
use std::collections::BTreeMap;

pub struct TestSetup {
    pub mpk: PublicKey<CGWKV>,
    pub policies: BTreeMap<String, Policy>,
    pub usks: BTreeMap<String, UserSecretKey<CGWKV>>,
}

impl Default for TestSetup {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        let id1 = String::from("l.botros@cs.ru.nl");
        let id2 = String::from("leon.botros@gmail.com");

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
                Attribute::new("pbdf.gemeente.personalData.name", Some("leon")),
                Attribute::new("pbdf.sidn-pbdf.email.email", Some("leon.botros@gmail.com")),
            ],
        };

        let policies = BTreeMap::<String, Policy>::from([(id1, p1), (id2, p2)]);

        let (tmpk, msk) = ibe::kem::cgw_kv::CGWKV::setup(&mut rng);
        let mpk = PublicKey::<CGWKV>(tmpk);

        let usks = policies
            .iter()
            .map(|(id, pol)| {
                let derived = pol.derive::<CGWKV>().unwrap();
                let usk = UserSecretKey(CGWKV::extract_usk(Some(&mpk.0), &msk, &derived, &mut rng));
                (id.clone(), usk)
            })
            .collect();

        TestSetup {
            mpk,
            policies,
            usks,
        }
    }
}
