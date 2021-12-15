use crate::{Attribute, Policy, PublicKey, UserSecretKey};
use ibe::kem::cgw_fo::CGWFO;
use ibe::kem::IBKEM;
use std::collections::BTreeMap;

pub struct TestSetup {
    pub mpk: PublicKey<CGWFO>,
    pub policies: BTreeMap<String, Policy>,
    pub usks: BTreeMap<String, UserSecretKey<CGWFO>>,
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

        let policies = BTreeMap::<String, Policy>::from([(id1.clone(), p1), (id2.clone(), p2)]);

        let (tmpk, msk) = ibe::kem::cgw_fo::CGWFO::setup(&mut rng);
        let mpk = PublicKey::<CGWFO>(tmpk);

        let usks = policies
            .iter()
            .map(|(id, pol)| {
                let derived = pol.derive::<CGWFO>().unwrap();
                let usk = UserSecretKey(CGWFO::extract_usk(Some(&mpk.0), &msk, &derived, &mut rng));
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
