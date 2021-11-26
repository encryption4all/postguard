use crate::{Attribute, Policy, PublicKey, RecipientIdentifier, UserSecretKey};
use ibe::kem::cgw_fo::CGWFO;
use ibe::kem::IBKEM;

pub struct TestSetup {
    pub mpk: PublicKey<CGWFO>,
    pub identifiers: [RecipientIdentifier; 2],
    pub policies: [Policy; 2],
    pub usks: [UserSecretKey<CGWFO>; 2],
}

impl Default for TestSetup {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        let identifier1 = RecipientIdentifier::from("l.botros@cs.ru.nl");
        let identifier2 = RecipientIdentifier::from("leon.botros@gmail.com");

        let p1 = Policy {
            timestamp: 1566722350,
            con: vec![Attribute::new("pbdf.gemeente.personalData.bsn", Some("123456789")).unwrap()],
        };
        let p2 = Policy {
            timestamp: 1566722350,
            con: vec![
                Attribute::new("pbdf.gemeente.personalData.name", Some("leon")).unwrap(),
                Attribute::new("pbdf.sidn-pbdf.email.email", Some("leon.botros@gmail.com"))
                    .unwrap(),
            ],
        };

        let identifiers = [identifier1, identifier2];
        let policies = [p1, p2];

        let (tmpk, msk) = ibe::kem::cgw_fo::CGWFO::setup(&mut rng);
        let mpk = PublicKey::<CGWFO>(tmpk);

        // Extract associated user secret keys
        let derived_0 = policies[0].derive().unwrap();
        let usk_0 = UserSecretKey(CGWFO::extract_usk(Some(&mpk.0), &msk, &derived_0, &mut rng));

        let derived_1 = policies[1].derive().unwrap();
        let usk_1 = UserSecretKey(CGWFO::extract_usk(Some(&mpk.0), &msk, &derived_1, &mut rng));

        let usks = [usk_0, usk_1];

        TestSetup {
            mpk,
            identifiers,
            policies,
            usks,
        }
    }
}
