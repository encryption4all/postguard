use crate::stream::util::SliceReader;
use crate::stream::*;
use crate::*;

use arrayvec::ArrayVec;
use rand::RngCore;

use ibe::kem::{cgw_fo::CGWFO, IBKEM};

type BigBuf = ArrayVec<u8, 65536>;

struct DefaultProps {
    pub i: Identity,
    pub pk: <CGWFO as IBKEM>::Pk,
    pub sk: <CGWFO as IBKEM>::Sk,
}

impl Default for DefaultProps {
    fn default() -> DefaultProps {
        let mut rng = rand::thread_rng();
        let i = Identity::new(
            1566722350,
            "pbdf.pbdf.email.email",
            Some("w.geraedts@sarif.nl"),
        )
        .unwrap();

        let (pk, sk) = CGWFO::setup(&mut rng);

        DefaultProps { i, pk, sk }
    }
}

fn seal(props: &DefaultProps, content: &[u8]) -> BigBuf {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk: _ } = props;

    let mut buf = BigBuf::new();
    {
        let mut s = Sealer::new(i.clone(), &PublicKey(pk.clone()), &mut rng, &mut buf).unwrap();
        s.write(&content).unwrap();
    } // Force Drop of s.
    buf
}

fn unseal(props: &DefaultProps, buf: &[u8]) -> (BigBuf, bool) {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk } = props;

    let mut mr = MetadataReader::new();
    let mut mrr = None;

    let mut written = 0;
    for b in buf {
        written += 1;
        match mr.write(&[*b]).unwrap() {
            MetadataReaderResult::Hungry => continue,
            MetadataReaderResult::Saturated {
                unconsumed,
                header,
                metadata,
                version: v,
            } => {
                assert_eq!(unconsumed, 0);
                assert_eq!(v, VERSION_V2);
                mrr = Some((header, metadata));
                break;
            }
        }
    }

    let (header, metadata) = mrr.unwrap();

    let i2 = match metadata {
        #[cfg(feature = "v1")]
        Metadata::V1(ref x) => &x.identity,
        Metadata::V2(ref x) => &x.identity,
    };

    assert_eq!(&i, &i2);
    let usk = UserSecretKey(CGWFO::extract_usk(
        Some(&pk),
        &sk,
        &i2.derive::<CGWFO>().unwrap(),
        &mut rng,
    ));

    let pk = PublicKey(*pk);

    let bufr = SliceReader::new(&buf[written..]);
    if let Metadata::V2(m) = metadata {
        let mut unsealer = Unsealer::new_v2(&m, header, &usk, &pk, bufr).unwrap();
        let mut dst = BigBuf::new();
        unsealer.write_to(&mut dst).unwrap();

        (dst, unsealer.validate())
    } else {
        // this else is required when feature "v1" is enabled
        panic!("Should be v2")
    }
}

fn seal_and_unseal(props: &DefaultProps, content: &[u8]) -> (BigBuf, bool) {
    let buf = seal(props, content);
    unseal(props, &buf)
}

fn do_test(props: &DefaultProps, content: &mut [u8]) {
    rand::thread_rng().fill_bytes(content);
    let (dst, valid) = seal_and_unseal(props, content);

    assert_eq!(&content.as_ref(), &dst.as_slice());
    assert!(valid);
}

#[test]
fn reflection_sealer_opener() {
    let props = DefaultProps::default();

    do_test(&props, &mut [0u8; 0]);
    do_test(&props, &mut [0u8; 1]);
    do_test(&props, &mut [0u8; 511]);
    do_test(&props, &mut [0u8; 512]);
    do_test(&props, &mut [0u8; 1008]);
    do_test(&props, &mut [0u8; 1023]);
    do_test(&props, &mut [0u8; 60000]);
}

#[test]
fn corrupt_body() {
    let props = DefaultProps::default();

    let mut content = [0u8; 60000];
    rand::thread_rng().fill_bytes(&mut content);

    let mut buf = seal(&props, &content);
    buf[1000] += 0x02;
    let (dst, valid) = unseal(&props, &buf);

    assert_ne!(&content.as_ref(), &dst.as_slice());
    assert!(!valid);
}

#[test]
fn corrupt_mac() {
    let props = DefaultProps::default();

    let mut content = [0u8; 60000];
    rand::thread_rng().fill_bytes(&mut content);

    let mut buf = seal(&props, &content);
    let mutation_point = buf.len() - 5;
    buf[mutation_point] += 0x02;
    let (dst, valid) = unseal(&props, &buf);

    assert_eq!(&content.as_ref(), &dst.as_slice());
    assert!(!valid);
}
