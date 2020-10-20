use crate::stream::*;
use crate::util::SliceReader;
use crate::*;

use arrayvec::ArrayVec;
use arrayvec::ArrayString;
use rand::RngCore;
use serde_json;

type BigBuf = ArrayVec<[u8; 65536]>;
type StrBuf = ArrayString<[u8; 256]>;

struct DefaultProps {
    pub i: Identity,
    pub data_type: StrBuf,
    pub data_metadata: serde_json::Value,
    pub pk: ibe::kiltz_vahlis_one::PublicKey,
    pub sk: ibe::kiltz_vahlis_one::SecretKey,
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

        let data_type = StrBuf::from("test data").unwrap();
        let data_metadata = serde_json::json!({ "an": "object" });

        let (pk, sk) = ibe::kiltz_vahlis_one::setup(&mut rng);

        DefaultProps { i, data_type, data_metadata, pk, sk }
    }
}

fn seal(props: &DefaultProps, content: &[u8]) -> BigBuf {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, data_type: _, data_metadata: _, pk, sk: _ } = props;

    let mut buf = BigBuf::new();
    {
        let mut s = Sealer::new("test_data", serde_json::Value::Null, &i, &PublicKey(pk.clone()), &mut rng, &mut buf).unwrap();
        s.write(&content).unwrap();
    } // Force Drop of s.

    buf
}

fn unseal(props: &DefaultProps, buf: &[u8]) -> (BigBuf, bool) {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, data_type: _, data_metadata: _, pk, sk } = props;

    let bufr = SliceReader::new(&buf);
    let o = OpenerSealed::new(bufr).unwrap();
    let m = &o.metadata.clone();
    let i2 = &o.metadata.identity;

    assert_eq!(&i, &i2);

    let usk = ibe::kiltz_vahlis_one::extract_usk(&pk, &sk, &i2.derive().unwrap(), &mut rng);

    let mut o2 = o.unseal(&UserSecretKey(usk)).unwrap();
    let m2 = &o2.metadata.clone();

    assert_eq!(&m, &m2);

    let mut dst = BigBuf::new();
    o2.write_to(&mut dst).unwrap();

    (dst, o2.validate())
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
    let mut props = DefaultProps::default();

    // Do test with additional metadata
    do_test(&props, &mut [0u8; 0]);
    do_test(&props, &mut [0u8; 1]);
    do_test(&props, &mut [0u8; 511]);
    do_test(&props, &mut [0u8; 512]);
    do_test(&props, &mut [0u8; 1008]);
    do_test(&props, &mut [0u8; 1023]);
    do_test(&props, &mut [0u8; 60000]);

    // Do test without additional metadata  
    props.data_metadata = serde_json::json!(null);
    do_test(&props, &mut [0u8; 1008]);
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
fn corrupt_hmac() {
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
