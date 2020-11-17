use crate::stream::*;
use crate::*;

use arrayvec::ArrayVec;
use futures::executor::block_on;
use rand::RngCore;

type BigBuf = ArrayVec<[u8; 65536]>;

struct DefaultProps {
    pub i: Identity,
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

        let (pk, sk) = ibe::kiltz_vahlis_one::setup(&mut rng);

        DefaultProps { i, pk, sk }
    }
}

async fn seal<'a>(props: &DefaultProps, content: &[u8]) -> BigBuf {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk: _ } = props;

    let mut buf_writer = IntoAsyncWrite::from(BigBuf::new());

    let mut s = Sealer::new(i.clone(), &PublicKey(pk.clone()), &mut rng, &mut buf_writer)
        .await
        .unwrap();
    s.seal(content).await.unwrap();

    buf_writer.into_inner()
}

async fn unseal(props: &DefaultProps, buf: &[u8]) -> (BigBuf, bool) {
    let mut rng = rand::thread_rng();
    let DefaultProps { i, pk, sk } = props;

    let (m, o) = OpenerSealed::new(buf).await.unwrap();
    let i2 = &m.identity;

    assert_eq!(&i, &i2);

    let usk = ibe::kiltz_vahlis_one::extract_usk(&pk, &sk, &i2.derive().unwrap(), &mut rng);
    let mut dst = IntoAsyncWrite::from(BigBuf::new());
    let validated = o.unseal(&m, &UserSecretKey(usk), &mut dst).await.unwrap();

    (dst.into_inner(), validated)
}

async fn seal_and_unseal(props: &DefaultProps, content: &[u8]) -> (BigBuf, bool) {
    let buf = seal(props, content).await;
    unseal(props, &buf).await
}

fn do_test(props: &DefaultProps, content: &mut [u8]) {
    rand::thread_rng().fill_bytes(content);
    let (dst, valid) = block_on(seal_and_unseal(props, content));

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

    block_on(async {
        let mut buf = seal(&props, &content).await;
        buf[1000] += 0x02;
        let (dst, valid) = unseal(&props, &buf).await;

        assert_ne!(&content.as_ref(), &dst.as_slice());
        assert!(!valid);
    })
}

#[test]
fn corrupt_hmac() {
    let props = DefaultProps::default();

    let mut content = [0u8; 60000];
    rand::thread_rng().fill_bytes(&mut content);

    block_on(async {
        let mut buf = seal(&props, &content).await;
        let mutation_point = buf.len() - 5;
        buf[mutation_point] += 0x02;
        let (dst, valid) = unseal(&props, &buf).await;

        assert_eq!(&content.as_ref(), &dst.as_slice());
        assert!(!valid);
    })
}
