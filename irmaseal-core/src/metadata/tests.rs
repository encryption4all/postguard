use crate::metadata::*;

use crate::util::generate_iv;
use crate::Attribute;

macro_rules! setup {
    ($ma: ident) => {
        let mut rng = rand::thread_rng();
        let identifier1 = RecipientIdentifier::new("l.botros@cs.ru.nl").unwrap();
        let identifier2 = RecipientIdentifier::new("leon.botros@gmail.com").unwrap();

        let p1 = HiddenPolicy {
            timestamp: 1566722350,
            con: vec![Attribute::new("pbdf.gemeente.personalData.bsn", Some("*****1234")).unwrap()],
        };
        let p2 = HiddenPolicy {
            timestamp: 1566722350,
            con: vec![Attribute::new("pbdf.gemeente.personalData.bsn", Some("*****1234")).unwrap()],
        };

        let list = [(identifier1, p1.clone()), (identifier2, p2.clone())];
        let c = Policies(&list);
        let iv = generate_iv(&mut rng);

        let $ma = MetadataArgs {
            recipients: c,
            iv,
            chunk_size: 1024 * 1024,
        };
    };
}

#[test]
fn test_enc_dec_json() {
    setup!(ma);
    let id2 = &ma.recipients.0[1].0.clone();
    let policy2 = &ma.recipients.0[1].1.clone();

    let s = ma.write_to_json_string().unwrap();
    println!("encoded: {}", &s);

    // Decode string, while looking for id2
    let decoded = RecipientMetadata::from_string(&s, id2).unwrap();
    println!("decoded: {:?}", &decoded);

    assert_eq!(&decoded.recipient_info.identifier, id2);
    assert_eq!(&decoded.recipient_info.policy, policy2);
    assert_eq!(&decoded.iv, &ma.iv);
    assert_eq!(&decoded.chunk_size, &ma.chunk_size);
}

#[test]
fn test_enc_dec_msgpack() {
    setup!(ma);

    let id2 = &ma.recipients.0[1].0.clone();
    let policy2 = &ma.recipients.0[1].1.clone();

    let mut v = Vec::new();
    ma.msgpack_write_into(&mut v).unwrap();
    //dbg!(&v);
    println!("output is {} bytes", v.len());

    let decoded = RecipientMetadata::msgpack_from_slice(&v[..], &id2).unwrap();
    //dbg!(&decoded);

    assert_eq!(&decoded.recipient_info.identifier, id2);
    assert_eq!(&decoded.recipient_info.policy, policy2);
    assert_eq!(&decoded.iv, &ma.iv);
    assert_eq!(&decoded.chunk_size, &ma.chunk_size);
}

#[test]
fn test_transcode() {
    setup!(ma);

    // encode to binary via msgpack and transcode into json
    let mut v = Vec::new();
    let mut out = Vec::new();

    ma.msgpack_write_into(&mut v).unwrap();
    let mut des = rmp_serde::decode::Deserializer::from_read_ref(&v);
    let mut ser = serde_json::Serializer::pretty(&mut out);

    serde_transcode::transcode(&mut des, &mut ser).unwrap();
}
