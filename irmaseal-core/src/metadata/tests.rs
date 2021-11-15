use crate::metadata::*;
use crate::Attribute;

use ibe::kem::IBKEM;

macro_rules! setup {
    ($rids: ident, $policies: ident, $mpk: ident, $msk: ident, $rng: ident) => {
        let mut $rng = rand::thread_rng();

        let identifier1 = RecipientIdentifier::new("l.botros@cs.ru.nl").unwrap();
        let identifier2 = RecipientIdentifier::new("leon.botros@gmail.com").unwrap();

        let p1 = Policy {
            timestamp: 1566722350,
            con: vec![Attribute::new("pbdf.gemeente.personalData.bsn", Some("123456789")).unwrap()],
        };
        let p2 = Policy {
            timestamp: 1566722350,
            con: vec![Attribute::new("pbdf.gemeente.personalData.name", Some("leon")).unwrap()],
        };

        let $rids = [&identifier1, &identifier2];
        let $policies = [&p1, &p2];

        let (tmpk, $msk) = ibe::kem::cgw_fo::CGWFO::setup(&mut $rng);
        let $mpk = PublicKey::<CGWFO>(tmpk);
    };
}

#[test]
fn test_enc_dec_json() {
    setup!(rids, policies, mpk, _msk, rng);

    let (meta, _ss) = Metadata::new(&mpk, &rids, &policies, &mut rng).unwrap();

    let s = meta.to_json_string().unwrap();
    println!("encoded: {}", &s);

    // Decode string, while looking for id2
    let decoded = RecipientMetadata::from_string(&s, rids[1]).unwrap();
    dbg!(&decoded);

    assert_eq!(&decoded.recipient_info.identifier, rids[1]);
    assert_eq!(&decoded.iv, &meta.iv);
    assert_eq!(&decoded.chunk_size, &meta.chunk_size);
}

#[test]
fn test_enc_dec_msgpack() {
    use std::io::Cursor;
    setup!(rids, policies, mpk, _msk, rng);

    let (meta, _ss) = Metadata::new(&mpk, &rids, &policies, &mut rng).unwrap();

    let mut v = Vec::new();
    meta.msgpack_into(&mut v).unwrap();

    println!("output is {} bytes", v.len());

    let mut c = Cursor::new(v);
    let decoded = RecipientMetadata::msgpack_from(&mut c, &rids[1]).unwrap();

    assert_eq!(&decoded.recipient_info.identifier, rids[1]);
    assert_eq!(&decoded.iv, &meta.iv);
    assert_eq!(&decoded.chunk_size, &meta.chunk_size);
}

#[test]
fn test_transcode() {
    use crate::PREAMBLE_SIZE;
    use std::io::Cursor;

    // This test encodes to binary and then transcodes into serde_json
    // The transcoded data is compared with a direct serialization of the same metadata.
    setup!(rids, policies, mpk, _msk, rng);

    let (meta, _ss) = Metadata::new(&mpk, &rids, &policies, &mut rng).unwrap();

    let mut binary = Vec::new();
    meta.msgpack_into(&mut binary).unwrap();

    let v1 = serde_json::to_vec(&meta).unwrap();
    let mut v2 = Vec::new();

    // Be sure to skip the preamble when transcoding
    let mut des = rmp_serde::decode::Deserializer::new(&binary[PREAMBLE_SIZE..]);
    let mut ser = serde_json::Serializer::new(Cursor::new(&mut v2));

    serde_transcode::transcode(&mut des, &mut ser).unwrap();

    assert_eq!(&v1, &v2);
}

#[test]
// This test tests that both encoding methods derive the same keys as the sender.
fn test_round() {
    use crate::util::derive_keys;
    use std::io::Cursor;

    setup!(rids, policies, mpk, msk, rng);

    let (meta, ss) = Metadata::new(&mpk, &rids, &policies, &mut rng).unwrap();
    let keys1 = derive_keys(&ss);

    // Encode to binary via MessagePack.
    let mut v = Vec::new();
    meta.msgpack_into(&mut v).unwrap();

    // Encode to JSON string.
    let s = meta.to_json_string().unwrap();

    // Derive a user secret key.
    let derived = policies[1].derive();
    let usk = &UserSecretKey(CGWFO::extract_usk(Some(&mpk.0), &msk, &derived, &mut rng));

    // Decode, while looking for id2 (= "leon.botros@gmail.com").
    let mut c = Cursor::new(v);
    let decoded1 = RecipientMetadata::msgpack_from(&mut c, &rids[1]).unwrap();
    let keys2 = decoded1.derive_keys(usk, &mpk).unwrap();

    // Idem, decode while looking for id2.
    let decoded2 = RecipientMetadata::from_string(&s, rids[1]).unwrap();
    let keys3 = decoded2.derive_keys(usk, &mpk).unwrap();

    assert_eq!(&decoded1.recipient_info.identifier, rids[1]);
    assert_eq!(&decoded1.iv, &meta.iv);
    assert_eq!(&decoded1.chunk_size, &meta.chunk_size);

    // Make sure we derive the same keys.
    assert_eq!(&keys1.aes_key, &keys2.aes_key);
    assert_eq!(&keys1.mac_key, &keys2.mac_key);

    assert_eq!(&keys1.mac_key, &keys3.mac_key);
    assert_eq!(&keys1.mac_key, &keys3.mac_key);
}
