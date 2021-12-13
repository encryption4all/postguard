use crate::metadata::*;
use crate::test_common::TestSetup;
use crate::Policy;

#[test]
fn test_enc_dec_json() {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::default();
    let test_id = &setup.identifiers[0];

    let policies = BTreeMap::<String, Policy>::from([
        (String::from("l.botros@cs.ru.nl"), setup.policies[0].clone()),
        (
            String::from("l.botros@gmail.com"),
            setup.policies[1].clone(),
        ),
    ]);

    let (meta, _ss) = Metadata::new(&setup.mpk, policies, &mut rng).unwrap();

    let s = meta.to_json_string().unwrap();

    println!("{}", &s);

    // Decode string, while looking for id2
    let decoded = RecipientMetadata::from_string(&s, test_id).unwrap();

    dbg!(&decoded);
    let full_decoded: Metadata = serde_json::from_str(&s).unwrap();

    dbg!(&full_decoded.policies.into_keys());

    assert_eq!(
        &decoded.recipient_info.policy,
        &setup.policies[0].to_hidden()
    );
    assert_eq!(&decoded.iv, &meta.iv);
    assert_eq!(&decoded.chunk_size, &meta.chunk_size);
}

//#[test]
//fn test_enc_dec_msgpack() {
//    use std::io::Cursor;
//
//    let mut rng = rand::thread_rng();
//    let setup = TestSetup::default();
//    let test_id = &setup.identifiers[1];
//
//    let identifier_refs: Vec<&String> = setup.identifiers.iter().collect();
//    let policy_refs: Vec<&Policy> = setup.policies.iter().collect();
//
//    let (meta, _ss) = Metadata::new(&setup.mpk, &identifier_refs, &policy_refs, &mut rng).unwrap();
//
//    let mut v = Vec::new();
//    meta.msgpack_into(&mut v).unwrap();
//
//    // println!("output is {} bytes", v.len());
//
//    let mut c = Cursor::new(v);
//    let decoded = RecipientMetadata::msgpack_from(&mut c, test_id).unwrap();
//
//    assert_eq!(&decoded.recipient_info.identifier, test_id);
//    assert_eq!(&decoded.iv, &meta.iv);
//    assert_eq!(&decoded.chunk_size, &meta.chunk_size);
//}
//
//#[test]
//fn test_transcode() {
//    use crate::PREAMBLE_SIZE;
//    use std::io::Cursor;
//
//    // This test encodes to binary and then transcodes into serde_json
//    // The transcoded data is compared with a direct serialization of the same metadata.
//    let mut rng = rand::thread_rng();
//    let setup = TestSetup::default();
//
//    let identifier_refs: Vec<&String> = setup.identifiers.iter().collect();
//    let policy_refs: Vec<&Policy> = setup.policies.iter().collect();
//
//    let (meta, _ss) = Metadata::new(&setup.mpk, &identifier_refs, &policy_refs, &mut rng).unwrap();
//
//    let mut binary = Vec::new();
//    meta.msgpack_into(&mut binary).unwrap();
//
//    let v1 = serde_json::to_vec(&meta).unwrap();
//    let mut v2 = Vec::new();
//
//    // Be sure to skip or better, check, the preamble when transcoding
//    let mut des = rmp_serde::decode::Deserializer::new(&binary[PREAMBLE_SIZE..]);
//    let mut ser = serde_json::Serializer::new(Cursor::new(&mut v2));
//
//    serde_transcode::transcode(&mut des, &mut ser).unwrap();
//
//    assert_eq!(&v1, &v2);
//}
//
//#[test]
//// This test tests that both encoding methods derive the same keys as the sender.
//fn test_round() {
//    use crate::util::derive_keys;
//    use std::io::Cursor;
//
//    let mut rng = rand::thread_rng();
//    let setup = TestSetup::default();
//    let test_id = &setup.identifiers[1];
//    let test_usk = &setup.usks[1];
//
//    let identifier_refs: Vec<&String> = setup.identifiers.iter().collect();
//    let policy_refs: Vec<&Policy> = setup.policies.iter().collect();
//
//    let (meta, ss) = Metadata::new(&setup.mpk, &identifier_refs, &policy_refs, &mut rng).unwrap();
//    let keys1 = derive_keys(&ss);
//
//    // Encode to binary via MessagePack.
//    let mut v = Vec::new();
//    meta.msgpack_into(&mut v).unwrap();
//
//    // Encode to JSON string.
//    let s = meta.to_json_string().unwrap();
//
//    // Decode, while looking for id2 (= "leon.botros@gmail.com").
//    let mut c = Cursor::new(v);
//    let decoded1 = RecipientMetadata::msgpack_from(&mut c, test_id).unwrap();
//    let keys2 = decoded1.derive_keys(test_usk, &setup.mpk).unwrap();
//
//    // Idem, decode while looking for test_id.
//    let decoded2 = RecipientMetadata::from_string(&s, test_id).unwrap();
//    let keys3 = decoded2.derive_keys(test_usk, &setup.mpk).unwrap();
//
//    assert_eq!(&decoded1.recipient_info.identifier, test_id);
//    assert_eq!(&decoded1.iv, &meta.iv);
//    assert_eq!(&decoded1.chunk_size, &meta.chunk_size);
//
//    // Make sure we derive the same keys.
//    assert_eq!(&keys1.aes_key, &keys2.aes_key);
//    assert_eq!(&keys1.mac_key, &keys2.mac_key);
//
//    assert_eq!(&keys1.aes_key, &keys3.aes_key);
//    assert_eq!(&keys1.mac_key, &keys3.mac_key);
//}
