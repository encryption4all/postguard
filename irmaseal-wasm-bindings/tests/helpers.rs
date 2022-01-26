use irmaseal_core::kem::cgw_kv::CGWKV;
use irmaseal_core::kem::IBKEM;
use irmaseal_core::{Attribute, Policy, PublicKey, UserSecretKey};
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;
use wasm_streams::readable::sys::ReadableStream as RawReadableStream;
use wasm_streams::writable::sys::WritableStream as RawWritableStream;

#[wasm_bindgen(module = "/tests/helpers.js")]
extern "C" {
    pub fn new_readable_byte_stream_from_array(chunks: Box<[JsValue]>) -> RawReadableStream;
}

#[wasm_bindgen(module = "/tests/helpers.js")]
extern "C" {
    pub fn new_recording_writable_stream() -> WritableStreamAndEvents;

    #[derive(Clone, Debug)]
    pub type WritableStreamAndEvents;

    #[wasm_bindgen(method, getter)]
    pub fn stream(this: &WritableStreamAndEvents) -> RawWritableStream;

    #[wasm_bindgen(method, getter)]
    pub fn written(this: &WritableStreamAndEvents) -> Box<[JsValue]>;
}

pub struct RecordingWritableStream {
    raw: WritableStreamAndEvents,
}

impl RecordingWritableStream {
    pub fn new() -> Self {
        Self {
            raw: new_recording_writable_stream(),
        }
    }

    pub fn stream(&self) -> RawWritableStream {
        self.raw.stream()
    }

    pub fn written(&self) -> Vec<String> {
        self.raw
            .written()
            .into_iter()
            .map(|x| x.as_string().unwrap())
            .collect::<Vec<_>>()
    }
}

pub fn rand_vec(length: usize) -> Vec<u8> {
    (0..length).map(|_| rand::random::<u8>()).collect()
}

pub struct TestSetup {
    pub mpk: PublicKey<CGWKV>,
    pub policies: BTreeMap<String, Policy>,
    pub usks: BTreeMap<String, UserSecretKey<CGWKV>>,
}

impl Default for TestSetup {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        let id1 = String::from("alice@example.com");
        let id2 = String::from("bob@example.com");

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
                Attribute::new("pbdf.gemeente.personalData.name", Some("bob")),
                Attribute::new("pbdf.sidn-pbdf.email.email", Some("bob@example.com")),
            ],
        };

        let policies = BTreeMap::<String, Policy>::from([(id1, p1), (id2, p2)]);

        let (tmpk, msk) = CGWKV::setup(&mut rng);
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
