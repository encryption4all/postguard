use futures::io::Cursor;
use js_sys::Uint8Array;
use pg_core::consts::SYMMETRIC_CRYPTO_DEFAULT_CHUNK;
use pg_core::rust::stream::{SealerStreamConfig as RSC, UnsealerStreamConfig as RUC};
use pg_core::{Sealer, Unsealer};
use pg_wasm::{js_seal, JsUnsealer};
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

#[allow(unused)]
mod helpers;

use helpers::*;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const LENGTHS: &[u32] = &[
    1,
    512,
    SYMMETRIC_CRYPTO_DEFAULT_CHUNK - 3,
    SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
    SYMMETRIC_CRYPTO_DEFAULT_CHUNK + 3,
    3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK,
    3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK + 16,
    3 * SYMMETRIC_CRYPTO_DEFAULT_CHUNK - 17,
];

async fn test_rust_to_rust(len: usize) {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::default();

    let usk = &setup.usks.get("alice@example.com").unwrap();

    let plain = rand_vec(len);

    let mut a = Cursor::new(&plain);
    let mut b = Vec::new();

    Sealer::<RSC>::new(&setup.mpk, &setup.policies, &mut rng)
        .unwrap()
        .seal(&mut a, &mut b)
        .await
        .unwrap();

    let mut c = Cursor::new(&b);
    let mut unsealer = Unsealer::<_, RUC>::new(&mut c).await.unwrap();

    let mut plain2 = Vec::new();
    unsealer
        .unseal("alice@example.com", usk, &mut plain2)
        .await
        .unwrap();

    assert_eq!(&plain, &plain2);
}

async fn test_web_to_web(len: usize) {
    let setup = TestSetup::default();

    let mpk = serde_wasm_bindgen::to_value(&setup.mpk).unwrap();
    let policies = serde_wasm_bindgen::to_value(&setup.policies).unwrap();
    let usk = serde_wasm_bindgen::to_value(&setup.usks.get("alice@example.com").unwrap()).unwrap();

    let plain = rand_vec(len);
    let js_plain = Uint8Array::from(&plain[..]);

    let sealer_input = new_readable_stream_from_array(vec![js_plain.into()].into_boxed_slice());
    let sealer_output = new_recording_writable_stream();

    js_seal(mpk.clone(), policies, sealer_input, sealer_output.stream())
        .await
        .unwrap();

    let unsealer_input =
        new_readable_stream_from_array(sealer_output.written().to_vec().into_boxed_slice());
    let unsealer_output = new_recording_writable_stream();

    let unsealer = JsUnsealer::new(unsealer_input).await.unwrap();

    unsealer
        .unseal(
            "alice@example.com".to_string(),
            usk,
            unsealer_output.stream(),
        )
        .await
        .unwrap();

    let plain2: Vec<u8> = unsealer_output
        .written()
        .iter()
        .flat_map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
        .collect();

    assert_eq!(&plain, &plain2);
}

async fn test_web_to_rust(len: usize) {
    let setup = TestSetup::default();

    let mpk = serde_wasm_bindgen::to_value(&setup.mpk).unwrap();
    let policies = serde_wasm_bindgen::to_value(&setup.policies).unwrap();
    let usk = setup.usks.get("alice@example.com").unwrap();

    let plain = rand_vec(len);
    let js_plain = Uint8Array::from(&plain[..]);

    let sealer_input = new_readable_stream_from_array(vec![js_plain.into()].into_boxed_slice());
    let sealer_output = new_recording_writable_stream();

    js_seal(mpk.clone(), policies, sealer_input, sealer_output.stream())
        .await
        .unwrap();

    let unsealer_input: Vec<u8> = sealer_output
        .written()
        .iter()
        .flat_map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
        .collect();

    let mut tmp = Cursor::new(&unsealer_input);
    let mut unsealer = Unsealer::<_, RUC>::new(&mut tmp).await.unwrap();

    let mut plain2 = Vec::new();
    unsealer
        .unseal("alice@example.com", usk, &mut plain2)
        .await
        .unwrap();

    assert_eq!(&plain, &plain2);
}

async fn test_rust_to_web(len: usize) {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::default();

    let usk = serde_wasm_bindgen::to_value(&setup.usks.get("alice@example.com").unwrap()).unwrap();

    let plain = rand_vec(len);
    let mut a = Cursor::new(&plain);
    let mut b = Vec::new();

    Sealer::<RSC>::new(&setup.mpk, &setup.policies, &mut rng)
        .unwrap()
        .seal(&mut a, &mut b)
        .await
        .unwrap();

    let unsealer_input = new_readable_stream_from_array(
        vec![Uint8Array::from(&b[..]).dyn_into().unwrap()].into_boxed_slice(),
    );
    let unsealer_output = new_recording_writable_stream();

    let unsealer = JsUnsealer::new(unsealer_input).await.unwrap();

    unsealer
        .unseal(
            "alice@example.com".to_string(),
            usk,
            unsealer_output.stream(),
        )
        .await
        .unwrap();

    let plain2: Vec<u8> = unsealer_output
        .written()
        .iter()
        .flat_map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
        .collect();

    assert_eq!(&plain, &plain2);
}

#[wasm_bindgen_test]
async fn test_seal_unseal_rust() {
    for l in LENGTHS {
        test_rust_to_rust(*l as usize).await;
    }
}

#[wasm_bindgen_test]
async fn test_seal_unseal_webstreams() {
    for l in LENGTHS {
        test_web_to_web(*l as usize).await;
    }
}

#[wasm_bindgen_test]
async fn test_seal_unseal_web_to_rust() {
    for l in LENGTHS {
        test_web_to_rust(*l as usize).await;
    }
}

#[wasm_bindgen_test]
async fn test_seal_unseal_rust_to_web() {
    for l in LENGTHS {
        test_rust_to_web(*l as usize).await;
    }
}
