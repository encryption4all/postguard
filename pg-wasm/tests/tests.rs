use futures::io::Cursor;
use js_sys::Uint8Array;

use pg_core::client::rust::stream::{SealerStreamConfig as RSC, UnsealerStreamConfig as RUC};
use pg_core::client::{Sealer, Unsealer};
use pg_core::consts::SYMMETRIC_CRYPTO_DEFAULT_CHUNK;
use pg_core::test::TestSetup;
use pg_wasm::SealOptions;
use pg_wasm::{js_seal, JsUnsealer};

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(a: &str);
}

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
    1024 * 1024,
];

async fn test_rust_to_rust(len: usize) {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::new(&mut rng);

    let usk = setup.usks.get("Bob").unwrap();
    let signing_key = setup.signing_keys.get("Alice").unwrap();
    let vk = setup.ibs_pk;

    let plain = rand_vec(len);

    let mut a = Cursor::new(&plain);
    let mut b = Vec::new();

    let window = web_sys::window().expect("no window");
    let performance = window.performance().expect("no performance");
    let t0 = performance.now();

    Sealer::<_, RSC>::new(&setup.mpk, &setup.policies, signing_key, &mut rng)
        .unwrap()
        .seal(&mut a, &mut b)
        .await
        .unwrap();

    let mut c = Cursor::new(&b);
    let unsealer = Unsealer::<_, RUC>::new(&mut c, &vk).await.unwrap();

    let mut plain2 = Vec::new();
    let pol = unsealer.unseal("Bob", usk, &mut plain2).await.unwrap();

    let t = performance.now() - t0;
    log(&format!(
        "[rust]: seal/unseal message of length {len} took {t:.1} ms"
    ));

    assert_eq!(&plain, &plain2);
    assert_eq!(&signing_key.policy, &pol);
}

async fn test_web_to_web(len: usize) {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::new(&mut rng);

    let options = SealOptions {
        policy: setup.policies.clone(),
        pub_sign_key: setup.signing_keys.get("Alice").unwrap().clone(),
        priv_sign_key: None,
    };

    let js_options = serde_wasm_bindgen::to_value(&options).unwrap();

    let mpk = serde_wasm_bindgen::to_value(&setup.mpk).unwrap();
    let usk = serde_wasm_bindgen::to_value(&setup.usks.get("Bob").unwrap()).unwrap();
    let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

    let plain = rand_vec(len);
    let js_plain = Uint8Array::from(&plain[..]);

    let sealer_input = new_readable_stream_from_array(vec![js_plain.into()].into_boxed_slice());
    let sealer_output = new_recording_writable_stream();

    let window = web_sys::window().expect("no window");
    let performance = window.performance().expect("no performance");
    let t0 = performance.now();

    js_seal(
        mpk.clone(),
        js_options,
        sealer_input,
        sealer_output.stream(),
    )
    .await
    .unwrap();

    let unsealer_input =
        new_readable_stream_from_array(sealer_output.written().to_vec().into_boxed_slice());
    let unsealer_output = new_recording_writable_stream();

    let unsealer = JsUnsealer::new(unsealer_input, vk).await.unwrap();

    unsealer
        .unseal("Bob".to_string(), usk, unsealer_output.stream())
        .await
        .unwrap();

    let t = performance.now() - t0;
    log(&format!(
        "[web]: seal/unseal message of length {len} took {t:.1} ms"
    ));

    let plain2: Vec<u8> = unsealer_output
        .written()
        .iter()
        .flat_map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
        .collect();

    assert_eq!(&plain, &plain2);
}

async fn test_web_to_rust(len: usize) {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::new(&mut rng);

    // Seal inputs (Web).
    let mpk = serde_wasm_bindgen::to_value(&setup.mpk).unwrap();
    let options = SealOptions {
        policy: setup.policies.clone(),
        pub_sign_key: setup.signing_keys.get("Alice").unwrap().clone(),
        priv_sign_key: None,
    };

    let js_options = serde_wasm_bindgen::to_value(&options).unwrap();

    // Unseal inputs (Rust).
    let usk = setup.usks.get("Bob").unwrap();
    let vk = setup.ibs_pk;

    let plain = rand_vec(len);
    let js_plain = Uint8Array::from(&plain[..]);

    let sealer_input = new_readable_stream_from_array(vec![js_plain.into()].into_boxed_slice());
    let sealer_output = new_recording_writable_stream();

    js_seal(
        mpk.clone(),
        js_options,
        sealer_input,
        sealer_output.stream(),
    )
    .await
    .unwrap();

    let unsealer_input: Vec<u8> = sealer_output
        .written()
        .iter()
        .flat_map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
        .collect();

    let mut tmp = Cursor::new(&unsealer_input);
    let unsealer = Unsealer::<_, RUC>::new(&mut tmp, &vk).await.unwrap();

    let mut plain2 = Vec::new();
    let pol = unsealer.unseal("Bob", usk, &mut plain2).await.unwrap();

    assert_eq!(&plain, &plain2);
    assert_eq!(&setup.signing_keys.get("Alice").unwrap().policy, &pol);
}

async fn test_rust_to_web(len: usize) {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::new(&mut rng);

    // Sealer inputs (rust).
    let signing_key = setup.signing_keys.get("Alice").unwrap();

    // Unsealer inputs (web).
    let usk = serde_wasm_bindgen::to_value(&setup.usks.get("Bob").unwrap()).unwrap();
    let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

    let plain = rand_vec(len);
    let mut a = Cursor::new(&plain);
    let mut b = Vec::new();

    Sealer::<_, RSC>::new(&setup.mpk, &setup.policies, signing_key, &mut rng)
        .unwrap()
        .seal(&mut a, &mut b)
        .await
        .unwrap();

    let unsealer_input = new_readable_stream_from_array(
        vec![Uint8Array::from(&b[..]).dyn_into().unwrap()].into_boxed_slice(),
    );
    let unsealer_output = new_recording_writable_stream();

    let unsealer = JsUnsealer::new(unsealer_input, vk).await.unwrap();

    unsealer
        .unseal("Bob".to_string(), usk, unsealer_output.stream())
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
async fn test_seal_unseal_web() {
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
