use futures::io::Cursor;
use irmaseal_core::stream::{seal, Unsealer};
use irmaseal_wasm_bindings::{js_seal, JsUnsealer};
use js_sys::Uint8Array;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::*;

#[allow(unused)]
mod helpers;

use helpers::*;

wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

async fn test_stdio_with_len(len: usize) {
    let mut rng = rand::thread_rng();
    let setup = TestSetup::default();

    let ids: Vec<String> = setup.policies.keys().cloned().collect();

    let test_id = &ids[1];
    let test_usk = &setup.usks.get(test_id).unwrap();

    let plain = rand_vec(len);

    let mut a = Cursor::new(&plain);
    let mut b = Vec::new();

    seal(&setup.mpk, &setup.policies, &mut rng, &mut a, &mut b)
        .await
        .unwrap();

    let mut c = Cursor::new(&b);
    let mut unsealer = Unsealer::new(&mut c).await.unwrap();

    let mut plain2 = Vec::new();
    unsealer
        .unseal(test_id, test_usk, &mut plain2)
        .await
        .unwrap();

    assert_eq!(&plain, &plain2);
}

async fn test_webstreams_with_len(len: usize) {
    let setup = TestSetup::default();

    // Convert the inputs to JS types.
    let mpk = JsValue::from_serde(&setup.mpk).unwrap();
    let policies = JsValue::from_serde(&setup.policies).unwrap();
    let usk = JsValue::from_serde(&setup.usks.get("alice@example.com").unwrap()).unwrap();

    let a = rand_vec(len);
    let js_plain = Uint8Array::from(&a[..]);

    let sealer_input =
        new_readable_byte_stream_from_array(vec![js_plain.into()].into_boxed_slice());
    let sealer_output = new_recording_writable_stream();

    js_seal(mpk.clone(), policies, sealer_input, sealer_output.stream())
        .await
        .unwrap();

    let unsealer_input =
        new_readable_byte_stream_from_array(sealer_output.written().to_vec().into_boxed_slice());

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

    let b: Vec<u8> = unsealer_output
        .written()
        .iter()
        .map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
        .flatten()
        .collect();

    assert_eq!(&a, &b);
}

#[wasm_bindgen_test]
async fn test_seal_unseal_stdio() {
    test_stdio_with_len(1).await;
    test_stdio_with_len(512).await;
    test_stdio_with_len(128 * 1024 - 1).await;
    test_stdio_with_len(128 * 1024).await;
    test_stdio_with_len(128 * 1024 + 1).await;
    test_stdio_with_len(128 * 2048 + 12324).await;
}

#[wasm_bindgen_test]
async fn test_seal_unseal_webstreams() {
    test_webstreams_with_len(1).await;
    test_webstreams_with_len(512).await;
    test_webstreams_with_len(128 * 1024 - 1).await;
    test_webstreams_with_len(128 * 1024).await;
    test_webstreams_with_len(128 * 1024 + 2).await;
    test_webstreams_with_len(128 * 2048 + 12324).await;
}
