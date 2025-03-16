use futures::io::Cursor;
use js_sys::Uint8Array;

use pg_core::client::{Sealer, Unsealer, VerificationResult};
use pg_core::consts::SYMMETRIC_CRYPTO_DEFAULT_CHUNK;
use pg_core::test::TestSetup;
use pg_wasm::SealOptions;
use pg_wasm::{js_seal, js_stream_seal, MemoryUnsealer, StreamUnsealer};

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
    16 * 1024 * 1024,
];

mod mem {
    use super::*;

    async fn test_rust_to_rust(len: usize) {
        use pg_core::client::rust::{SealerMemoryConfig as SC, UnsealerMemoryConfig as UC};

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let usk = &setup.usks[2];
        let signing_key = &setup.signing_keys[0];
        let vk = setup.ibs_pk;

        let plain = rand_vec(len);

        let window = web_sys::window().expect("no window");
        let performance = window.performance().expect("no performance");
        let t0 = performance.now();

        let ct = Sealer::<_, SC>::new(&setup.ibe_pk, &setup.policy, signing_key, &mut rng)
            .unwrap()
            .seal(&plain)
            .unwrap();

        let unsealer = Unsealer::<_, UC>::new(&ct, &vk).unwrap();
        let (plain2, pol) = unsealer.unseal("Bob", usk).unwrap();

        let t = performance.now() - t0;
        log(&format!(
            "[rust/mem]: seal/unseal message of length {len} took {t:.1} ms"
        ));

        assert_eq!(&plain, &plain2);
        assert_eq!(&pol.public, &signing_key.policy);
        assert_eq!(pol.private, None);
    }

    async fn test_web_to_web(len: usize) {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let options = SealOptions {
            skip_encryption: None,
            policy: Some(setup.policy.clone()),
            pub_sign_key: setup.signing_keys[0].clone(),
            priv_sign_key: Some(setup.signing_keys[1].clone()),
        };

        let js_options = serde_wasm_bindgen::to_value(&options).unwrap();

        let mpk = serde_wasm_bindgen::to_value(&setup.ibe_pk).unwrap();
        let usk = serde_wasm_bindgen::to_value(&setup.usks[2]).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

        let plain = rand_vec(len);
        let js_plain = Uint8Array::from(&plain[..]);

        let window = web_sys::window().expect("no window");
        let performance = window.performance().expect("no performance");

        let t0 = performance.now();

        let unsealer_input = js_seal(mpk.clone(), js_options.into(), js_plain)
            .await
            .unwrap();

        let unsealer = MemoryUnsealer::new(unsealer_input.into(), vk)
            .await
            .unwrap();
        let res = unsealer.unseal("Bob".to_string(), usk).await.unwrap();

        let t = performance.now() - t0;
        log(&format!(
            "[web/mem]: seal/unseal message of length {len} took {t:.1} ms"
        ));

        let verified: VerificationResult = serde_wasm_bindgen::from_value(res.get(1)).unwrap();

        assert_eq!(
            &plain,
            &res.get(0).dyn_into::<Uint8Array>().unwrap().to_vec()
        );
        assert_eq!(&verified.public, &setup.signing_keys[0].policy);
        assert_eq!(verified.private, Some(setup.signing_keys[1].policy.clone()));
    }

    async fn test_web_to_rust(len: usize) {
        use pg_core::client::rust::UnsealerMemoryConfig as UC;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        // Seal inputs (Web).
        let mpk = serde_wasm_bindgen::to_value(&setup.ibe_pk).unwrap();
        let options = SealOptions {
            skip_encryption: None,
            policy: Some(setup.policy.clone()),
            pub_sign_key: setup.signing_keys[0].clone(),
            priv_sign_key: Some(setup.signing_keys[1].clone()),
        };

        let js_options = serde_wasm_bindgen::to_value(&options).unwrap();

        // Unseal inputs (Rust).
        let usk = &setup.usks[2];
        let vk = setup.ibs_pk;

        let plain = rand_vec(len);
        let js_plain = Uint8Array::from(&plain[..]);

        let ct = js_seal(mpk.clone(), js_options.into(), js_plain)
            .await
            .unwrap();

        let unsealer = Unsealer::<_, UC>::new(&ct.to_vec(), &vk).unwrap();
        let (plain2, verified) = unsealer.unseal("Bob", usk).unwrap();

        assert_eq!(&plain, &plain2.to_vec());
        assert_eq!(&verified.public, &setup.signing_keys[0].policy);
        assert_eq!(verified.private, Some(setup.signing_keys[1].policy.clone()));
    }

    async fn test_rust_to_web(len: usize) {
        use pg_core::client::rust::SealerMemoryConfig as SC;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        // Sealer inputs (rust).
        let pub_signing_key = &setup.signing_keys[0];
        let priv_sign_key = &setup.signing_keys[1];

        // Unsealer inputs (web).
        let usk = serde_wasm_bindgen::to_value(&setup.usks[2]).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

        let plain = rand_vec(len);

        let ct = Sealer::<_, SC>::new(&setup.ibe_pk, &setup.policy, pub_signing_key, &mut rng)
            .unwrap()
            .with_priv_signing_key(priv_sign_key.clone())
            .seal(&plain)
            .unwrap();

        let js_ct = Uint8Array::from(&ct[..]);

        let unsealer = MemoryUnsealer::new(js_ct, vk).await.unwrap();
        let res = unsealer.unseal("Bob".to_string(), usk).await.unwrap();
        let verified: VerificationResult = serde_wasm_bindgen::from_value(res.get(1)).unwrap();

        assert_eq!(
            &plain,
            &res.get(0).dyn_into::<Uint8Array>().unwrap().to_vec()
        );
        assert_eq!(&verified.public, &setup.signing_keys[0].policy);
        assert_eq!(verified.private, Some(setup.signing_keys[1].policy.clone()));
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
}

mod stream {
    use super::*;

    async fn test_rust_to_rust(len: usize) {
        use pg_core::client::rust::stream::{SealerStreamConfig as SC, UnsealerStreamConfig as UC};

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let usk = &setup.usks[2];
        let signing_key = &setup.signing_keys[0];
        let vk = setup.ibs_pk;

        let plain = rand_vec(len);

        let mut a = Cursor::new(&plain);
        let mut b = Vec::new();

        let window = web_sys::window().expect("no window");
        let performance = window.performance().expect("no performance");
        let t0 = performance.now();

        Sealer::<_, SC>::new(&setup.ibe_pk, &setup.policy, signing_key, &mut rng)
            .unwrap()
            .seal(&mut a, &mut b)
            .await
            .unwrap();

        let mut c = Cursor::new(&b);
        let unsealer = Unsealer::<_, UC>::new(&mut c, &vk).await.unwrap();

        let mut plain2 = Vec::new();
        let pol = unsealer.unseal("Bob", usk, &mut plain2).await.unwrap();

        let t = performance.now() - t0;
        log(&format!(
            "[rust/stream]: seal/unseal message of length {len} took {t:.1} ms"
        ));

        assert_eq!(&plain, &plain2);
        assert_eq!(&pol.public, &signing_key.policy);
        assert_eq!(pol.private, None);
    }

    async fn test_web_to_web(len: usize) {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let options = SealOptions {
            skip_encryption: None,
            policy: Some(setup.policy.clone()),
            pub_sign_key: setup.signing_keys[0].clone(),
            priv_sign_key: Some(setup.signing_keys[1].clone()),
        };

        let js_options = serde_wasm_bindgen::to_value(&options).unwrap();

        let mpk = serde_wasm_bindgen::to_value(&setup.ibe_pk).unwrap();
        let usk = serde_wasm_bindgen::to_value(&setup.usks[2]).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

        let plain = rand_vec(len);
        let js_plain = Uint8Array::from(&plain[..]);

        let sealer_input = new_readable_stream_from_array(vec![js_plain.into()].into_boxed_slice());
        let sealer_output = new_recording_writable_stream();

        let window = web_sys::window().expect("no window");
        let performance = window.performance().expect("no performance");

        let t0 = performance.now();

        js_stream_seal(
            mpk.clone(),
            js_options.into(),
            sealer_input,
            sealer_output.stream(),
        )
        .await
        .unwrap();

        let unsealer_input =
            new_readable_stream_from_array(sealer_output.written().to_vec().into_boxed_slice());
        let unsealer_output = new_recording_writable_stream();

        let unsealer = StreamUnsealer::new(unsealer_input, vk).await.unwrap();

        let res = unsealer
            .unseal("Bob".to_string(), usk, unsealer_output.stream())
            .await
            .unwrap();

        let t = performance.now() - t0;
        log(&format!(
            "[web/stream]: seal/unseal message of length {len} took {t:.1} ms"
        ));

        let res: VerificationResult = serde_wasm_bindgen::from_value(res).unwrap();

        let plain2: Vec<u8> = unsealer_output
            .written()
            .iter()
            .flat_map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
            .collect();

        assert_eq!(&plain, &plain2);
        assert_eq!(&res.public, &setup.signing_keys[0].policy);
        assert_eq!(res.private, Some(setup.signing_keys[1].policy.clone()));
    }

    async fn test_web_to_rust(len: usize) {
        use pg_core::client::rust::stream::UnsealerStreamConfig as UC;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        // Seal inputs (Web).
        let mpk = serde_wasm_bindgen::to_value(&setup.ibe_pk).unwrap();
        let options = SealOptions {
            skip_encryption: None,
            policy: Some(setup.policy.clone()),
            pub_sign_key: setup.signing_keys[0].clone(),
            priv_sign_key: None,
        };

        let js_options = serde_wasm_bindgen::to_value(&options).unwrap();

        // Unseal inputs (Rust).
        let usk = &setup.usks[2];
        let vk = setup.ibs_pk;

        let plain = rand_vec(len);
        let js_plain = Uint8Array::from(&plain[..]);

        let sealer_input = new_readable_stream_from_array(vec![js_plain.into()].into_boxed_slice());
        let sealer_output = new_recording_writable_stream();

        js_stream_seal(
            mpk.clone(),
            js_options.into(),
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
        let unsealer = Unsealer::<_, UC>::new(&mut tmp, &vk).await.unwrap();

        let mut plain2 = Vec::new();
        unsealer.unseal("Bob", usk, &mut plain2).await.unwrap();

        assert_eq!(&plain, &plain2);
    }

    async fn test_web_to_rust_skip_enc(len: usize) {
        use pg_core::client::rust::stream::UnsealerStreamConfig as UC;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        // Seal inputs (Web).
        let mpk = serde_wasm_bindgen::to_value(&setup.ibe_pk).unwrap();
        let options = SealOptions {
            skip_encryption: Some(true),
            policy: None,
            pub_sign_key: setup.signing_keys[0].clone(),
            priv_sign_key: None,
        };

        let js_options = serde_wasm_bindgen::to_value(&options).unwrap();

        // Unseal inputs (Rust).
        let usk = &setup.usks[5];
        let vk = setup.ibs_pk;

        let plain = rand_vec(len);
        let js_plain = Uint8Array::from(&plain[..]);

        let sealer_input = new_readable_stream_from_array(vec![js_plain.into()].into_boxed_slice());
        let sealer_output = new_recording_writable_stream();

        js_stream_seal(
            mpk.clone(),
            js_options.into(),
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
        let unsealer = Unsealer::<_, UC>::new(&mut tmp, &vk).await.unwrap();

        let mut plain2 = Vec::new();
        unsealer.unseal("Default", usk, &mut plain2).await.unwrap();

        assert_eq!(&plain, &plain2);
    }

    async fn test_rust_to_web(len: usize) {
        use pg_core::client::rust::stream::SealerStreamConfig as SC;

        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        // Sealer inputs (rust).
        let signing_key = &setup.signing_keys[0];

        // Unsealer inputs (web).
        let usk = serde_wasm_bindgen::to_value(&setup.usks[2]).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

        let plain = rand_vec(len);
        let mut a = Cursor::new(&plain);
        let mut b = Vec::new();

        Sealer::<_, SC>::new(&setup.ibe_pk, &setup.policy, &signing_key, &mut rng)
            .unwrap()
            .seal(&mut a, &mut b)
            .await
            .unwrap();

        let unsealer_input = new_readable_stream_from_array(
            vec![Uint8Array::from(&b[..]).dyn_into().unwrap()].into_boxed_slice(),
        );
        let unsealer_output = new_recording_writable_stream();

        let unsealer = StreamUnsealer::new(unsealer_input, vk).await.unwrap();

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
    
    #[wasm_bindgen_test]
    async fn test_seal_unseal_web_to_rust_skip_enc() {
        for l in LENGTHS {
            test_web_to_rust_skip_enc(*l as usize).await;
        }
    }
}
