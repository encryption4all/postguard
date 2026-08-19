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

    #[wasm_bindgen_test]
    async fn test_seal_unseal_web_to_rust_skip_enc() {
        for l in LENGTHS {
            test_web_to_rust_skip_enc(*l as usize).await;
        }
    }
}

/// `h_sig_ext` — the header signature together with the sender's public signing
/// policy — travels outside the AEAD, so anyone who intercepts a container can
/// replace it with a signature over the same header bytes made with a signing
/// key the PKG hands to whoever authenticates. What stops the swap is the copy
/// of the public signing policy the sealer writes inside the AEAD. These tests
/// drive that check through the web reader.
mod swapped_header_signature {
    use super::*;

    use pg_core::artifacts::SigningKeyExt;
    use pg_core::consts::{PREAMBLE_SIZE, PRELUDE_SIZE, SIG_SIZE_SIZE, VERSION_SIZE};
    use pg_core::ibs::gg::Signer;

    /// Splits a sealed container into the header bytes, the header signature
    /// block and everything after it.
    fn split_container(sealed: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let header_len = u32::from_be_bytes(
            sealed[PRELUDE_SIZE + VERSION_SIZE..PREAMBLE_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        let sig_len_at = PREAMBLE_SIZE + header_len;
        let sig_len = u32::from_be_bytes(
            sealed[sig_len_at..sig_len_at + SIG_SIZE_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        let sig_at = sig_len_at + SIG_SIZE_SIZE;

        (
            &sealed[PREAMBLE_SIZE..sig_len_at],
            &sealed[sig_at..sig_at + sig_len],
            &sealed[sig_at + sig_len..],
        )
    }

    /// Rebuilds `sealed` with the header signature block replaced by one made
    /// over the same header bytes with `attacker`'s key, carrying `attacker`'s
    /// policy. Preamble, header and ciphertext stay byte for byte.
    ///
    /// pg-core's `SignatureExt` is crate-private, but bincode encodes struct
    /// fields positionally and adds no framing, so the block is the encoded
    /// signature followed by the encoded policy.
    fn swap_header_signature(sealed: &[u8], attacker: &SigningKeyExt) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let (header_bytes, _, rest) = split_container(sealed);

        let sig = Signer::default()
            .chain(header_bytes)
            .sign(&attacker.key.0, &mut rng);

        let mut block = pg_core::bincode_compat::serialize(&sig).unwrap();
        block.extend_from_slice(&pg_core::bincode_compat::serialize(&attacker.policy).unwrap());

        let mut out = sealed[..PREAMBLE_SIZE + header_bytes.len()].to_vec();
        out.extend_from_slice(&(block.len() as u32).to_be_bytes());
        out.extend_from_slice(&block);
        out.extend_from_slice(rest);

        out
    }

    fn seal_options(setup: &TestSetup) -> SealOptions {
        SealOptions {
            skip_encryption: None,
            policy: Some(setup.policy.clone()),
            pub_sign_key: setup.signing_keys[0].clone(),
            priv_sign_key: Some(setup.signing_keys[1].clone()),
        }
    }

    #[wasm_bindgen_test]
    async fn test_mem_unseal_rejects_swapped_header_signature() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let mpk = serde_wasm_bindgen::to_value(&setup.ibe_pk).unwrap();
        let usk = serde_wasm_bindgen::to_value(&setup.usks[2]).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();
        let js_options = serde_wasm_bindgen::to_value(&seal_options(&setup)).unwrap();

        let ct = js_seal(mpk, js_options.into(), Uint8Array::from(&rand_vec(512)[..]))
            .await
            .unwrap();

        // Charlie's name-only key — a key the PKG hands to whoever authenticates
        // as Charlie, which is what makes the swap cheap.
        let swapped = swap_header_signature(&ct.to_vec(), &setup.signing_keys[4]);

        let unsealer = MemoryUnsealer::new(Uint8Array::from(&swapped[..]), vk)
            .await
            .expect("the swapped header signature still verifies — that is the attack");

        assert!(
            unsealer.unseal("Bob".to_string(), usk).await.is_err(),
            "a swapped header signature must not unseal"
        );
    }

    #[wasm_bindgen_test]
    async fn test_stream_unseal_rejects_swapped_header_signature() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let mpk = serde_wasm_bindgen::to_value(&setup.ibe_pk).unwrap();
        let usk = serde_wasm_bindgen::to_value(&setup.usks[2]).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();
        let js_options = serde_wasm_bindgen::to_value(&seal_options(&setup)).unwrap();

        let plain = Uint8Array::from(&rand_vec(512)[..]);
        let sealer_input = new_readable_stream_from_array(vec![plain.into()].into_boxed_slice());
        let sealer_output = new_recording_writable_stream();

        js_stream_seal(mpk, js_options.into(), sealer_input, sealer_output.stream())
            .await
            .unwrap();

        let ct: Vec<u8> = sealer_output
            .written()
            .iter()
            .flat_map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
            .collect();

        let swapped = swap_header_signature(&ct, &setup.signing_keys[4]);

        let unsealer_input = new_readable_stream_from_array(
            vec![Uint8Array::from(&swapped[..]).dyn_into().unwrap()].into_boxed_slice(),
        );
        let unsealer_output = new_recording_writable_stream();

        let unsealer = StreamUnsealer::new(unsealer_input, vk)
            .await
            .expect("the swapped header signature still verifies — that is the attack");

        assert!(
            unsealer
                .unseal("Bob".to_string(), usk, unsealer_output.stream())
                .await
                .is_err(),
            "a swapped header signature must not unseal"
        );
    }
}

/// Containers sealed by the published `@e4a/pg-wasm@0.6.1` carry no copy of the
/// public signing policy inside the AEAD. The web reader must still open them:
/// absence means an older sealer, not a stripped field, because stripping it
/// takes the AEAD key the attacker does not have.
///
/// Same fixtures `pg-core/tests/wire_format.rs` pins, read through the web
/// reader — a separate implementation of the same format.
mod legacy_containers {
    use super::*;

    use js_sys::{Reflect, JSON};

    const MEM: &[u8] = include_bytes!("../../pg-core/testdata/wire-format-v3/mem.bin");
    const STREAM: &[u8] = include_bytes!("../../pg-core/testdata/wire-format-v3/stream.bin");
    const VK: &str = include_str!("../../pg-core/testdata/wire-format-v3/vk.json");
    const USK: &str = include_str!("../../pg-core/testdata/wire-format-v3/usk.json");

    // `meta.json`'s recipientId, and its plaintextB64 decoded.
    const RECIPIENT: &str = "phd-holder";
    const PLAIN: &[u8] =
        b"postguard-e2e crypto-compat fixture: old ciphertexts must decrypt forever";

    fn field(json: &str, name: &str) -> JsValue {
        Reflect::get(&JSON::parse(json).unwrap(), &name.into()).unwrap()
    }

    #[wasm_bindgen_test]
    async fn test_mem_unseals_a_container_without_the_appended_policy() {
        let unsealer = MemoryUnsealer::new(Uint8Array::from(MEM), field(VK, "publicKey"))
            .await
            .expect("parse the golden in-memory container");

        let res = unsealer
            .unseal(RECIPIENT.to_string(), field(USK, "key"))
            .await
            .expect("unseal the golden in-memory container");

        assert_eq!(
            &res.get(0).dyn_into::<Uint8Array>().unwrap().to_vec(),
            PLAIN
        );
    }

    #[wasm_bindgen_test]
    async fn test_stream_unseals_a_container_without_the_appended_policy() {
        let unsealer_input = new_readable_stream_from_array(
            vec![Uint8Array::from(STREAM).dyn_into().unwrap()].into_boxed_slice(),
        );
        let unsealer_output = new_recording_writable_stream();

        let unsealer = StreamUnsealer::new(unsealer_input, field(VK, "publicKey"))
            .await
            .expect("parse the golden streaming container");

        unsealer
            .unseal(
                RECIPIENT.to_string(),
                field(USK, "key"),
                unsealer_output.stream(),
            )
            .await
            .expect("unseal the golden streaming container");

        let plain: Vec<u8> = unsealer_output
            .written()
            .iter()
            .flat_map(|chunk| chunk.dyn_ref::<Uint8Array>().unwrap().to_vec())
            .collect();

        assert_eq!(&plain, PLAIN);
    }
}

/// The challenge exports are what lets a relay that holds only the verifying
/// key check that whoever is uploading holds the signing key for the identity
/// it reads out of a container. `pg-core` covers the crypto; these tests cover
/// the boundary the JS caller actually sees — the signature crossing as a
/// `Uint8Array` and coming back.
mod challenge {
    use super::*;

    use pg_wasm::{js_sign_challenge, js_verify_challenge};

    const CONTEXT: &str = "cryptify/upload";
    const CHALLENGE: &[u8] = b"a verifier-chosen challenge";

    #[wasm_bindgen_test]
    fn test_sign_verify_roundtrip() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let key = serde_wasm_bindgen::to_value(&setup.signing_keys[0]).unwrap();
        let pol = serde_wasm_bindgen::to_value(&setup.signing_keys[0].policy).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

        let sig = js_sign_challenge(key.into(), CONTEXT, Uint8Array::from(CHALLENGE))
            .expect("sign the challenge");

        assert_eq!(sig.length() as usize, pg_core::ibs::gg::SIG_BYTES);

        assert!(
            js_verify_challenge(vk, pol.into(), CONTEXT, Uint8Array::from(CHALLENGE), sig)
                .expect("verify the challenge")
        );
    }

    #[wasm_bindgen_test]
    fn test_verify_rejects_another_identity() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let key = serde_wasm_bindgen::to_value(&setup.signing_keys[0]).unwrap();
        let other = serde_wasm_bindgen::to_value(&setup.signing_keys[1].policy).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

        let sig = js_sign_challenge(key.into(), CONTEXT, Uint8Array::from(CHALLENGE))
            .expect("sign the challenge");

        assert!(
            !js_verify_challenge(vk, other.into(), CONTEXT, Uint8Array::from(CHALLENGE), sig)
                .expect("verify the challenge")
        );
    }

    /// A signature the caller mangled is a failed proof, not a thrown error: JS
    /// callers get `false` rather than an exception they have to catch.
    #[wasm_bindgen_test]
    fn test_verify_returns_false_for_a_malformed_signature() {
        let mut rng = rand::thread_rng();
        let setup = TestSetup::new(&mut rng);

        let pol = serde_wasm_bindgen::to_value(&setup.signing_keys[0].policy).unwrap();
        let vk = serde_wasm_bindgen::to_value(&setup.ibs_pk).unwrap();

        for len in [0u32, 1, (pg_core::ibs::gg::SIG_BYTES as u32) - 1] {
            let vk = vk.clone();
            let pol = pol.clone();

            assert!(!js_verify_challenge(
                vk,
                pol.into(),
                CONTEXT,
                Uint8Array::from(CHALLENGE),
                Uint8Array::new_with_length(len),
            )
            .expect("verify a signature of the wrong length"));
        }

        // The right length but not a decodable signature, which reaches the
        // decode branch instead of stopping at the length check. All-zero
        // bytes would not do: those decode fine and merely fail to verify.
        let undecodable = vec![0xffu8; pg_core::ibs::gg::SIG_BYTES];

        assert!(!js_verify_challenge(
            vk,
            pol.into(),
            CONTEXT,
            Uint8Array::from(CHALLENGE),
            Uint8Array::from(undecodable.as_slice()),
        )
        .expect("verify an undecodable signature"));
    }
}
