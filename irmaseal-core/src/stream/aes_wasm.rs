use crate::stream::{AsyncNewCipher, AsyncStreamCipher};
use crate::Error;
use crate::{IV_SIZE, NONCE_SIZE};
use async_trait::async_trait;
use js_sys::{Array, Object, Reflect, Uint8Array};
use std::convert::TryInto;
use wasm_bindgen::{prelude::*, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesCtrParams, Crypto, CryptoKey};

const BLOCKSIZE: usize = 16;
const MODE: &'static str = "AES-CTR";
const COUNTER_BITS: u8 = 64;

// JS web workers do not support accessing web-sys::window(), so
// we have to import crypto using a custom binding.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = crypto, js_name = valueOf)]
    fn get_crypto() -> Crypto;
}

pub(crate) struct Ctr64BEAes128 {
    key: CryptoKey,
    nonce: [u8; IV_SIZE],
    counter: u64,
}

#[async_trait(?Send)]
impl AsyncNewCipher for Ctr64BEAes128 {
    type Cipher = Ctr64BEAes128;

    async fn new_from_slices(key: &[u8], nonce: &[u8]) -> Result<Self::Cipher, Error> {
        let subtle_crypto = get_crypto().subtle();

        let algorithm: JsValue = Object::new().into();
        Reflect::set(
            &algorithm,
            &JsValue::from_str("name"),
            &JsValue::from_str(MODE),
        )
        .unwrap();

        let key_usages = Array::of2(&JsValue::from_str("encrypt"), &JsValue::from_str("decrypt"));
        let key_value: Uint8Array = key.as_ref().into();
        let key_promise = subtle_crypto.import_key_with_object(
            "raw",
            &key_value.into(),
            &algorithm.into(),
            false,
            &key_usages,
        );

        let key_object = JsFuture::from(key_promise.unwrap())
            .await
            .map_err(|_e| Error::KeyError)?;

        Ok(Ctr64BEAes128 {
            key: key_object.into(),
            nonce: nonce.try_into().unwrap(),
            counter: 0,
        })
    }
}

#[async_trait(?Send)]
impl AsyncStreamCipher for Ctr64BEAes128 {
    async fn apply_keystream(&mut self, data: &mut [u8]) {
        let params = self.get_aes_params();
        let subtle = get_crypto().subtle();

        let js_data = Uint8Array::from(&*data);

        let result = subtle.encrypt_with_object_and_buffer_source(&params, &self.key, &js_data);
        let array_buffer = JsFuture::from(result.unwrap()).await.unwrap().into();
        let out = Uint8Array::new(&array_buffer);
        out.copy_to(data);

        self.update(data);
    }
}

impl Ctr64BEAes128 {
    fn get_aes_params(&self) -> AesCtrParams {
        let low = &self.nonce[..NONCE_SIZE];
        let high = self
            .counter
            .wrapping_add(u64::from_be_bytes(
                self.nonce[NONCE_SIZE..].try_into().unwrap(),
            ))
            .to_be_bytes();

        let mut iv = [0u8; IV_SIZE];
        iv[..NONCE_SIZE].copy_from_slice(&low);
        iv[NONCE_SIZE..].copy_from_slice(&high);

        let iv_arr: Uint8Array = iv.as_ref().into();

        AesCtrParams::new(MODE, &iv_arr, COUNTER_BITS)
    }

    fn update(&mut self, data: &[u8]) {
        // Update our bookkeeping, do checked_add to prevent re-use of counters.
        let new_counter = self.counter.checked_add((data.len() / BLOCKSIZE) as u64);
        self.counter = new_counter.unwrap();
    }
}
