use super::{IVSIZE, KEYSIZE};
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::{prelude::*, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesCtrParams, Crypto, CryptoKey};

use crate::stream::BLOCKSIZE;

// JS web workers do not support accessing web-sys::window(), so
// we have to import crypto using a custom binding.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = crypto, js_name = valueOf)]
    fn get_crypto() -> Crypto;
}

pub struct SymCrypt {
    key: CryptoKey,
    nonce: [u8; IVSIZE],
    counter: u128,
    block_index: u32,
}

// TODO: Maybe create some kind of fallback to aes_lib for browsers where crypto is not available (like IE)
impl SymCrypt {
    pub async fn new(key: &[u8; KEYSIZE], nonce: &[u8; IVSIZE]) -> Self {
        let subtle_crypto = get_crypto().subtle();
        let algorithm: JsValue = Object::new().into();
        Reflect::set(
            &algorithm,
            &JsValue::from_str("name"),
            &JsValue::from_str("AES-CTR"),
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
        let key_object = JsFuture::from(key_promise.unwrap()).await.unwrap();
        SymCrypt {
            key: key_object.into(),
            nonce: nonce.clone(),
            counter: 0,
            block_index: 0,
        }
    }

    fn get_aes_params(&self) -> AesCtrParams {
        let iv = self.counter.wrapping_add(u128::from_be_bytes(self.nonce));
        let iv_arr: Uint8Array = iv.to_be_bytes().as_ref().into();
        AesCtrParams::new("AES-CTR", &iv_arr, 128)
    }

    fn align_data(&self, data: &mut [u8]) -> Uint8Array {
        match self.block_index {
            0 => Uint8Array::from(&*data),
            block_index => {
                let data_len = data.len() as u32;
                let arr = Uint8Array::new_with_length(data_len + block_index);
                // TODO: set does a memcopy in JS, so maybe check whether this can be done more memory
                //       efficient (be aware that more efficiency might require use of unsafe methods).
                arr.set(&Uint8Array::from(&*data), block_index);
                arr
            }
        }
    }

    fn update(&mut self, data: &[u8]) {
        // Update our bookkeeping, do checked_add to prevent re-use of counters.
        let new_len = (self.block_index as usize) + data.len();
        let new_counter = self.counter.checked_add((new_len / BLOCKSIZE) as u128);
        self.counter = new_counter.unwrap();
        self.block_index = (new_len % BLOCKSIZE) as u32;
    }

    pub async fn encrypt(&mut self, data: &mut [u8]) {
        let params = self.get_aes_params();
        let subtle = get_crypto().subtle();

        // Introduce zero-padding at begin if block is not nicely aligned.
        let aligned = self.align_data(data);

        // Encrypt
        let result = subtle.encrypt_with_object_and_buffer_source(&params, &self.key, &aligned);

        // Parse result and remove zero-padding again.
        let array_buffer = JsFuture::from(result.unwrap()).await.unwrap().into();
        let encrypted = Uint8Array::new(&array_buffer);
        encrypted
            .subarray(self.block_index, encrypted.length())
            .copy_to(data);

        self.update(data);
    }

    pub async fn decrypt(&mut self, data: &mut [u8]) {
        let params = self.get_aes_params();
        let subtle = get_crypto().subtle();

        // Introduce zero-padding at begin if block is not nicely aligned.
        let aligned = self.align_data(data);

        // Decrypt
        let result = subtle.decrypt_with_object_and_buffer_source(&params, &self.key, &aligned);

        // Parse result and remove zero-padding again.
        let array_buffer = JsFuture::from(result.unwrap()).await.unwrap().into();
        let decrypted = Uint8Array::new(&array_buffer);
        decrypted
            .subarray(self.block_index, decrypted.length())
            .copy_to(data);

        self.update(data);
    }
}
