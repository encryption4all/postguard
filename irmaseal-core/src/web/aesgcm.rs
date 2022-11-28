use crate::consts::*;
use js_sys::{Array, Object, Reflect, Uint8Array};
use wasm_bindgen::{prelude::*, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesGcmParams, Crypto, CryptoKey};

const MODE: &str = "AES-GCM";

// JS web workers do not support accessing web-sys::window(), so
// we have to import crypto using a custom binding.
#[wasm_bindgen]
extern "C" {
    #[allow(unsafe_code)]
    #[wasm_bindgen(js_namespace = crypto, js_name = valueOf)]
    fn get_crypto() -> Crypto;
}

pub async fn get_key(key: &[u8]) -> Result<CryptoKey, JsValue> {
    let subtle = get_crypto().subtle();
    let algorithm: JsValue = Object::new().into();
    Reflect::set(
        &algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str(MODE),
    )?;

    let key_usages = Array::of2(&JsValue::from_str("encrypt"), &JsValue::from_str("decrypt"));
    let key_value: Uint8Array = key.into();
    let key_promise = subtle.import_key_with_object(
        "raw",
        &key_value.into(),
        &algorithm.into(),
        false,
        &key_usages,
    )?;

    JsFuture::from(key_promise).await.map(|k| k.into())
}

/// One-shot encryption function, using WebCrypto's AES-GCM128.
///
/// The data in the buffer is replaced by its ciphertext.  The buffer is also extended using the
/// authentication tag.
pub async fn encrypt(
    key: &CryptoKey,
    iv: &[u8],
    aad: &Uint8Array,
    data: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let subtle = get_crypto().subtle();

    let mut pars = AesGcmParams::new(MODE, &Uint8Array::from(iv));
    pars.additional_data(aad);
    pars.tag_length((TAG_SIZE * 8).try_into().unwrap()); // This can never fail, since the input is
                                                         // constant.

    let result = subtle.encrypt_with_object_and_buffer_source(&pars, key, data)?;
    let array_buffer = JsFuture::from(result).await?;
    let ct = Uint8Array::new(&array_buffer);

    Ok(ct)
}

/// One-shot decryption function, using WebCrypto's AES-GCM128.
///
/// Expects a ciphertext and tag in the buffer.  Upon a correct decryption (a valid tag), the
/// contents of the buffer is overwritten with the plaintext and shrinked to not contain the tag.
pub async fn decrypt(
    key: &CryptoKey,
    iv: &[u8],
    aad: &Uint8Array,
    data: &Uint8Array,
) -> Result<Uint8Array, JsValue> {
    let subtle = get_crypto().subtle();

    let mut pars = AesGcmParams::new(MODE, &Uint8Array::from(iv));
    pars.additional_data(aad);
    pars.tag_length((TAG_SIZE * 8).try_into().unwrap());

    let result = subtle.decrypt_with_object_and_buffer_source(&pars, key, data)?;
    let array_buffer = JsFuture::from(result).await?;
    let plain = Uint8Array::new(&array_buffer);

    Ok(plain)
}
