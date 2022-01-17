use crate::constants::*;
use crate::Error;
use aead::Buffer;
use js_sys::{Array, Object, Reflect, Uint8Array};
use std::convert::TryInto;
use wasm_bindgen::{prelude::*, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{AesGcmParams, Crypto, CryptoKey};

const MODE: &str = "AES-GCM";

// JS web workers do not support accessing web-sys::window(), so
// we have to import crypto using a custom binding.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = crypto, js_name = valueOf)]
    fn get_crypto() -> Crypto;
}

async fn get_key(key: &[u8]) -> Result<CryptoKey, Error> {
    let subtle = get_crypto().subtle();
    let algorithm: JsValue = Object::new().into();
    Reflect::set(
        &algorithm,
        &JsValue::from_str("name"),
        &JsValue::from_str(MODE),
    )
    .unwrap();

    let key_usages = Array::of2(&JsValue::from_str("encrypt"), &JsValue::from_str("decrypt"));
    let key_value: Uint8Array = key.into();
    let key_promise = subtle.import_key_with_object(
        "raw",
        &key_value.into(),
        &algorithm.into(),
        false,
        &key_usages,
    );

    JsFuture::from(key_promise.unwrap())
        .await
        .map(|v| v.into())
        .map_err(|_e| Error::KeyError)
}

/// One-shot encryption function, using WebCrypto's AES-GCM128.
///
/// The data in the buffer is replaced by it's ciphertext.
/// The buffer is also extended using the authentication tag.
pub async fn encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    data: &mut dyn Buffer,
) -> Result<(), Error> {
    let len = data.len();
    let subtle = get_crypto().subtle();

    let key_object = get_key(key).await?;

    let mut pars = AesGcmParams::new(MODE, &Uint8Array::from(iv));
    pars.additional_data(&Uint8Array::from(aad));
    pars.tag_length((TAG_SIZE * 8).try_into().unwrap());

    let plain = Uint8Array::from(&data.as_ref()[..]);
    let result = subtle.encrypt_with_object_and_buffer_source(&pars, &key_object, &plain);
    let array_buffer = JsFuture::from(result.unwrap()).await.unwrap().into();
    let ct = Uint8Array::new(&array_buffer);

    // copy the ciphertext, if there is any, it should fit.
    ct.subarray(0, len.try_into().unwrap())
        .copy_to(&mut data.as_mut()[..len]);

    // slice off the tag and extend the buffer with this tag.
    let tag = ct.slice(
        len.try_into().unwrap(),
        (len + TAG_SIZE).try_into().unwrap(),
    );

    data.extend_from_slice(tag.to_vec().as_slice()).unwrap();

    Ok(())
}

/// One-shot decryption function, using WebCrypto's AES-GCM128.
///
/// Expects a ciphertext and tag in the buffer.
/// Upon a correct decryption (a valid tag), the contents of the buffer
/// is overwritten with the plaintext and shrinked to not contain the tag.
pub async fn decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    data: &mut dyn Buffer,
) -> Result<(), Error> {
    let subtle = get_crypto().subtle();
    let len = data.len();

    let key_object = get_key(key).await?;

    let mut pars = AesGcmParams::new(MODE, &Uint8Array::from(iv));
    pars.additional_data(&Uint8Array::from(aad));
    pars.tag_length((TAG_SIZE * 8).try_into().unwrap());

    let ct = Uint8Array::from(&data.as_ref()[..]);
    let result = subtle.decrypt_with_object_and_buffer_source(&pars, &key_object, &ct);
    let array_buffer = JsFuture::from(result.unwrap()).await.unwrap().into();
    let plain = Uint8Array::new(&array_buffer);

    plain.copy_to(&mut data.as_mut()[..len - TAG_SIZE]);
    data.truncate(len - TAG_SIZE);

    Ok(())
}
