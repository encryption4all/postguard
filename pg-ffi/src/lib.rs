use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::slice;

use futures::io::Cursor;
use ibe::kem::cgw_kv::CGWKV;
use pg_core::artifacts::{PublicKey, SigningKeyExt};
use pg_core::client::rust::stream::SealerStreamConfig;
use pg_core::client::Sealer;
use pg_core::identity::EncryptionPolicy;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_last_error(msg: &str) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg).unwrap_or_default();
    });
}

fn seal_impl(
    mpk_json: &str,
    policy_json: &str,
    pub_sign_key_json: &str,
    priv_sign_key_json: Option<&str>,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let mpk: PublicKey<CGWKV> =
        serde_json::from_str(mpk_json).map_err(|e| format!("failed to parse MPK: {e}"))?;

    let policy: EncryptionPolicy =
        serde_json::from_str(policy_json).map_err(|e| format!("failed to parse policy: {e}"))?;

    let pub_sign_key: SigningKeyExt = serde_json::from_str(pub_sign_key_json)
        .map_err(|e| format!("failed to parse pubSignKey: {e}"))?;

    let mut rng = rand::thread_rng();

    let sealer = Sealer::<_, SealerStreamConfig>::new(&mpk, &policy, &pub_sign_key, &mut rng)
        .map_err(|e| format!("failed to create sealer: {e}"))?;

    let sealer = if let Some(json) = priv_sign_key_json {
        let priv_sign_key: SigningKeyExt =
            serde_json::from_str(json).map_err(|e| format!("failed to parse privSignKey: {e}"))?;
        sealer.with_priv_signing_key(priv_sign_key)
    } else {
        sealer
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to create tokio runtime: {e}"))?;

    rt.block_on(async {
        let mut input = Cursor::new(plaintext);
        let mut output = Vec::new();

        sealer
            .seal(&mut input, &mut output)
            .await
            .map_err(|e| format!("seal failed: {e}"))?;

        Ok(output)
    })
}

/// Seal (encrypt + sign) plaintext data using PostGuard IBE (streaming mode).
///
/// # Arguments
/// - `mpk_json`: JSON string of the master public key (base64-encoded, e.g. `"\"<base64>\""`)
/// - `policy_json`: JSON string of the encryption policy map
/// - `pub_sign_key_json`: JSON string of the public signing key (`SigningKeyExt`)
/// - `priv_sign_key_json`: JSON string of the private signing key, or null
/// - `plaintext` + `plaintext_len`: input bytes to seal
/// - `output` + `output_len`: out-parameters for sealed ciphertext (allocated by Rust)
///
/// Returns 0 on success, -1 on error. Call `pg_last_error()` for the error message.
#[no_mangle]
pub unsafe extern "C" fn pg_seal(
    mpk_json: *const c_char,
    policy_json: *const c_char,
    pub_sign_key_json: *const c_char,
    priv_sign_key_json: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
    output: *mut *mut u8,
    output_len: *mut usize,
) -> i32 {
    let mpk_str = match CStr::from_ptr(mpk_json).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in mpk_json: {e}"));
            return -1;
        }
    };

    let policy_str = match CStr::from_ptr(policy_json).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in policy_json: {e}"));
            return -1;
        }
    };

    let pub_sign_str = match CStr::from_ptr(pub_sign_key_json).to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(&format!("invalid UTF-8 in pub_sign_key_json: {e}"));
            return -1;
        }
    };

    let priv_sign_str = if priv_sign_key_json.is_null() {
        None
    } else {
        match CStr::from_ptr(priv_sign_key_json).to_str() {
            Ok(s) => Some(s),
            Err(e) => {
                set_last_error(&format!("invalid UTF-8 in priv_sign_key_json: {e}"));
                return -1;
            }
        }
    };

    let plain = if plaintext.is_null() || plaintext_len == 0 {
        &[]
    } else {
        slice::from_raw_parts(plaintext, plaintext_len)
    };

    match seal_impl(mpk_str, policy_str, pub_sign_str, priv_sign_str, plain) {
        Ok(sealed) => {
            let len = sealed.len();
            let boxed = sealed.into_boxed_slice();
            let ptr = Box::into_raw(boxed) as *mut u8;
            *output = ptr;
            *output_len = len;
            0
        }
        Err(msg) => {
            set_last_error(&msg);
            -1
        }
    }
}

/// Free memory allocated by `pg_seal`.
#[no_mangle]
pub unsafe extern "C" fn pg_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        let _ = Box::from_raw(slice::from_raw_parts_mut(ptr, len));
    }
}

/// Get the last error message. Returns a pointer to a null-terminated UTF-8 string.
/// The pointer is valid until the next call to `pg_seal` on the same thread.
#[no_mangle]
pub extern "C" fn pg_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_seal_invalid_mpk() {
        let mpk = CString::new("\"invalid\"").unwrap();
        let policy = CString::new("{}").unwrap();
        let pub_sign = CString::new("{}").unwrap();
        let mut output: *mut u8 = std::ptr::null_mut();
        let mut output_len: usize = 0;

        let result = unsafe {
            pg_seal(
                mpk.as_ptr(),
                policy.as_ptr(),
                pub_sign.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                &mut output,
                &mut output_len,
            )
        };

        assert_eq!(result, -1);
        let err = unsafe { CStr::from_ptr(pg_last_error()) };
        let err_str = err.to_str().unwrap();
        assert!(!err_str.is_empty());
    }
}
