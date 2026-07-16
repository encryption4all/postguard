//! Wire-format tripwire (EPIC issue #211).
//!
//! Pins the VERSION_V3 byte format against golden fixtures committed in
//! `testdata/wire-format-v3/` (sealed once by the published `@e4a/pg-wasm`,
//! with the key material to unseal them). If a change to `consts.rs`, the
//! bincode framing, or the header layout breaks these tests, every ciphertext
//! already in the wild — old encrypted emails and files — breaks identically.
//! That must be a deliberate, versioned decision: regenerate fixtures for the
//! NEW version (see the testdata README) and keep the old set decodable.
#![cfg(all(feature = "rust", feature = "stream"))]

use std::fs;
use std::path::PathBuf;

use pg_core::api::Parameters;
use pg_core::artifacts::{UserSecretKey, VerifyingKey};
use pg_core::client::rust::stream::UnsealerStreamConfig;
use pg_core::client::rust::UnsealerMemoryConfig;
use pg_core::client::Unsealer;
use pg_core::consts::{PREAMBLE_SIZE, PRELUDE, PRELUDE_SIZE, VERSION_SIZE, VERSION_V3};
use pg_core::kem::cgw_kv::CGWKV;

use serde::Deserialize;

fn testdata(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/wire-format-v3")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[derive(Deserialize)]
struct Meta {
    #[serde(rename = "recipientId")]
    recipient_id: String,
    #[serde(rename = "plaintextB64")]
    plaintext_b64: String,
}

struct Fixture {
    meta: Meta,
    vk: VerifyingKey,
    usk: UserSecretKey<CGWKV>,
    want: Vec<u8>,
}

fn fixture() -> Fixture {
    #[derive(Deserialize)]
    struct UskResponse {
        key: UserSecretKey<CGWKV>,
    }

    let meta: Meta = serde_json::from_slice(&testdata("meta.json")).expect("parse meta.json");
    let vk: Parameters<VerifyingKey> =
        serde_json::from_slice(&testdata("vk.json")).expect("parse vk.json");
    let usk: UskResponse = serde_json::from_slice(&testdata("usk.json")).expect("parse usk.json");
    let want = b64(&meta.plaintext_b64);

    Fixture {
        meta,
        vk: vk.public_key,
        usk: usk.key,
        want,
    }
}

/// The exact byte values of the wire constants. These are literals on
/// purpose: if someone edits `consts.rs`, this must fail — the constants ARE
/// the compatibility contract with every ciphertext ever produced.
#[test]
fn wire_constants_are_pinned() {
    assert_eq!(PRELUDE, [0x14, 0x8A, 0x8E, 0xA7], "PRELUDE bytes changed");
    assert_eq!(VERSION_V3, 2, "VERSION_V3 changed");
    assert_eq!(PREAMBLE_SIZE, 10, "preamble layout changed");
}

/// Both golden containers begin with the documented 10-byte preamble:
/// PRELUDE (4) || VERSION_V3 big-endian (2) || header length (4).
#[test]
fn golden_fixtures_carry_the_pinned_preamble() {
    for name in ["stream.bin", "mem.bin"] {
        let ct = testdata(name);
        assert!(ct.len() > PREAMBLE_SIZE, "{name}: too short");
        assert_eq!(&ct[..PRELUDE_SIZE], &PRELUDE, "{name}: prelude mismatch");
        let version = u16::from_be_bytes(
            ct[PRELUDE_SIZE..PRELUDE_SIZE + VERSION_SIZE]
                .try_into()
                .unwrap(),
        );
        assert_eq!(version, VERSION_V3, "{name}: version mismatch");
    }
}

/// The in-memory golden container must keep parsing (bincode header framing)
/// and decrypting (KEM + AEAD + signature verification) forever.
#[test]
fn golden_mem_fixture_unseals() {
    let f = fixture();
    let unsealer = Unsealer::<Vec<u8>, UnsealerMemoryConfig>::new(&testdata("mem.bin"), &f.vk)
        .expect("parse the golden in-memory container");
    let (plain, _verified) = unsealer
        .unseal(&f.meta.recipient_id, &f.usk)
        .expect("unseal the golden in-memory container");
    assert_eq!(plain, f.want, "decrypted plaintext changed");
}

/// The streaming golden container (what cryptify stores and clients upload)
/// must keep parsing and decrypting forever.
#[test]
fn golden_stream_fixture_unseals() {
    let f = fixture();
    let ct = testdata("stream.bin");

    let mut plain = Vec::new();
    futures::executor::block_on(async {
        let mut reader = futures::io::Cursor::new(&ct);
        let unsealer = Unsealer::<_, UnsealerStreamConfig>::new(&mut reader, &f.vk)
            .await
            .expect("parse the golden streaming container");
        unsealer
            .unseal(&f.meta.recipient_id, &f.usk, &mut plain)
            .await
            .expect("unseal the golden streaming container");
    });
    assert_eq!(plain, f.want, "decrypted plaintext changed");
}

/// Minimal std-only base64 decoder (standard alphabet, padded) — avoids a
/// dev-dependency for one meta field.
fn b64(s: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &c in s.as_bytes() {
        if c == b'=' {
            break;
        }
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .unwrap_or_else(|| panic!("invalid base64 byte {c}")) as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}
