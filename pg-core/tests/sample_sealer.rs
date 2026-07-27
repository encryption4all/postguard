//! Guards the wire-compat sample sealer (issue #260).
//!
//! The sealer feeds the `wire-compat-rust` gate, which runs against
//! *published* readers and therefore only ever runs in CI. These tests keep
//! the producer side honest inside `cargo test -p pg-core`: the set must be
//! deterministic, it must round-trip with HEAD, and the manifest must keep
//! naming every file it promises — a manifest that points at a missing file
//! makes the gate green for the wrong reason.
//!
//! Needs the `stream` feature for the streaming cases; CI runs pg-core with
//! `--features test,rust,stream`.
#![cfg(all(feature = "rust", feature = "stream"))]

#[path = "../examples/seal-samples/sample_set.rs"]
mod sample_set;

use std::collections::BTreeMap;

use pg_core::api::Parameters;
use pg_core::artifacts::{UserSecretKey, VerifyingKey};
use pg_core::client::rust::stream::UnsealerStreamConfig;
use pg_core::client::rust::UnsealerMemoryConfig;
use pg_core::client::Unsealer;
use pg_core::consts::VERSION_V3;
use pg_core::kem::cgw_kv::CGWKV;

use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "wireVersion")]
    wire_version: u16,
    #[serde(rename = "verifyingKey")]
    verifying_key: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    mode: String,
    ciphertext: String,
    plaintext: String,
    #[serde(rename = "privateSigning")]
    private_signing: bool,
    recipients: Vec<Recipient>,
}

#[derive(Deserialize)]
struct Recipient {
    id: String,
    usk: String,
}

#[derive(Deserialize)]
struct UskResponse {
    key: UserSecretKey<CGWKV>,
}

fn manifest(set: &BTreeMap<String, Vec<u8>>) -> Manifest {
    serde_json::from_slice(&set[sample_set::MANIFEST]).expect("parse manifest.json")
}

/// The whole point of a fixed seed: the same tree seals the same bytes. If
/// this fails, the gate can no longer tell "the wire format changed" from
/// "the RNG moved".
#[test]
fn sample_set_is_deterministic() {
    let first = sample_set::build();
    let second = sample_set::build();
    assert_eq!(
        first.keys().collect::<Vec<_>>(),
        second.keys().collect::<Vec<_>>(),
        "sample set file list changed between runs"
    );
    for (name, bytes) in &first {
        assert_eq!(bytes, &second[name], "{name} differs between two runs");
    }
}

/// Every file the manifest names must exist, and every file in the set must
/// be named by the manifest. A reader that cannot find a case skips it, and a
/// gate that skips everything is green and worthless.
#[test]
fn manifest_names_every_file() {
    let set = sample_set::build();
    let m = manifest(&set);

    assert_eq!(m.schema_version, sample_set::SCHEMA_VERSION);
    assert_eq!(m.wire_version, VERSION_V3);
    assert!(!m.cases.is_empty(), "manifest lists no cases");

    let mut named: Vec<String> = vec![sample_set::MANIFEST.to_string(), m.verifying_key.clone()];
    for case in &m.cases {
        assert!(
            matches!(case.mode.as_str(), "memory" | "stream"),
            "{}: unknown mode {}",
            case.name,
            case.mode
        );
        assert!(!case.recipients.is_empty(), "{}: no recipients", case.name);
        named.push(case.ciphertext.clone());
        named.push(case.plaintext.clone());
        named.extend(case.recipients.iter().map(|r| r.usk.clone()));
    }

    named.sort();
    named.dedup();
    let present: Vec<String> = set.keys().cloned().collect();
    assert_eq!(named, present, "manifest and sample set disagree on files");
}

/// HEAD must be able to read back what HEAD sealed, for both recipients of
/// every case. This is the trivial direction — but if it fails, the published
/// readers in the gate have no chance and the failure would be reported
/// against the wrong version.
#[test]
fn head_reads_back_every_case() {
    let set = sample_set::build();
    let m = manifest(&set);

    let vk: Parameters<VerifyingKey> =
        serde_json::from_slice(&set[&m.verifying_key]).expect("parse the verifying key");
    let vk = vk.public_key;

    for case in &m.cases {
        let ct = &set[&case.ciphertext];
        let want = &set[&case.plaintext];

        for recipient in &case.recipients {
            let usk: UskResponse =
                serde_json::from_slice(&set[&recipient.usk]).expect("parse a user secret key");

            let (plain, verified) = match case.mode.as_str() {
                "memory" => {
                    let unsealer = Unsealer::<Vec<u8>, UnsealerMemoryConfig>::new(ct.clone(), &vk)
                        .unwrap_or_else(|e| panic!("{}: parse: {e}", case.name));
                    assert_eq!(unsealer.version, VERSION_V3, "{}: version", case.name);
                    unsealer
                        .unseal(&recipient.id, &usk.key)
                        .unwrap_or_else(|e| panic!("{}/{}: unseal: {e}", case.name, recipient.id))
                }
                "stream" => {
                    let mut plain = Vec::new();
                    let verified = futures::executor::block_on(async {
                        let mut reader = futures::io::Cursor::new(ct);
                        let unsealer = Unsealer::<_, UnsealerStreamConfig>::new(&mut reader, &vk)
                            .await
                            .unwrap_or_else(|e| panic!("{}: parse: {e}", case.name));
                        assert_eq!(unsealer.version, VERSION_V3, "{}: version", case.name);
                        unsealer
                            .unseal(&recipient.id, &usk.key, &mut plain)
                            .await
                            .unwrap_or_else(|e| {
                                panic!("{}/{}: unseal: {e}", case.name, recipient.id)
                            })
                    });
                    (plain, verified)
                }
                other => panic!("{}: unknown mode {other}", case.name),
            };

            assert_eq!(&plain, want, "{}/{}: plaintext", case.name, recipient.id);
            assert_eq!(
                verified.private.is_some(),
                case.private_signing,
                "{}: private signature presence",
                case.name
            );
        }
    }
}
