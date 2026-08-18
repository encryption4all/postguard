//! The deterministic wire-compat sample set (issue #260).
//!
//! Everything here is a pure function of [`SEED`]: master keys, user secret
//! keys, signatures, IVs and therefore the sealed bytes. Two runs of the same
//! tree produce byte-identical artifacts, which is what makes a diff in CI
//! meaningful — a changed byte means the wire format changed, not that the
//! RNG moved.
//!
//! This file is compiled twice: once as part of the `seal-samples` example
//! (which writes the set to a directory) and once by
//! `pg-core/tests/sample_sealer.rs` (which checks it is deterministic and
//! round-trips with HEAD). The artifact layout is documented in
//! `pg-compat/README.md`.

use std::collections::BTreeMap;

use pg_core::api::{KeyResponse, Parameters};
use pg_core::artifacts::{PublicKey, SigningKey, SigningKeyExt, UserSecretKey, VerifyingKey};
use pg_core::client::rust::stream::SealerStreamConfig;
use pg_core::client::rust::SealerMemoryConfig;
use pg_core::client::Sealer;
use pg_core::consts::{SYMMETRIC_CRYPTO_DEFAULT_CHUNK, VERSION_2};
use pg_core::identity::{Attribute, EncryptionPolicy, Policy};
use pg_core::kem::cgw_kv::CGWKV;
use pg_core::kem::IBKEM;

use irma::{ProofStatus, SessionStatus};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Seed for every random value in the sample set. Changing it changes every
/// artifact byte, so don't — add a case instead.
pub const SEED: [u8; 32] = *b"postguard-wire-compat-sample-set";

/// Version of the manifest layout, bumped when the *artifact* shape changes
/// (not when a case is added). Readers must refuse a manifest they do not
/// understand rather than silently skip cases.
pub const SCHEMA_VERSION: u32 = 1;

/// Fixed policy timestamp (2024-01-01T00:00:00Z).
const TIMESTAMP: u64 = 1_704_067_200;

/// The sender identity that signs every sample.
///
/// Deliberately **not** in canonical form: the leading and trailing space and
/// the mixed case exercise both halves of the email rule. The sealer is handed
/// this value while the manifest promises `canonicalize` of it, so a reader that
/// derives the sender identity from the raw header bytes only agrees with the
/// signing key while canonicalization still reaches the wire.
const SENDER: &str = " Sender@Sample.TEST ";

/// Filename of the manifest that ties the set together.
pub const MANIFEST: &str = "manifest.json";

/// A recipient of every sample container.
struct Recipient {
    /// Identifier used as the map key in the header, and the one a reader
    /// passes to `unseal`.
    id: &'static str,
    /// File the recipient's user secret key is written to.
    usk_file: &'static str,
    /// The policy the USK is derived from.
    policy: Policy,
}

/// One sealed container in the set.
pub struct Case {
    /// Stable case name, also used by the JS half of the gate (#261).
    pub name: &'static str,
    /// `"memory"` or `"stream"`, matching the two [`Sealer`] flavours.
    pub mode: &'static str,
    /// File the ciphertext is written to.
    pub file: &'static str,
    /// File the expected plaintext is written to.
    pub plaintext_file: &'static str,
    /// Whether the payload signature uses a separate, encrypted signing
    /// policy (`with_priv_signing_key`).
    pub private_signing: bool,
    /// The bytes a reader must recover.
    pub plaintext: Vec<u8>,
}

/// Payload that spans more than one AEAD segment, so the sample set covers
/// the STREAM segment counter and the final-segment flag.
fn multi_segment_payload() -> Vec<u8> {
    let len = SYMMETRIC_CRYPTO_DEFAULT_CHUNK as usize + 4096;
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// The cases in the set, in a fixed order.
pub fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "mem",
            mode: "memory",
            file: "mem.bin",
            plaintext_file: "mem.plain",
            private_signing: false,
            plaintext: b"postguard wire-compat sample: in-memory container".to_vec(),
        },
        Case {
            name: "mem-privsig",
            mode: "memory",
            file: "mem-privsig.bin",
            plaintext_file: "mem-privsig.plain",
            private_signing: true,
            plaintext: b"postguard wire-compat sample: in-memory container, private signature"
                .to_vec(),
        },
        Case {
            name: "stream",
            mode: "stream",
            file: "stream.bin",
            plaintext_file: "stream.plain",
            private_signing: false,
            plaintext: b"postguard wire-compat sample: streaming container".to_vec(),
        },
        Case {
            name: "stream-privsig",
            mode: "stream",
            file: "stream-privsig.bin",
            plaintext_file: "stream-privsig.plain",
            private_signing: true,
            // Stream mode puts the private signature in the encrypted payload
            // trailer rather than in the header, so it is a different wire
            // surface from `mem-privsig` and needs its own case.
            plaintext: b"postguard wire-compat sample: streaming container, private signature"
                .to_vec(),
        },
        Case {
            name: "stream-multi-segment",
            mode: "stream",
            file: "stream-multi-segment.bin",
            plaintext_file: "stream-multi-segment.plain",
            private_signing: false,
            plaintext: multi_segment_payload(),
        },
    ]
}

fn recipients() -> Vec<Recipient> {
    vec![
        Recipient {
            id: "alice",
            usk_file: "usk-alice.json",
            policy: Policy {
                timestamp: TIMESTAMP,
                con: vec![Attribute::new(
                    "pbdf.sidn-pbdf.email.email",
                    Some("alice@sample.test"),
                )],
            },
        },
        Recipient {
            id: "bob",
            usk_file: "usk-bob.json",
            policy: Policy {
                timestamp: TIMESTAMP,
                con: vec![
                    Attribute::new("pbdf.gemeente.personalData.fullname", Some("Bob")),
                    Attribute::new("pbdf.sidn-pbdf.email.email", Some("bob@sample.test")),
                ],
            },
        },
    ]
}

/// The policy the sender signs the header with (public, visible to anyone).
fn public_sender_policy() -> Policy {
    Policy {
        timestamp: TIMESTAMP,
        con: vec![Attribute::new("pbdf.sidn-pbdf.email.email", Some(SENDER))],
    }
}

/// The policy the sender signs the payload with in the `*-privsig` cases
/// (encrypted, only visible to a recipient who can decrypt).
///
/// `fullname` carries no canonicalization rule and stays for the
/// different-attribute-type coverage the `*-privsig` cases have always had; the
/// mobile number is the non-canonical half. It covers the *phone* rule rather
/// than the email rule a second time, and picks the `(0)` trunk group on
/// purpose: dropping the parentheses while keeping the `0` yields
/// `+310612345678`, which passes an E.164 shape check and dials nowhere.
///
/// `canonical_signing_key` guards the public policy and `with_priv_signing_key`
/// canonicalizes this one in a separate statement, so a non-canonical value in
/// only one of the two leaves the other as blind as an all-canonical corpus.
fn private_sender_policy() -> Policy {
    Policy {
        timestamp: TIMESTAMP,
        con: vec![
            Attribute::new("pbdf.gemeente.personalData.fullname", Some("Sample Sender")),
            Attribute::new(
                "pbdf.sidn-pbdf.mobilenumber.mobilenumber",
                Some("+31 (0)6 1234 5678"),
            ),
        ],
    }
}

/// Seal the whole sample set and return it as `filename -> bytes`.
///
/// The result is a pure function of [`SEED`] and this file, so callers can
/// compare two invocations byte for byte.
pub fn build() -> BTreeMap<String, Vec<u8>> {
    let mut rng = ChaCha20Rng::from_seed(SEED);

    let (ibe_pk, ibe_msk) = CGWKV::setup(&mut rng);
    let (ibs_pk, ibs_sk) = ibs::gg::setup(&mut rng);
    let mpk = PublicKey::<CGWKV>(ibe_pk);
    let vk = VerifyingKey(ibs_pk);

    let recipients = recipients();
    let mut out = BTreeMap::new();

    // Encryption policy: one shared multi-recipient header for every case.
    let enc_policy: EncryptionPolicy = recipients
        .iter()
        .map(|r| (r.id.to_string(), r.policy.clone()))
        .collect();

    // User secret keys, shaped exactly like a PKG `/v2/request/.../key`
    // response so the same file feeds the Rust and the JS readers.
    for r in &recipients {
        let derived = r.policy.derive_kem::<CGWKV>().unwrap();
        let usk = UserSecretKey::<CGWKV>(CGWKV::extract_usk(
            Some(&mpk.0),
            &ibe_msk,
            &derived,
            &mut rng,
        ));
        let response = KeyResponse {
            status: SessionStatus::Done,
            proof_status: Some(ProofStatus::Valid),
            key: Some(usk),
        };
        out.insert(r.usk_file.to_string(), json(&response));
    }

    // The verifying key, shaped like the PKG's `/v2/parameters` response.
    let public = public_sender_policy();
    let private = private_sender_policy();
    let pub_sign_key = SigningKeyExt {
        key: SigningKey(ibs::gg::keygen(
            &ibs_sk,
            &public.derive_ibs().unwrap(),
            &mut rng,
        )),
        policy: public.clone(),
    };
    let priv_sign_key = SigningKeyExt {
        key: SigningKey(ibs::gg::keygen(
            &ibs_sk,
            &private.derive_ibs().unwrap(),
            &mut rng,
        )),
        policy: private.clone(),
    };

    out.insert(
        "vk.json".to_string(),
        json(&Parameters {
            format_version: 0,
            public_key: vk,
        }),
    );

    let cases = cases();
    for case in &cases {
        let bytes = match case.mode {
            "memory" => {
                let sealer = Sealer::<_, SealerMemoryConfig>::new(
                    &mpk,
                    &enc_policy,
                    &pub_sign_key,
                    &mut rng,
                )
                .unwrap();
                let sealer = if case.private_signing {
                    sealer.with_priv_signing_key(priv_sign_key.clone())
                } else {
                    sealer
                };
                sealer.seal(&case.plaintext).unwrap()
            }
            "stream" => {
                let mut sealer = Sealer::<_, SealerStreamConfig>::new(
                    &mpk,
                    &enc_policy,
                    &pub_sign_key,
                    &mut rng,
                )
                .unwrap();
                if case.private_signing {
                    sealer = sealer.with_priv_signing_key(priv_sign_key.clone());
                }
                // A size hint on the multi-segment case so the set covers a
                // populated `size_hint` in the header as well as the default.
                if case.plaintext.len() > SYMMETRIC_CRYPTO_DEFAULT_CHUNK as usize {
                    let len = case.plaintext.len() as u64;
                    sealer = sealer.with_size_hint((len, Some(len)));
                }

                let mut buf = Vec::new();
                futures::executor::block_on(async {
                    let mut input = futures::io::Cursor::new(&case.plaintext);
                    sealer.seal(&mut input, &mut buf).await.unwrap();
                });
                buf
            }
            other => panic!("unknown mode {other}"),
        };

        out.insert(case.file.to_string(), bytes);
        out.insert(case.plaintext_file.to_string(), case.plaintext.clone());
    }

    out.insert(MANIFEST.to_string(), manifest(&cases, &recipients));

    out
}

fn manifest(cases: &[Case], recipients: &[Recipient]) -> Vec<u8> {
    let recipients: Vec<_> = recipients
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "usk": r.usk_file,
            })
        })
        .collect();

    let cases: Vec<_> = cases
        .iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "mode": c.mode,
                "ciphertext": c.file,
                "plaintext": c.plaintext_file,
                "privateSigning": c.private_signing,
                "recipients": recipients,
            })
        })
        .collect();

    let manifest = serde_json::json!({
        "schemaVersion": SCHEMA_VERSION,
        "sealedBy": {
            "crate": "pg-core",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "wireVersion": VERSION_2,
        "verifyingKey": "vk.json",
        // The *canonical* forms, not the raw ones the sealer is handed. The
        // manifest is the expectation readers are checked against, so this
        // disagreement between what the caller passes and what the manifest
        // promises is what makes the non-canonical sender a test rather than
        // decoration. Derived with `canonical()` rather than written out, so
        // there is no second copy of the value to drift.
        "sender": {
            "public": public_sender_policy().canonical(),
            "private": private_sender_policy().canonical(),
        },
        "cases": cases,
    });

    json(&manifest)
}

/// Serialize as pretty JSON with a trailing newline, so a reviewer can read a
/// diff between two artifact sets.
fn json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut buf = serde_json::to_vec_pretty(value).unwrap();
    buf.push(b'\n');
    buf
}
