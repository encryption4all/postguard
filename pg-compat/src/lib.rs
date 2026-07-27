//! Reader half of the Rust wire-compat gate (issue #260, epic #247).
//!
//! `pg-core`'s `seal-samples` example seals a deterministic sample set with
//! HEAD; this crate opens that set with every **published** `pg-core` in the
//! support window (#252). A failure here means a wire change that looked
//! additive is not: ciphertexts produced after it ship would be unreadable by
//! SDKs already pinned in the field.
//!
//! The artifact layout is documented in `README.md` next to this file. It is
//! also what the Node half of the gate (#261) consumes, so treat the manifest
//! as a contract rather than an implementation detail.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Manifest schema this reader understands. A newer set is an error, not a
/// skip: silently reading nothing is the one failure mode a gate must not
/// have.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Environment variable naming the directory holding the sample set.
pub const ARTIFACTS_ENV: &str = "PG_COMPAT_ARTIFACTS";

/// `manifest.json` — the index of the sample set.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// Layout version of the set (see [`SUPPORTED_SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// Wire version the containers claim to be.
    pub wire_version: u16,
    /// File holding the PKG parameters with the verifying key.
    pub verifying_key: String,
    /// The sealed containers.
    pub cases: Vec<Case>,
}

/// One sealed container plus everything needed to open and check it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Case {
    /// Stable case name, used in failure messages.
    pub name: String,
    /// `"memory"` or `"stream"`.
    pub mode: String,
    /// File holding the sealed bytes.
    pub ciphertext: String,
    /// File holding the bytes a reader must recover.
    pub plaintext: String,
    /// Whether the payload carries a separate encrypted signing policy.
    pub private_signing: bool,
    /// Every recipient the container was sealed for.
    pub recipients: Vec<Recipient>,
}

/// A recipient of a [`Case`].
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    /// Identifier to pass to `unseal`.
    pub id: String,
    /// File holding that recipient's user secret key, shaped like a PKG key
    /// response.
    pub usk: String,
}

/// Locate the sample set: `$PG_COMPAT_ARTIFACTS`, or the directory the CI job
/// writes it to by default.
pub fn artifacts_dir() -> PathBuf {
    match std::env::var_os(ARTIFACTS_ENV) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/wire-compat/artifacts"),
    }
}

/// Read `manifest.json` from `dir`, refusing a layout this reader does not
/// understand.
pub fn read_manifest(dir: &Path) -> Manifest {
    let path = dir.join("manifest.json");
    let raw = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "read {}: {e}\nSeal the sample set first:\n  cargo run -p pg-core --features stream \
             --example seal-samples -- {}\nor point {ARTIFACTS_ENV} at an existing set.",
            path.display(),
            dir.display(),
        )
    });
    let manifest: Manifest =
        serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

    assert_eq!(
        manifest.schema_version, SUPPORTED_SCHEMA_VERSION,
        "artifact schema version {} is not the {SUPPORTED_SCHEMA_VERSION} this reader understands \
         — update pg-compat alongside the sealer",
        manifest.schema_version,
    );
    assert!(
        !manifest.cases.is_empty(),
        "the sample set lists no cases; the gate would pass without reading anything",
    );

    manifest
}

/// Read a file named by the manifest.
pub fn read_file(dir: &Path, name: &str) -> Vec<u8> {
    let path = dir.join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// A published `pg-core` that must be able to open the sample set.
pub struct Reader {
    /// Version as it appears on crates.io.
    pub version: &'static str,
    /// Opens every case in the set, returning one message per failure.
    pub verify: fn(&Path) -> Vec<String>,
}

/// Generates a reader module bound to one published `pg-core`.
///
/// Every supported version gets its own module because the versions are
/// distinct crates with distinct types; the macro keeps the check itself
/// written once.
macro_rules! reader {
    ($module:ident, $krate:ident, $version:literal) => {
        pub mod $module {
            use std::path::Path;

            use ::$krate as pg_core;
            use pg_core::api::Parameters;
            use pg_core::artifacts::{UserSecretKey, VerifyingKey};
            use pg_core::client::rust::stream::UnsealerStreamConfig;
            use pg_core::client::rust::UnsealerMemoryConfig;
            use pg_core::client::{Unsealer, VerificationResult};
            use pg_core::consts::VERSION_V3;
            use pg_core::kem::cgw_kv::CGWKV;

            use serde::Deserialize;

            use crate::{read_file, read_manifest};

            /// The crates.io version this module reads with.
            pub const VERSION: &str = $version;

            #[derive(Deserialize)]
            struct UskResponse {
                key: UserSecretKey<CGWKV>,
            }

            /// Open every case in `dir`, collecting a message per failure so a
            /// run reports all incompatible cases at once.
            pub fn verify(dir: &Path) -> Vec<String> {
                let manifest = read_manifest(dir);
                let mut failures = Vec::new();

                if manifest.wire_version != VERSION_V3 {
                    failures.push(format!(
                        "pg-core {VERSION}: sample set claims wire version {}, this reader \
                         speaks {VERSION_V3}",
                        manifest.wire_version,
                    ));
                    return failures;
                }

                let vk: Parameters<VerifyingKey> =
                    match serde_json::from_slice(&read_file(dir, &manifest.verifying_key)) {
                        Ok(vk) => vk,
                        Err(e) => {
                            failures.push(format!(
                                "pg-core {VERSION}: parse {}: {e}",
                                manifest.verifying_key,
                            ));
                            return failures;
                        }
                    };
                let vk = vk.public_key;

                for case in &manifest.cases {
                    let ct = read_file(dir, &case.ciphertext);
                    let want = read_file(dir, &case.plaintext);

                    for recipient in &case.recipients {
                        let usk: UskResponse =
                            match serde_json::from_slice(&read_file(dir, &recipient.usk)) {
                                Ok(usk) => usk,
                                Err(e) => {
                                    failures.push(format!(
                                        "pg-core {VERSION}: parse {}: {e}",
                                        recipient.usk,
                                    ));
                                    continue;
                                }
                            };

                        let opened = match case.mode.as_str() {
                            "memory" => open_memory(&ct, &vk, &recipient.id, &usk.key),
                            "stream" => open_stream(&ct, &vk, &recipient.id, &usk.key),
                            other => Err(format!("unknown mode {other}")),
                        };

                        let label = format!("pg-core {VERSION}: {}/{}", case.name, recipient.id);
                        match opened {
                            Err(e) => failures.push(format!("{label}: {e}")),
                            Ok((plain, verified)) => {
                                if plain != want {
                                    failures.push(format!(
                                        "{label}: recovered {} bytes, expected {}",
                                        plain.len(),
                                        want.len(),
                                    ));
                                }
                                if verified.private.is_some() != case.private_signing {
                                    failures.push(format!(
                                        "{label}: private signature present={}, manifest says {}",
                                        verified.private.is_some(),
                                        case.private_signing,
                                    ));
                                }
                            }
                        }
                    }
                }

                failures
            }

            fn open_memory(
                ct: &[u8],
                vk: &VerifyingKey,
                id: &str,
                usk: &UserSecretKey<CGWKV>,
            ) -> Result<(Vec<u8>, VerificationResult), String> {
                let unsealer = Unsealer::<Vec<u8>, UnsealerMemoryConfig>::new(ct, vk)
                    .map_err(|e| format!("parse: {e}"))?;
                unsealer.unseal(id, usk).map_err(|e| format!("unseal: {e}"))
            }

            fn open_stream(
                ct: &[u8],
                vk: &VerifyingKey,
                id: &str,
                usk: &UserSecretKey<CGWKV>,
            ) -> Result<(Vec<u8>, VerificationResult), String> {
                let mut plain = Vec::new();
                let verified = futures::executor::block_on(async {
                    let mut reader = futures::io::Cursor::new(ct);
                    let unsealer = Unsealer::<_, UnsealerStreamConfig>::new(&mut reader, vk)
                        .await
                        .map_err(|e| format!("parse: {e}"))?;
                    unsealer
                        .unseal(id, usk, &mut plain)
                        .await
                        .map_err(|e| format!("unseal: {e}"))
                })?;

                Ok((plain, verified))
            }
        }
    };
}

reader!(v0_6_1, pg_core_0_6_1, "0.6.1");

/// Every published reader in the support window.
pub fn readers() -> Vec<Reader> {
    vec![Reader {
        version: v0_6_1::VERSION,
        verify: v0_6_1::verify,
    }]
}
