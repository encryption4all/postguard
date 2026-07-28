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
//!
//! Each case is opened in its own process, by the `pg-compat-case` binary this
//! crate also builds. A published reader handed a shifted header does not
//! always return an error: it can read a garbage length prefix, attempt a
//! multi-gigabyte allocation and abort. In-process that takes every remaining
//! case with it, and an abort is not a panic so `catch_unwind` cannot hold it.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output};

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
    /// Container version this published reader speaks. Checked against the
    /// manifest before any ciphertext is handed to it, so a bumped
    /// `VERSION_V3` is reported once rather than once per case.
    pub wire_version: u16,
    /// Opens one case with every recipient, returning one message per failure.
    pub verify_case: fn(&Path, &Manifest, &Case) -> Vec<String>,
}

/// Describe a plaintext mismatch.
///
/// Lengths alone are not enough. A wire change that alters the key schedule or
/// the nonce derivation corrupts the content while preserving its length, and
/// that payload-level break is exactly what the multi-segment case exists to
/// catch. This message is only ever printed when the gate is already red, so
/// it is the one place that has to carry information.
pub fn describe_plaintext_mismatch(got: &[u8], want: &[u8]) -> String {
    match got.iter().zip(want).position(|(a, b)| a != b) {
        Some(offset) => format!(
            "recovered {} bytes, expected {}; first difference at offset {offset} \
             (got {:#04x}, expected {:#04x})",
            got.len(),
            want.len(),
            got[offset],
            want[offset],
        ),
        None => format!(
            "recovered {} bytes, expected {}; the shorter is a prefix of the longer",
            got.len(),
            want.len(),
        ),
    }
}

/// Open one case in a child process and turn its outcome into failure
/// messages.
///
/// `runner` is the `pg-compat-case` binary; `scratch` is the directory the
/// child runs in, so a core dump from an aborting reader lands under `target/`
/// rather than in the working tree.
pub fn run_case(
    runner: &Path,
    dir: &Path,
    scratch: &Path,
    version: &str,
    case: &str,
) -> Vec<String> {
    let output = Command::new(runner)
        .arg(dir)
        .arg(version)
        .arg(case)
        .current_dir(scratch)
        .output()
        .unwrap_or_else(|e| panic!("run {}: {e}", runner.display()));

    child_failures(&format!("pg-core {version}: {case}"), &output)
}

/// Interpret a finished `pg-compat-case` run.
///
/// A child that exits non-zero with nothing on stdout never got as far as
/// reporting: that is what an allocation abort on a shifted header looks like.
/// Say so, and name the case, so one dead case does not read as a silent pass
/// and the run still lists the others.
pub fn child_failures(label: &str, output: &Output) -> Vec<String> {
    if output.status.success() {
        return Vec::new();
    }

    let reported: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if !reported.is_empty() {
        return reported;
    }

    vec![format!(
        "{label}: reader {} before it could report{}",
        exit_description(&output.status),
        stderr_tail(&output.stderr),
    )]
}

fn exit_description(status: &ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return format!("died on signal {signal}");
        }
    }
    match status.code() {
        Some(code) => format!("exited with status {code}"),
        None => "exited abnormally".to_string(),
    }
}

/// The last line of the child's stderr that says something, which for an
/// aborting reader is the allocation message and for a panicking one is the
/// panic message. Rust's backtrace hint is dropped: it is the last line of
/// both and it carries nothing.
fn stderr_tail(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let last = text
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty() && !line.starts_with("note: run with `RUST_BACKTRACE"));

    match last {
        Some(line) => format!(": {line}"),
        None => String::new(),
    }
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

            use crate::{describe_plaintext_mismatch, read_file, Case, Manifest};

            /// The crates.io version this module reads with.
            pub const VERSION: &str = $version;

            /// The container version this published reader speaks.
            pub const WIRE_VERSION: u16 = VERSION_V3;

            #[derive(Deserialize)]
            struct UskResponse {
                key: UserSecretKey<CGWKV>,
            }

            /// Open one case with every recipient, collecting a message per
            /// failure so a case reports all of its recipients at once.
            pub fn verify_case(dir: &Path, manifest: &Manifest, case: &Case) -> Vec<String> {
                let mut failures = Vec::new();

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
                                    "{label}: {}",
                                    describe_plaintext_mismatch(&plain, &want),
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
        wire_version: v0_6_1::WIRE_VERSION,
        verify_case: v0_6_1::verify_case,
    }]
}

/// The reader for one published version, by the name it has on crates.io.
pub fn reader(version: &str) -> Option<Reader> {
    readers().into_iter().find(|r| r.version == version)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cargo runs test binaries from the package root, so the aborting child
    /// below has to be pointed elsewhere or it drops a core file in the
    /// working tree.
    fn run(script: &str) -> Output {
        Command::new("sh")
            .arg("-c")
            .arg(script)
            .current_dir(std::env::temp_dir())
            .output()
            .expect("run sh")
    }

    /// The regression this crate's subprocess harness exists for: a published
    /// reader can abort instead of returning an error, and the run has to
    /// survive it with a message naming the case.
    #[cfg(unix)]
    #[test]
    fn an_aborting_case_is_reported_rather_than_taking_the_run_down() {
        let out = run("echo 'memory allocation of 21474836480 bytes failed' >&2; kill -ABRT $$");
        let failures = child_failures("pg-core 0.6.1: mem", &out);

        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].starts_with("pg-core 0.6.1: mem: reader died on signal 6"));
        assert!(failures[0].ends_with("memory allocation of 21474836480 bytes failed"));
    }

    #[test]
    fn a_case_that_reports_failures_passes_them_through() {
        let out = run("echo 'pg-core 0.6.1: mem/alice: parse: bad'; echo; exit 1");
        assert_eq!(
            child_failures("pg-core 0.6.1: mem", &out),
            vec!["pg-core 0.6.1: mem/alice: parse: bad".to_string()],
        );
    }

    #[test]
    fn a_case_that_opens_reports_nothing() {
        assert!(child_failures("pg-core 0.6.1: mem", &run("exit 0")).is_empty());
    }

    /// A silent non-zero exit must not read as a pass either.
    #[test]
    fn a_silent_non_zero_exit_is_still_a_failure() {
        let failures = child_failures("pg-core 0.6.1: mem", &run("exit 2"));
        assert_eq!(
            failures,
            vec!["pg-core 0.6.1: mem: reader exited with status 2 before it could report"],
        );
    }

    /// Equal lengths with different bytes is the payload-level break the
    /// multi-segment case exists to catch, so the message has to say more than
    /// the lengths.
    #[test]
    fn a_same_length_mismatch_names_the_first_differing_offset() {
        let message = describe_plaintext_mismatch(b"abcXe", b"abcde");
        assert!(
            message.contains("first difference at offset 3"),
            "{message}"
        );
        assert!(message.contains("got 0x58, expected 0x64"), "{message}");
    }

    #[test]
    fn a_truncated_plaintext_says_so() {
        let message = describe_plaintext_mismatch(b"abc", b"abcde");
        assert!(
            message.contains("recovered 3 bytes, expected 5"),
            "{message}"
        );
        assert!(message.contains("prefix"), "{message}");
    }
}
