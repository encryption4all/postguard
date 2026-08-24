//! Does the Rust half of the gate actually go red?
//!
//! `wire_compat.rs` only ever asserts that a good sample set opens, which is an
//! assertion a harness that has stopped reading also satisfies. This test hands
//! a published reader a copy of the set whose `manifest.json` promises the
//! *raw*, non-canonical sender value, and requires a failure naming the
//! mismatch.
//!
//! It is the counterpart of `pg-compat-js/test/gate-teeth.test.mjs`, and it
//! guards the newer of the two assertions: the JS half has compared the
//! recovered sender policy since #261, the Rust half only since #355.

use std::fs;
use std::path::{Path, PathBuf};

use pg_compat::{artifacts_dir, read_manifest, readers, run_case};

/// The per-case child. Cargo builds it before this test runs.
const CASE_RUNNER: &str = env!("CARGO_BIN_EXE_pg-compat-case");

/// The value `sample_set.rs` hands the sealer. `manifest.json` promises
/// `canonicalize` of it, so writing this back into the manifest is what a
/// sealer that stopped canonicalizing on its way to the wire would have
/// produced.
const RAW_SENDER: &str = " Sender@Sample.TEST ";

/// A throwaway copy of the sample set for `damage` to rewrite.
///
/// Under `CARGO_TARGET_TMPDIR` rather than a random temp directory, so a
/// failing run leaves the damaged copy where a reviewer can look at it and no
/// dev-dependency is needed for the naming.
fn with_damaged_set(name: &str, damage: impl FnOnce(&Path), body: impl FnOnce(&Path)) {
    let source = artifacts_dir();
    // Fail with read_manifest's "seal the sample set first" message rather than
    // an ENOENT from the copy loop below.
    read_manifest(&source);
    let source = fs::canonicalize(&source).unwrap_or_else(|e| panic!("{}: {e}", source.display()));

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));

    for entry in fs::read_dir(&source).unwrap_or_else(|e| panic!("{}: {e}", source.display())) {
        let entry = entry.unwrap_or_else(|e| panic!("{}: {e}", source.display()));
        if entry.path().is_file() {
            let to = dir.join(entry.file_name());
            fs::copy(entry.path(), &to).unwrap_or_else(|e| panic!("{}: {e}", to.display()));
        }
    }

    damage(&dir);
    body(&dir);
}

/// Rewrite `manifest.json` in place.
fn edit_manifest(dir: &Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = dir.join("manifest.json");
    let raw = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

    edit(&mut manifest);

    fs::write(
        &path,
        serde_json::to_vec_pretty(&manifest).expect("serialize the manifest"),
    )
    .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

/// The reader the teeth are checked with: the newest pin, so a failure here is
/// about the assertion rather than about an old release.
fn newest_reader() -> String {
    let readers = readers();
    let reader = readers.first().expect("no published readers configured");

    reader.version.to_string()
}

fn scratch() -> PathBuf {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cases");
    fs::create_dir_all(&scratch).unwrap_or_else(|e| panic!("{}: {e}", scratch.display()));

    scratch
}

/// The assertion #355 added: a manifest promising the raw sender value must not
/// agree with the canonical policy the container carries.
#[test]
fn a_manifest_promising_the_raw_sender_value_is_reported() {
    let version = newest_reader();

    with_damaged_set(
        "raw-sender",
        |dir| {
            edit_manifest(dir, |manifest| {
                let attribute = &mut manifest["sender"]["public"]["con"][0]["v"];
                assert!(
                    attribute.is_string(),
                    "the manifest has no sender.public conjunction to rewrite",
                );
                *attribute = serde_json::Value::String(RAW_SENDER.to_string());
            });
        },
        |dir| {
            let failures = run_case(Path::new(CASE_RUNNER), dir, &scratch(), &version, "mem");

            assert!(
                !failures.is_empty(),
                "a manifest promising {RAW_SENDER:?} was reported as opening cleanly",
            );
            assert!(
                failures
                    .iter()
                    .all(|f| f.contains("public signing policy is")),
                "{failures:?}",
            );
            // One per recipient, each naming which one it was.
            assert!(
                failures.iter().any(|f| f.contains("mem/alice")),
                "{failures:?}"
            );
            assert!(
                failures.iter().any(|f| f.contains("mem/bob")),
                "{failures:?}"
            );
        },
    );
}

/// The private half is guarded by a separate statement in the sealer
/// (`with_priv_signing_key`), so it needs its own tooth.
#[test]
fn a_manifest_promising_the_wrong_private_sender_value_is_reported() {
    let version = newest_reader();

    with_damaged_set(
        "wrong-private-sender",
        |dir| {
            edit_manifest(dir, |manifest| {
                let con = manifest["sender"]["private"]["con"]
                    .as_array_mut()
                    .expect("the manifest has no sender.private conjunction to rewrite");
                let attribute = con
                    .iter_mut()
                    .find(|a| a["t"] == "pbdf.sidn-pbdf.mobilenumber.mobilenumber")
                    .expect("sender.private carries no mobile number");
                attribute["v"] = serde_json::Value::String("+31 (0)6 1234 5678".to_string());
            });
        },
        |dir| {
            let failures = run_case(
                Path::new(CASE_RUNNER),
                dir,
                &scratch(),
                &version,
                "mem-privsig",
            );

            assert!(
                !failures.is_empty(),
                "a manifest promising a non-canonical private value was reported as opening \
                 cleanly",
            );
            assert!(
                failures
                    .iter()
                    .all(|f| f.contains("private signing policy is")),
                "{failures:?}",
            );
        },
    );
}
