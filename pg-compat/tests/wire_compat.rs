//! The gate itself: HEAD-sealed bytes must open with every published
//! `pg-core` in the support window.
//!
//! ```text
//! cargo run -p pg-core --features stream --example seal-samples -- target/wire-compat/artifacts
//! PG_COMPAT_ARTIFACTS=$PWD/target/wire-compat/artifacts \
//!   cargo test --manifest-path pg-compat/Cargo.toml --locked
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use pg_compat::{artifacts_dir, read_manifest, readers, run_case};

/// The per-case child. Cargo builds it before this test runs.
const CASE_RUNNER: &str = env!("CARGO_BIN_EXE_pg-compat-case");

#[test]
fn published_readers_open_the_head_sealed_sample_set() {
    let dir = artifacts_dir();
    let manifest = read_manifest(&dir);
    // Absolute, because the children run somewhere else.
    let dir = fs::canonicalize(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));

    let readers = readers();
    assert!(!readers.is_empty(), "no published readers configured");

    // Children run here so that a core dump from an aborting reader lands
    // under target/ rather than in the working tree.
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cases");
    fs::create_dir_all(&scratch).unwrap_or_else(|e| panic!("{}: {e}", scratch.display()));

    let runner = Path::new(CASE_RUNNER);
    let mut failures = Vec::new();
    for reader in &readers {
        if manifest.wire_version != reader.wire_version {
            // Every case would fail the same way; say it once.
            failures.push(format!(
                "pg-core {}: sample set claims wire version {}, this reader speaks {}",
                reader.version, manifest.wire_version, reader.wire_version,
            ));
            continue;
        }
        for case in &manifest.cases {
            failures.extend(run_case(runner, &dir, &scratch, reader.version, &case.name));
        }
    }

    assert!(
        failures.is_empty(),
        "HEAD-sealed containers do not open with published pg-core:\n  {}\n\nA wire change that \
         old readers cannot follow is not additive: make it additive, or roll readers out before \
         writers.",
        failures.join("\n  "),
    );

    let versions: Vec<&str> = readers.iter().map(|r| r.version).collect();
    println!(
        "{} case(s) opened by published pg-core {}",
        manifest.cases.len(),
        versions.join(", "),
    );
}
