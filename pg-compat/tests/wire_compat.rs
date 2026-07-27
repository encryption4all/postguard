//! The gate itself: HEAD-sealed bytes must open with every published
//! `pg-core` in the support window.
//!
//! ```text
//! cargo run -p pg-core --features stream --example seal-samples -- target/wire-compat/artifacts
//! PG_COMPAT_ARTIFACTS=$PWD/target/wire-compat/artifacts \
//!   cargo test --manifest-path pg-compat/Cargo.toml --locked
//! ```

use pg_compat::{artifacts_dir, read_manifest, readers};

#[test]
fn published_readers_open_the_head_sealed_sample_set() {
    let dir = artifacts_dir();
    let manifest = read_manifest(&dir);
    let readers = readers();
    assert!(!readers.is_empty(), "no published readers configured");

    let mut failures = Vec::new();
    for reader in &readers {
        failures.extend((reader.verify)(&dir));
    }

    assert!(
        failures.is_empty(),
        "HEAD-sealed containers do not open with published pg-core:\n  {}\n\nA wire change that \
         old readers cannot follow is not additive: make it additive, or roll readers out before \
         writers.",
        failures.join("\n  "),
    );

    println!(
        "{} case(s) opened by {} published reader(s)",
        manifest.cases.len(),
        readers.len(),
    );
}
