//! Pins `release-plz.toml`'s `semver_check = false` (#426, #430).
//!
//! That setting is only safe because `pg-core` -- the only `publish = true`
//! crate release-plz's own check would have covered -- is already checked
//! against the same crates.io baseline by the required `semver-checks` job.
//! `pg-core/tests/ci_wiring.rs`'s `the_semver_gate_still_calls_the_script_this_repo_pins`
//! pins that that job still calls `scripts/semver-checks.sh`. This test does
//! not duplicate that premise, only the setting that depends on it staying
//! true. If that other test is ever deleted, this setting stops being safe;
//! a reader who finds one must be able to find the other.
//!
//! It reads the file as text, not as parsed TOML: `pg-core`'s
//! `[dev-dependencies]` has no `toml` crate, and one line does not earn it.

use std::fs;
use std::path::PathBuf;

fn release_plz_toml_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("release-plz.toml")
}

/// The file, with line endings normalised -- `core.autocrlf=true` is the Git
/// for Windows default, and the line-oriented scan below needs `\n` anchors.
fn release_plz_toml() -> String {
    let path = release_plz_toml_path();
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

#[test]
fn semver_check_stays_off() {
    let toml = release_plz_toml();

    // A formatter or a human may reflow `semver_check = false` to
    // `semver_check=false` or add extra spaces around the `=`; that is still
    // the setting this test pins. So whitespace inside a candidate line is
    // stripped before comparing, which accepts any of those but still rejects
    // `semver_check = true`, and a `#`-commented-out line is skipped rather
    // than read as the setting itself.
    let still_off = toml
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            line.chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
        })
        .any(|line| line == "semver_check=false");

    assert!(
        still_off,
        "{} no longer sets `semver_check = false` in [workspace], so release-plz's \
         release-pr run is back to recomputing a semver check the required semver-checks \
         job already ran -- the ~8½-minute window that loses release-PR changelog updates \
         (#412, #426, #430)",
        release_plz_toml_path().display(),
    );
}
