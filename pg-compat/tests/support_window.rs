//! The crates.io half of #268: nothing compared the `Reader list` block in
//! `COMPATIBILITY.md` against what `pg-compat` actually pins, so a row could
//! drift from the manifest with nothing noticing — the same silent-green
//! class the wire-compat gate exists to close. This is the crates.io mirror
//! of `pg-compat-js/test/manifest.test.mjs`'s npm check.

use pg_compat::readers;
use pg_compat::support_window::{compatibility_doc, declared_crates_io_readers};

#[test]
fn the_support_window_is_the_crates_io_reader_list_in_compatibility_md() {
    let mut declared = declared_crates_io_readers(&compatibility_doc());
    declared.sort();

    let mut pinned: Vec<String> = readers()
        .into_iter()
        .map(|r| r.version.to_string())
        .collect();
    pinned.sort();

    assert_eq!(
        declared, pinned,
        "COMPATIBILITY.md's crates.io reader list and pg-compat's readers() have drifted; the \
         document decides",
    );
}

/// One pin per minor line, because two of them cannot resolve: `=0.6.1` and
/// `=0.6.3` are semver-compatible, so cargo unifies them to a single version
/// and the two `=` requirements conflict. The window is "the highest published
/// patch of each line", so moving a line is a replacement rather than an
/// addition — a trap `pg-compat/README.md`'s own example used to name, which
/// is why it is a test rather than a paragraph.
#[test]
fn no_two_pinned_readers_share_a_minor_line() {
    let mut seen: Vec<(String, String)> = Vec::new();

    for reader in readers() {
        let line = minor_line(reader.version);

        if let Some((_, other)) = seen.iter().find(|(l, _)| *l == line) {
            panic!(
                "pg-compat pins both {other} and {} on the {line} line; two same-minor `=` pins \
                 do not resolve, because cargo unifies semver-compatible requirements to one \
                 version. Replace the {line} pin instead of adding to it.",
                reader.version,
            );
        }

        seen.push((line, reader.version.to_string()));
    }
}

/// `major.minor` of a crates.io version, which is what decides whether two
/// pins are semver-compatible.
fn minor_line(version: &str) -> String {
    let mut parts = version.split('.');
    let major = parts
        .next()
        .unwrap_or_else(|| panic!("version {version} has no major component"));
    let minor = parts
        .next()
        .unwrap_or_else(|| panic!("version {version} has no minor component"));

    format!("{major}.{minor}")
}
