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
