//! The support window as `COMPATIBILITY.md` declares it.
//!
//! `pg-compat/Cargo.toml`'s renamed dependencies (and the `readers()` they
//! back) are this crate's copy of the crates.io half of that list, and a copy
//! is only worth having if something compares it to the original. The
//! `Reader list` section of `COMPATIBILITY.md` is a fenced block of
//! `<registry> <package> <versions...>` rows for that reason, so the drift
//! that matters — the window growing in the normative document while the
//! gate keeps testing the versions it always tested — is a red run rather
//! than an unnoticed one. Mirrors `pg-compat-js/src/support-window.mjs`,
//! which does the same for the npm rows.
//!
//! Reformatting the block into prose or a table breaks the test in
//! `tests/support_window.rs` on purpose: the check is what makes the
//! sentence in the document true.

use std::fs;
use std::path::{Path, PathBuf};

/// The document the reader list is declared in.
pub fn compatibility_doc() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../COMPATIBILITY.md")
}

/// First line of the block, and what marks it as the one to parse.
const HEADER: &str = "# <registry> <package> <versions...>";

/// The crates.io `pg-core` versions `COMPATIBILITY.md` declares as readers.
pub fn declared_crates_io_readers(path: &Path) -> Vec<String> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    parse_crates_io_readers(&text, &path.display().to_string())
}

/// @param text the document
/// @param what what to name when there is nothing to parse
/// @returns one entry per version on a `crates.io` row
pub fn parse_crates_io_readers(text: &str, what: &str) -> Vec<String> {
    let rows = reader_list_block(text).unwrap_or_else(|| {
        panic!(
            "{what} has no reader-list block: expected a fenced block whose first line is \
             \"{HEADER}\""
        )
    });

    let mut versions = Vec::new();
    for row in rows {
        let trimmed = row.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut fields = trimmed.split_whitespace();
        let registry = fields.next().unwrap_or_default();
        let package = fields.next().unwrap_or_default();
        let row_versions: Vec<&str> = fields.collect();

        if registry != "crates.io" {
            continue;
        }
        if row_versions.is_empty() {
            panic!("{what}: the crates.io row for {package} lists no version");
        }
        assert_eq!(
            package, "pg-core",
            "{what}: unexpected crates.io package {package}, pg-compat only reads pg-core",
        );
        versions.extend(row_versions.into_iter().map(str::to_string));
    }

    // An empty list would compare equal to nothing and make the drift check
    // vacuous, which is the failure this module exists to catch.
    assert!(
        !versions.is_empty(),
        "{what}: the reader-list block holds no crates.io row",
    );

    versions
}

/// The rows of the fenced block whose first line is [`HEADER`], or `None`
/// when the document has no such block.
fn reader_list_block(text: &str) -> Option<Vec<&str>> {
    let mut inside_fence = false;
    let mut rows: Option<Vec<&str>> = None;

    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            if rows.is_some() {
                return rows;
            }
            inside_fence = !inside_fence;
            continue;
        }

        if let Some(r) = rows.as_mut() {
            r.push(line);
        } else if inside_fence && line.trim() == HEADER {
            rows = Some(Vec::new());
        }
    }

    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_with_no_fenced_block_is_an_error() {
        let result = std::panic::catch_unwind(|| parse_crates_io_readers("prose, no block", "doc"));
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "holds no crates.io row")]
    fn a_block_with_only_npm_rows_is_an_error() {
        parse_crates_io_readers(
            "```\n# <registry> <package> <versions...>\nnpm @e4a/pg-js 2.3.3\n```\n",
            "doc",
        );
    }

    #[test]
    #[should_panic(expected = "lists no version")]
    fn a_crates_io_row_with_no_version_is_an_error() {
        parse_crates_io_readers(
            "```\n# <registry> <package> <versions...>\ncrates.io pg-core\n```\n",
            "doc",
        );
    }

    #[test]
    fn a_well_formed_block_yields_every_declared_version() {
        let versions = parse_crates_io_readers(
            "```\n# <registry> <package> <versions...>\ncrates.io pg-core 0.6.1 0.5.10\nnpm \
             @e4a/pg-js 2.3.3\n```\n",
            "doc",
        );
        assert_eq!(versions, vec!["0.6.1", "0.5.10"]);
    }
}
