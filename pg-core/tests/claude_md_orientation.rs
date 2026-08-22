//! Root `CLAUDE.md` is orientation, and nothing may refill it (encryption4all/dobby-code#689).
//!
//! It was 67,118 B at `af6116c`, the revision this cut was made against: every
//! trap, gate and dependency note any container had ever found in the workspace,
//! appended one bullet at a time because the prompt told each of them to write
//! what it learned into this file. That instruction is retired. Documentation
//! goes to docs.postguard.eu/repos/postguard, a durable check goes to the rule
//! bundle the host lands at `~/dobby-rules.md`, and a trap tied to one file goes
//! in a comment beside it -- this module being an example of the third.
//!
//! The 4,000 B cap is not cosmetic: it is the gate that decides whether a
//! container working this repo gets its cwd pointed at the clone. Above it, the
//! checkout is demoted to a sibling directory. So the size is load-bearing to a
//! reader who never opens the file, which is exactly the kind of constraint that
//! needs a test rather than a note.
//!
//! This lives in `pg-core` for the reason `ci_wiring.rs` beside it gives for the
//! same choice: `Test workspace (pg-core)` in `build.yml` carries no path filter,
//! so it runs on every PR -- including a PR that touches nothing but `CLAUDE.md`,
//! which is the shape this guard exists to catch. A guard filtered to the crate
//! it happens to sit in would be skipped by exactly that PR.
//!
//! ```text
//! cargo test --manifest-path pg-core/Cargo.toml --test claude_md_orientation
//! ```

use std::fs;
use std::path::PathBuf;

/// The cap from the host's cwd decision -- `CLAUDE_MD_CWD_MAX_BYTES` in
/// dobby-code's `docker/entrypoint.sh`, copied here because nothing spans the two
/// repos to keep them in step. Against an orientation file that lands near
/// 3,500 B it leaves room to add a part or reword a line, not room for a second
/// corpus. Raising it should be a decision, not a reflex.
const MAX_BYTES: u64 = 4_000;

/// The revision that holds the cut corpus. The old file is not migrated and not
/// reconstructed anywhere, so this SHA is its only address -- and three places
/// still send a reader to `CLAUDE.md` for content that now lives only there:
/// `scripts/ruleset-drift.sh`, `.github/workflows/api-diff.yml`, and the
/// wire-compat section of `CONTRIBUTING.md`. Dropping the pointer strands all of
/// them, which the byte count alone would not notice.
///
/// `cryptify/src/main.rs`'s `See CLAUDE.md` is deliberately not a fourth: it sits
/// in `mod api_gate_tests` and means `cryptify/CLAUDE.md`, which this cut did not
/// touch. Aiming it here would land a reader on the pg-pkg spec's paragraph in
/// the archive -- a different gate, different counts, and plausible enough to be
/// read as an answer.
const ARCHIVE_REV: &str = "af6116c";

fn repo_file(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(name)
}

#[test]
fn claude_md_stays_orientation_sized() {
    let path = repo_file("CLAUDE.md");
    let bytes = fs::metadata(&path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .len();
    assert!(
        bytes <= MAX_BYTES,
        "CLAUDE.md is {bytes} B, over the {MAX_BYTES} B cap. This file is ORIENTATION -- what this \
         repo is, its parts, what a change here reaches, and the archive pointer. Documentation \
         belongs at docs.postguard.eu/repos/postguard; a durable check belongs in the rule bundle \
         (delivered to the next container at ~/dobby-rules.md), not here. See encryption4all/dobby-code#689."
    );
}

#[test]
fn claude_md_still_names_the_revision_holding_the_corpus() {
    let path = repo_file("CLAUDE.md");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert!(
        body.contains(ARCHIVE_REV),
        "CLAUDE.md no longer names `{ARCHIVE_REV}`, the revision carrying the 67,118 B corpus this \
         file was cut from. That corpus was deliberately left in git history rather than migrated, \
         so the SHA is the only way back to it -- keep the `git show {ARCHIVE_REV}:CLAUDE.md` \
         pointer even when the surrounding prose changes."
    );
}

/// The two source comments reach the corpus through `CLAUDE.md`'s redirect, but
/// `CONTRIBUTING.md` names the revision itself: it is the one pointer aimed at a
/// human contributor -- someone whose `wire-compat` gate just went red -- and they
/// have no reason to open an agent-orientation file to be redirected a second time.
/// The cost of that shortcut is a second copy of the SHA, so pin the two together.
#[test]
fn contributing_md_points_at_the_same_revision() {
    let path = repo_file("CONTRIBUTING.md");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    assert!(
        body.contains(ARCHIVE_REV),
        "CONTRIBUTING.md no longer names `{ARCHIVE_REV}`. Its wire-compat section sends a \
         contributor to the wire-format note for whether their change is additive, and that note \
         is only at `git show {ARCHIVE_REV}:CLAUDE.md` -- without the SHA the pointer is a dead \
         end at the moment the gate is red. If the corpus moves, move it in both files."
    );
}
