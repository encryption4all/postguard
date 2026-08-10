//! Every workspace member is copied by every Dockerfile built from the repo
//! root (#322).
//!
//! `cargo chef prepare` shells out to `cargo metadata`, which loads the
//! manifest of every member listed in the root `Cargo.toml` before any target
//! selection happens. A member the planner stage does not copy is therefore a
//! hard error even for an image that never compiles it:
//!
//! ```text
//! error: failed to load manifest for workspace member `/app/cryptify`
//! ```
//!
//! That is what adding `cryptify` to `members` in #277 did to `dev.Dockerfile`:
//! the other two Dockerfiles were patched, this one was missed, and because
//! nothing in this repo's CI builds it the break only surfaced in
//! `postguard-e2e`, whose stack builds the image. Its `e2e` workflow failed at
//! the image-build step for four days while reporting a Docker error that read
//! as unrelated.
//!
//! So the invariant is asserted here rather than in a Docker build: the next
//! member added to the workspace fails this test, in a job that already runs on
//! every PR, instead of a downstream repo's nightly.

use std::fs;
use std::path::{Path, PathBuf};

/// Dockerfiles built with the repo root as their context, so `cargo metadata`
/// runs against the root manifest and every member has to be present.
///
/// `cryptify/dev.Dockerfile` is deliberately absent: its compose file builds it
/// with `cryptify/` as the context, and it copies that crate's sources alone.
const ROOT_CONTEXT_DOCKERFILES: [&str; 3] = ["Dockerfile", "dev.Dockerfile", "cryptify/Dockerfile"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The `members` array of the root `[workspace]` table.
///
/// Hand-parsed to keep this test dependency-free. It reads the `members` key
/// only, so the `exclude` list (`pg-wasm`, `pg-compat`) stays out: those are not
/// workspace members and `cargo metadata` does not read their manifests.
fn workspace_members(manifest: &str) -> Vec<String> {
    let after_key = manifest
        .split_once("members")
        .map(|(_, rest)| rest)
        .expect("root Cargo.toml has a `members` key");
    let array = after_key
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(inner, _)| inner)
        .expect("`members` is followed by a [...] array");

    let members: Vec<String> = array
        .split(',')
        .map(|entry| entry.trim().trim_matches('"').to_string())
        .filter(|entry| !entry.is_empty())
        .collect();

    assert!(
        !members.is_empty(),
        "parsed no members out of the root Cargo.toml; the parser needs updating"
    );
    members
}

/// Whether `dockerfile` has a `COPY <member> ...` instruction.
///
/// `COPY --from=<stage>` lines are skipped: they move build artifacts between
/// stages and never carry a member's sources into the planner.
fn copies_member(dockerfile: &str, member: &str) -> bool {
    dockerfile.lines().any(|line| {
        let mut words = line.split_whitespace();
        if words.next() != Some("COPY") {
            return false;
        }
        words
            .next()
            .is_some_and(|source| !source.starts_with("--") && source == member)
    })
}

#[test]
fn every_root_context_dockerfile_copies_every_workspace_member() {
    let root = repo_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    let members = workspace_members(&manifest);

    for path in ROOT_CONTEXT_DOCKERFILES {
        let dockerfile =
            fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("read {path}: {e}"));

        let missing: Vec<&String> = members
            .iter()
            .filter(|member| !copies_member(&dockerfile, member))
            .collect();

        assert!(
            missing.is_empty(),
            "{path} does not copy workspace member(s) {missing:?}. \
             `cargo chef prepare` loads every member's manifest, so this image \
             fails to build with `failed to load manifest for workspace member`. \
             Add a `COPY <member> ./<member>` line to each stage that copies sources."
        );
    }
}

#[test]
fn the_dockerfile_list_is_the_set_of_root_context_dockerfiles() {
    // A new Dockerfile built from the repo root has to be added to
    // ROOT_CONTEXT_DOCKERFILES, or it is simply not covered above. Nothing in
    // the file itself says what context it is built with, so the check is that
    // every Dockerfile in the repo is either listed here or accounted for.
    const ROOT_CONTEXT_EXEMPT: [&str; 1] = ["cryptify/dev.Dockerfile"];

    let root = repo_root();
    let mut found: Vec<String> = Vec::new();
    for dir in ["", "cryptify"] {
        let entries = fs::read_dir(root.join(dir)).expect("read directory");
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with("Dockerfile") {
                found.push(Path::new(dir).join(name).to_string_lossy().into_owned());
            }
        }
    }
    found.sort();

    let mut known: Vec<String> = ROOT_CONTEXT_DOCKERFILES
        .iter()
        .chain(ROOT_CONTEXT_EXEMPT.iter())
        .map(|p| p.to_string())
        .collect();
    known.sort();

    assert_eq!(
        found, known,
        "the set of Dockerfiles changed; add each one to ROOT_CONTEXT_DOCKERFILES \
         (built from the repo root) or ROOT_CONTEXT_EXEMPT (built from its own directory)"
    );
}

#[test]
fn a_dockerfile_missing_a_member_is_caught() {
    // The failure the whole file exists to catch: dev.Dockerfile as it stood
    // between #277 and #322, with cryptify a member but not copied.
    let planner = "FROM chef AS planner\n\
                   COPY pg-core ./pg-core\n\
                   COPY pg-pkg ./pg-pkg\n\
                   COPY Cargo.toml Cargo.lock ./\n";
    assert!(copies_member(planner, "pg-core"));
    assert!(!copies_member(planner, "cryptify"));

    // `COPY --from=<stage>` is not a source copy, so it must not count as one.
    let cook = "COPY --from=planner /app/recipe.json recipe.json\n";
    assert!(!copies_member(cook, "--from=planner"));
    assert!(!copies_member(cook, "planner"));
}

#[test]
fn members_parses_the_members_key_and_not_exclude() {
    let manifest = "[workspace]\n\
                    members = [\"pg-core\", \"pg-cli\", \"cryptify\"]\n\
                    exclude = [\"pg-wasm\", \"pg-compat\"]\n";
    assert_eq!(
        workspace_members(manifest),
        ["pg-core", "pg-cli", "cryptify"]
    );
}
