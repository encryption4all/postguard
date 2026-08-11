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
/// `cryptify/dev.Dockerfile` joined the list in #325. It had kept the
/// standalone layout the crate had before #277 — its own `Cargo.toml`,
/// `Cargo.lock` and `src` — which no longer describes anything: a workspace
/// member has no `cryptify/Cargo.lock`, and its `pg-core` path dependency
/// escapes a crate-directory context. So its context is the repo root too, and
/// the invariant below is now its invariant as well.
const ROOT_CONTEXT_DOCKERFILES: [&str; 4] = [
    "Dockerfile",
    "dev.Dockerfile",
    "cryptify/Dockerfile",
    "cryptify/dev.Dockerfile",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The `members` array of the root `[workspace]` table.
///
/// Hand-parsed to keep this test dependency-free. It reads the `members` key
/// only, so the `exclude` list (`pg-wasm`, `pg-compat`) stays out: those are not
/// workspace members and `cargo metadata` does not read their manifests.
fn workspace_members(manifest: &str) -> Vec<String> {
    // Match the key at the start of a line. `default-members` also ends in
    // "members", and it lists a subset, so reading that array instead would
    // quietly shrink what this test checks rather than fail it.
    let from_key: String = manifest
        .split_inclusive('\n')
        .skip_while(|line| !line.trim_start().starts_with("members"))
        .collect();
    assert!(
        !from_key.is_empty(),
        "root Cargo.toml has no `members` key at the start of a line"
    );
    let array = from_key
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

/// The workspace manifest, as it is spelled in a `COPY` line built from the
/// repo root.
const WORKSPACE_MANIFEST: &str = "Cargo.toml";

/// Whether `dockerfile` has a `COPY <path> ...` instruction.
fn copies_path(dockerfile: &str, path: &str) -> bool {
    dockerfile.lines().any(|line| {
        let mut words = line.split_whitespace();
        // Instruction keywords are case-insensitive to Docker: `copy` builds
        // exactly as `COPY`. Matching only the upper-case spelling would let a
        // lower-case Dockerfile read as copying no member at all, which
        // `stages_missing_members` then waves through as "not a source-copying
        // stage" — the guard goes green on precisely the file it should fail.
        if !words
            .next()
            .is_some_and(|word| word.eq_ignore_ascii_case("COPY"))
        {
            return false;
        }
        // `--from=<stage>` moves build artifacts between stages and never
        // carries a member's sources, so such a line is not a source copy.
        // Other leading flags (`--chown=`, `--link`) do precede a real source
        // and have to be skipped, or a legitimate
        // `COPY --chown=1000:1000 pg-core ./pg-core` reads as a missing member.
        let mut source = None;
        for word in words {
            if word.starts_with("--from=") {
                return false;
            }
            if !word.starts_with("--") {
                source = Some(word);
                break;
            }
        }
        source == Some(path)
    })
}

/// The stages of a Dockerfile: the `FROM` line that opens each one, and the
/// lines that follow it up to the next `FROM`.
///
/// Lines before the first `FROM` belong to no stage. Only `ARG` and comments
/// may appear there, so no `COPY` is lost.
fn stages(dockerfile: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in dockerfile.lines() {
        // Case-insensitive for the same reason as `copies_path`: a lower-case
        // `from` opens a stage, and missing it collapses the file to zero stages
        // and every assertion over them to vacuously true.
        if line.trim_start().to_ascii_uppercase().starts_with("FROM ") {
            out.push((line.trim().to_string(), String::new()));
        }
        if let Some((_, body)) = out.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    out
}

/// The stages of `dockerfile` that copy some workspace members but not all, as
/// (`FROM` line, missing members).
///
/// The invariant is per stage, not per file: each stage starts from its parent
/// image's filesystem, so `cargo chef prepare` in the planner and `cargo build`
/// in the builder each need every member present in their own stage. Matching
/// the file as one blob lets a `COPY cryptify` in the planner cover for a
/// missing one in the builder — which is exactly #277's mistake, one stage
/// along.
///
/// A stage that copies *no* member is not a source-copying stage: `Dockerfile`'s
/// runtime stage copies only the built binary and `entrypoint.sh`. A stage that
/// copies *some* must copy all.
///
/// Copying the root `Cargo.toml` overrides that escape, and closes the hole
/// #325 fell through. `cryptify/dev.Dockerfile` copied a `Cargo.toml` and a
/// `Cargo.lock` and no member at all, having kept the layout the crate had
/// before it joined the workspace — so "copies no member" waved it through
/// while `cargo chef prepare` in that same stage died on the first member it
/// could not read. A stage that copies the workspace manifest is standing up
/// the workspace, and cargo reads every member that manifest lists.
fn stages_missing_members<'a>(
    dockerfile: &str,
    members: &'a [String],
) -> Vec<(String, Vec<&'a str>)> {
    stages(dockerfile)
        .into_iter()
        .filter_map(|(from, body)| {
            let missing: Vec<&str> = members
                .iter()
                .map(String::as_str)
                .filter(|member| !copies_path(&body, member))
                .collect();
            let copies_no_member = missing.len() == members.len();
            if missing.is_empty() || (copies_no_member && !copies_path(&body, WORKSPACE_MANIFEST)) {
                return None;
            }
            Some((from, missing))
        })
        .collect()
}

#[test]
fn every_root_context_dockerfile_copies_every_workspace_member() {
    let root = repo_root();
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    let members = workspace_members(&manifest);

    for path in ROOT_CONTEXT_DOCKERFILES {
        let dockerfile =
            fs::read_to_string(root.join(path)).unwrap_or_else(|e| panic!("read {path}: {e}"));

        let incomplete = stages_missing_members(&dockerfile, &members);

        assert!(
            incomplete.is_empty(),
            "{path} has stage(s) that copy some workspace members but not all: \
             {incomplete:?}. Each stage starts from its parent image's filesystem, \
             and `cargo chef prepare` and `cargo build` both load every member's \
             manifest, so such a stage fails with `failed to load manifest for \
             workspace member`. Add a `COPY <member> ./<member>` line to every \
             stage that copies sources."
        );
    }
}

/// Every Dockerfile in the tree, relative to the repo root.
///
/// The whole tree, not the two directories that hold one today: a Dockerfile
/// added under any crate has to reach the assertion below, or it goes uncovered
/// exactly as `dev.Dockerfile` did. `target` and `node_modules` hold build
/// output and dot-directories hold VCS and tooling state, so none of them are
/// sources this repo builds an image from.
///
/// Both naming conventions count. This repo writes `<prefix>.Dockerfile`, but
/// `Dockerfile.<suffix>` is just as common, and one added under that spelling
/// would be invisible here. `.dockerignore` is neither, so it stays ignored.
fn dockerfiles_in(dir: &Path, prefix: &Path, found: &mut Vec<String>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = prefix.join(&name);
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            dockerfiles_in(&entry.path(), &path, found);
        } else if name.ends_with("Dockerfile") || name.starts_with("Dockerfile.") {
            found.push(path.to_string_lossy().into_owned());
        }
    }
}

#[test]
fn the_dockerfile_list_is_the_set_of_root_context_dockerfiles() {
    // A new Dockerfile built from the repo root has to be added to
    // ROOT_CONTEXT_DOCKERFILES, or it is simply not covered above. Nothing in
    // the file itself says what context it is built with, so the check is that
    // every Dockerfile in the repo is either listed here or accounted for.
    // Empty since #325 moved `cryptify/dev.Dockerfile` to the root context.
    // Kept rather than deleted: it is the answer for a Dockerfile built from its
    // own directory, and the assertion below needs somewhere to put one.
    const ROOT_CONTEXT_EXEMPT: [&str; 0] = [];

    let root = repo_root();
    let mut found: Vec<String> = Vec::new();
    dockerfiles_in(&root, Path::new(""), &mut found);
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
    assert!(copies_path(planner, "pg-core"));
    assert!(!copies_path(planner, "cryptify"));

    // `COPY --from=<stage>` is not a source copy, so it must not count as one.
    let cook = "COPY --from=planner /app/recipe.json recipe.json\n";
    assert!(!copies_path(cook, "--from=planner"));
    assert!(!copies_path(cook, "planner"));

    // Other leading flags do precede a real source, so skipping them is what
    // keeps a legitimate Dockerfile from reading as a missing member.
    assert!(copies_path(
        "COPY --chown=1000:1000 pg-core ./pg-core\n",
        "pg-core"
    ));
    assert!(copies_path("COPY --link pg-core ./pg-core\n", "pg-core"));

    // Docker does not care about the case of an instruction keyword, so neither
    // may this parser: `copy` is a real member copy.
    assert!(copies_path("copy pg-core ./pg-core\n", "pg-core"));
    assert!(!copies_path(
        "copy --from=planner /app/pg-core ./pg-core\n",
        "pg-core"
    ));
}

#[test]
fn a_stage_missing_a_member_is_caught() {
    let members = ["pg-core", "pg-pkg", "cryptify"].map(str::to_string);

    // #277's mistake one stage along, and the likeliest way it recurs: the
    // planner gets the new member and the builder does not. Matching the file
    // as one blob sees `COPY cryptify` once and calls the image covered, while
    // `cargo build` in the builder dies on the manifest it cannot read.
    let planner_only = "FROM chef AS planner\n\
                        COPY pg-core ./pg-core\n\
                        COPY pg-pkg ./pg-pkg\n\
                        COPY cryptify ./cryptify\n\
                        RUN cargo chef prepare --recipe-path recipe.json\n\
                        FROM chef AS builder\n\
                        COPY --from=planner /app/recipe.json recipe.json\n\
                        COPY pg-core ./pg-core\n\
                        COPY pg-pkg ./pg-pkg\n\
                        RUN cargo build --bin pg-pkg\n";
    assert_eq!(
        stages_missing_members(planner_only, &members),
        [("FROM chef AS builder".to_string(), vec!["cryptify"])]
    );

    // #325's shape, and the reason "copies no member" cannot be the whole
    // escape: `cryptify/dev.Dockerfile` copied the manifest and the lockfile and
    // no member at all, so every member read as missing and the stage was waved
    // through — while `cargo chef prepare` on the line below died on the first
    // member it could not read. Copying the workspace manifest is the tell.
    let manifest_but_no_member = "FROM chef AS planner\n\
                                  COPY Cargo.toml .\n\
                                  COPY Cargo.lock .\n\
                                  COPY src ./src\n\
                                  RUN cargo chef prepare --recipe-path recipe.json\n";
    assert_eq!(
        stages_missing_members(manifest_but_no_member, &members),
        [(
            "FROM chef AS planner".to_string(),
            vec!["pg-core", "pg-pkg", "cryptify"]
        )]
    );

    // A runtime stage copies files but no member, so it is not a source-copying
    // stage and must not be reported as missing every member. It copies no
    // Cargo.toml either, so the override above does not drag it back in.
    let with_runtime = "FROM chef AS builder\n\
                        COPY pg-core ./pg-core\n\
                        COPY pg-pkg ./pg-pkg\n\
                        COPY cryptify ./cryptify\n\
                        RUN cargo build --bin pg-pkg\n\
                        FROM debian:trixie-slim\n\
                        COPY --from=builder /app/target/release/pg-pkg /usr/local/bin/pg-pkg\n\
                        COPY entrypoint.sh /entrypoint.sh\n";
    assert!(stages_missing_members(with_runtime, &members).is_empty());

    // A lower-case Dockerfile is a valid Dockerfile, and it must not disable the
    // guard. This one case covers both halves at once, which is the point: with
    // only `stages` case-insensitive the stage is found but no `copy` counts, so
    // every member reads as missing and the "not a source-copying stage" escape
    // skips it; with only `copies_path` case-insensitive there are no stages to
    // check. Either way the result is an empty vec and this assertion fails.
    let lowercase = "from chef as planner\n\
                     copy pg-core ./pg-core\n\
                     copy pg-pkg ./pg-pkg\n\
                     run cargo chef prepare --recipe-path recipe.json\n";
    assert_eq!(
        stages_missing_members(lowercase, &members),
        [("from chef as planner".to_string(), vec!["cryptify"])]
    );
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

    // `default-members` ends in "members" and lists a subset, so a substring
    // match would read it instead and check fewer crates without saying so.
    let with_default = "[workspace]\n\
                        default-members = [\"pg-pkg\"]\n\
                        members = [\"pg-core\", \"pg-cli\", \"cryptify\"]\n";
    assert_eq!(
        workspace_members(with_default),
        ["pg-core", "pg-cli", "cryptify"]
    );
}
