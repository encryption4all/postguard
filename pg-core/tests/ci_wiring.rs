//! What CI's gates in `build.yml` are actually wired to (issue #272).
//!
//! Every gate in this repo lands in two halves: the code and tests go in a PR,
//! and the workflow YAML is applied by hand, because the `dobby-coder` App has
//! no `workflows: write`. **Nothing detected a missing second half.** It has
//! already happened twice (#265 merged `pg-compat` with no job calling it;
//! postguard-js#137 patched one workflow of two), and both times the PR was
//! green.
//!
//! `pg-pkg/tests/api_gate.rs` closed that hole for `api-diff.yml` by reading the
//! workflow back and asserting the inputs its verdicts depend on. This file is
//! the same instrument pointed at `build.yml`, which carries the three gates
//! nothing machine-read until now: `wire-compat-rust`, `wire-compat-js` and
//! `semver-checks`, plus the `wire-compat` job that aggregates the first two
//! into the repo's sole required check.
//!
//! Two failure classes, and they are not the same shape:
//!
//! 1. **The patch was never applied.** A step that does not exist runs nothing,
//!    a filter that lost a path never fires, and both report the same green as a
//!    gate that ran and passed. Everything below that pins a command, a filter
//!    path, or a step's guard is aimed here.
//!
//! 2. **The check was renamed out from under its enforcement (#299).** The
//!    ruleset `main: required checks` (`bypass_actors: []`) pins the literal
//!    context string `Wire compat`. A ruleset requiring a context that no job
//!    produces blocks nothing at all, so renaming the aggregator *disarms* the
//!    gate rather than breaking it. The other side of that link lives in
//!    GitHub's API and no test runner can read it; this side is one file away,
//!    which is what [`the_required_check_name_still_names_the_aggregator`]
//!    asserts.
//!
//! This file therefore lives in `pg-core` rather than beside the crate each gate
//! guards, and specifically not in `pg-compat`: `pg-compat`'s tests run *inside*
//! `wire-compat-rust`, so a guard living there would be skipped by exactly the
//! deletion it exists to catch. `Test workspace (pg-core)` runs unconditionally
//! on every push and every PR, and `pg-core` is the crate whose wire format and
//! public API these gates protect.
//!
//! It reads YAML as text on purpose. The workspace has no YAML parser and this
//! needs none: the assertions are about literal commands and literal names, and
//! a shape change that defeats the reader fails loudly here rather than being
//! quietly skipped.
//!
//! ```text
//! cargo test --manifest-path pg-core/Cargo.toml --features test,rust,stream --test ci_wiring
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// The context string the `main: required checks` ruleset pins (#299). It is
/// the `name:` of the aggregator job, and the ruleset is the only thing on this
/// repo that `gh pr merge --admin` cannot walk past, so this string is load
/// bearing in a way the job id is not.
const REQUIRED_CHECK: &str = "Wire compat";

/// The two halves the aggregator exists to combine (#262). Pinned so the name
/// above cannot be moved onto a job that checks less: a `Wire compat` reporting
/// on one half, or on none, satisfies the ruleset just as well.
const AGGREGATED_HALVES: [&str; 2] = ["wire-compat-rust", "wire-compat-js"];

/// `wire-compat-rust`'s path filter. Each entry is a way the sealed bytes can
/// change, and dropping one silently narrows the gate rather than breaking it:
/// `pg-core` resolves from the *root* lockfile, so a `bincode-next`/`ibe`/serde
/// bump touches only `Cargo.lock` and `Cargo.toml`, and `build.yml` is here so
/// that editing the gate re-runs it.
const WIRE_FILTER: [&str; 7] = [
    "pg-core/**",
    "pg-wasm/**",
    "pg-compat/**",
    "pg-compat-js/**",
    "Cargo.lock",
    "Cargo.toml",
    ".github/workflows/build.yml",
];

/// `semver-checks`'s path filter, same reasoning: the two published surfaces,
/// the manifests that decide what they resolve to, and the gate's own files.
const SEMVER_FILTER: [&str; 7] = [
    "pg-core/**",
    "pg-wasm/**",
    "Cargo.toml",
    "Cargo.lock",
    "scripts/semver-checks.sh",
    "scripts/semver-checks-test.sh",
    ".github/workflows/build.yml",
];

/// The sealer the whole wire gate is built on. `--locked` is part of the
/// contract, not a nicety: the bytes HEAD produces are a function of the root
/// lockfile, so a run that silently re-resolved would be measuring a tree that
/// was never committed.
const SEAL_COMMAND: &str = "cargo run --locked -p pg-core --features stream --example seal-samples";

/// The Rust reader half: `pg-compat` builds against crates.io `pg-core`, which
/// is what makes opening the sealed set mean anything. It has its own lockfile,
/// hence `--locked` again.
const OPEN_COMMAND: &str = "cargo test --manifest-path pg-compat/Cargo.toml --locked";

/// The one decision every conditional step in `wire-compat-rust` reads, so the
/// `push` override cannot be applied to the seal and forgotten on the open.
const GATE_CONDITION: &str = "steps.gate.outputs.run == 'true'";

/// The `push` override itself (#299). On a push the path filter answers the
/// wrong question -- it diffs only the push that triggered it, so a commit that
/// reached `main` without the gate ever running is never re-checked, and the job
/// still reports green because "filter said no" and "gate passed" are the same
/// `success`. Measured on #297, which merged with no run at all and was then
/// reported green three times.
const PUSH_OVERRIDE: &str = r#""$GITHUB_EVENT_NAME" == "push""#;

/// What `wire-compat-js` keys off instead of a second copy of the path filter,
/// so the two halves cannot drift into disagreeing about whether to run.
const SEALED_OUTPUT: &str = "needs.wire-compat-rust.outputs.sealed == 'success'";

fn workflow_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".github/workflows/build.yml")
}

fn workflow() -> String {
    let path = workflow_path();
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The body of the top-level job `id`: every line indented past the job's own
/// key, with the key line itself dropped.
///
/// Scanning starts after `jobs:` because `on:`'s own keys (`push:`,
/// `pull_request:`) sit at the same indent as a job id and would otherwise match.
/// A missing job panics rather than returning an empty block, so a deleted job
/// fails here instead of vacuously satisfying every assertion about it.
fn job(workflow: &str, id: &str) -> String {
    let body = workflow
        .split_once("\njobs:\n")
        .unwrap_or_else(|| panic!("no top-level `jobs:` in {}", workflow_path().display()))
        .1;

    let needle = format!("  {id}:");
    let mut lines = body.lines().skip_while(|line| line.trim_end() != needle);
    assert!(
        lines.next().is_some(),
        "{} has no job `{id}:`, so whatever this test asserts about it is vacuous",
        workflow_path().display(),
    );

    lines
        .take_while(|line| line.trim().is_empty() || line.starts_with("    "))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The ids of every top-level job, in file order.
fn job_ids(workflow: &str) -> Vec<String> {
    let body = workflow
        .split_once("\njobs:\n")
        .expect("no top-level `jobs:`")
        .1;
    body.lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("  ")?;
            if rest.starts_with(char::is_whitespace) || rest.starts_with('#') {
                return None;
            }
            rest.strip_suffix(':').map(str::to_owned)
        })
        .collect()
}

/// The value of a job-level `key:`, i.e. one at exactly four spaces of indent.
/// Step-level keys sit at six and behind a `- `, so `name:` here is the job's
/// display name and never a step's.
fn field(job: &str, key: &str) -> Option<String> {
    let needle = format!("{key}:");
    job.lines()
        .filter_map(|line| line.strip_prefix("    "))
        .filter(|rest| !rest.starts_with(char::is_whitespace) && !rest.starts_with('-'))
        .find_map(|rest| rest.strip_prefix(&needle))
        .map(|value| value.trim().to_owned())
}

/// A job's steps, one block of text each.
fn steps(job: &str) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();
    for line in job.lines().skip_while(|line| line.trim() != "steps:") {
        if line.starts_with("      - ") {
            steps.push(String::new());
        }
        if let Some(step) = steps.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    steps
}

/// The single step containing `needle`, or a panic naming what was looked for.
/// Requiring exactly one match is what stops a duplicated step from letting one
/// of two copies drift unchecked.
fn step_with<'a>(steps: &'a [String], needle: &str) -> &'a str {
    let found: Vec<&String> = steps.iter().filter(|step| step.contains(needle)).collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one step containing {needle:?} in {}, found {}",
        workflow_path().display(),
        found.len(),
    );
    found[0]
}

/// The paths of the single `dorny/paths-filter` filter in a job.
///
/// Read from the `filters: |` block literal rather than from the job at large,
/// so a quoted list elsewhere in the job cannot pad the set and make a narrowed
/// filter look intact.
fn filter_paths(job: &str) -> BTreeSet<String> {
    let mut lines = job.lines().skip_while(|line| line.trim() != "filters: |");
    let header = lines.next().expect("no `filters: |` block in the job");
    let indent = header.len() - header.trim_start().len();

    lines
        .take_while(|line| line.trim().is_empty() || line.len() - line.trim_start().len() > indent)
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("- "))
        .map(|path| path.trim_matches('\'').to_owned())
        .collect()
}

fn expected(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|p| (*p).to_owned()).collect()
}

/// The `#299` half: the ruleset pins a *name*, so the name has to keep pointing
/// at the job that aggregates both halves.
///
/// Asserted from the name inwards rather than from the job id outwards, because
/// the dangerous edit is not "the aggregator lost its name" but "the name now
/// belongs to something weaker". A `Wire compat` that needs one half, or none,
/// satisfies the ruleset exactly as well as the real one and certifies almost
/// nothing.
#[test]
fn the_required_check_name_still_names_the_aggregator() {
    let workflow = workflow();

    let named: Vec<String> = job_ids(&workflow)
        .into_iter()
        .filter(|id| field(&job(&workflow, id), "name").as_deref() == Some(REQUIRED_CHECK))
        .collect();

    assert_eq!(
        named.len(),
        1,
        "the `main: required checks` ruleset (bypass_actors: []) requires the context \
         {REQUIRED_CHECK:?}, and {} jobs in {} carry that name: {named:?}. A ruleset \
         requiring a context no job produces blocks nothing, so renaming this job disarms \
         the gate instead of breaking it -- rename the ruleset's context in the same change \
         (`gh api repos/encryption4all/postguard/rules/branches/main`).",
        named.len(),
        workflow_path().display(),
    );

    let aggregator = job(&workflow, &named[0]);
    let needs: BTreeSet<String> = field(&aggregator, "needs")
        .expect("the aggregator has no `needs:`")
        .trim_matches(['[', ']'].as_slice())
        .split(',')
        .map(|need| need.trim().to_owned())
        .collect();

    assert_eq!(
        needs,
        expected(&AGGREGATED_HALVES),
        "the job named {REQUIRED_CHECK:?} does not aggregate both halves of the wire gate, \
         so the repo's sole required check would go green on a run where one half never \
         passed",
    );

    // Without this the aggregator *skips* when a half fails, and a skipped
    // required check sits pending forever rather than turning red -- the one
    // outcome that looks like neither pass nor fail from the merge button.
    assert_eq!(
        field(&aggregator, "if").as_deref(),
        Some("${{ !cancelled() }}"),
        "the job named {REQUIRED_CHECK:?} must run even when an upstream half failed, or a \
         red half leaves the required check pending instead of failing it",
    );
}

/// The seal half: the filter that decides when it runs, the `push` override
/// that stops the filter answering the wrong question, and the two commands
/// that are the gate.
#[test]
fn the_rust_wire_gate_still_seals_and_opens_what_it_claims_to() {
    let job = job(&workflow(), "wire-compat-rust");
    let steps = steps(&job);

    assert_eq!(
        filter_paths(&job),
        expected(&WIRE_FILTER),
        "wire-compat-rust's path filter and this test disagree about what can change the \
         sealed bytes. A path dropped here does not fail the gate, it silently stops it \
         firing; if the filter was widened on purpose, widen WIRE_FILTER with it",
    );

    let gate = step_with(&steps, "id: gate");
    assert!(
        gate.contains(PUSH_OVERRIDE),
        "wire-compat-rust's gate step no longer bypasses the path filter on `push`. On a \
         push the filter diffs only the push that triggered it, so a commit that reached \
         `main` without this gate running is never re-checked -- and the job still reports \
         green, because \"filter said no\" and \"gate passed\" are the same success (#299)",
    );

    let seal = step_with(&steps, "id: seal");
    assert!(
        seal.contains(SEAL_COMMAND),
        "wire-compat-rust does not seal with `{SEAL_COMMAND}`, so the bytes the published \
         readers open are not the ones this tree produces",
    );
    assert!(
        seal.contains(GATE_CONDITION),
        "wire-compat-rust's seal step is not behind `{GATE_CONDITION}`, so it no longer \
         shares one decision with the open step and the `push` override can be applied to \
         one and forgotten on the other",
    );

    let open = step_with(&steps, OPEN_COMMAND);
    assert!(
        open.contains(GATE_CONDITION),
        "wire-compat-rust's open step is not behind `{GATE_CONDITION}`, so it no longer \
         shares one decision with the seal step",
    );

    assert!(
        job.contains("sealed: ${{ steps.seal.outcome }}"),
        "wire-compat-rust no longer publishes `sealed` from the seal step's outcome, which is \
         the only thing wire-compat-js gates on -- without it the Node half runs on nothing, \
         or not at all",
    );
}

/// The Node half: it must open the *same* bytes, which is what makes a
/// non-deterministic sealer unable to hide between the two readers.
#[test]
fn the_js_wire_gate_still_opens_the_bytes_the_rust_half_sealed() {
    let job = job(&workflow(), "wire-compat-js");
    let steps = steps(&job);

    assert_eq!(
        field(&job, "needs").as_deref(),
        Some("wire-compat-rust"),
        "wire-compat-js no longer depends on wire-compat-rust, so it cannot be holding both \
         readers to the same bytes",
    );
    assert_eq!(
        field(&job, "if").as_deref(),
        Some("${{ !cancelled() }}"),
        "wire-compat-js must still run when the Rust half failed: a red seal is exactly when \
         it is worth knowing whether the JS readers broke the same way, and the artifact is \
         uploaded before that job's read step for this reason",
    );

    let download = step_with(&steps, "actions/download-artifact");
    assert!(
        download.contains(SEALED_OUTPUT),
        "wire-compat-js's download is not gated on `{SEALED_OUTPUT}`, so it no longer keys \
         off the same outcome the seal did and the two halves can drift over whether to run",
    );

    let open = step_with(&steps, "run: npm test");
    assert!(
        open.contains(SEALED_OUTPUT) && open.contains("working-directory: pg-compat-js"),
        "wire-compat-js does not run `npm test` in pg-compat-js behind `{SEALED_OUTPUT}`, so \
         the published npm readers are not being pointed at the sealed set",
    );
}

/// The semver gate: it is a shell script in this repo, so the half that can
/// drift is the workflow's -- whether the script is still called, on what, and
/// whether the breaking-change declaration still comes off the PR title.
#[test]
fn the_semver_gate_still_calls_the_script_this_repo_pins() {
    let job = job(&workflow(), "semver-checks");
    let steps = steps(&job);

    assert_eq!(
        filter_paths(&job),
        expected(&SEMVER_FILTER),
        "semver-checks's path filter and this test disagree about which changes can break a \
         published API. A path dropped here silently stops the gate firing; if the filter \
         was widened on purpose, widen SEMVER_FILTER with it",
    );

    step_with(&steps, "./scripts/semver-checks-test.sh");

    let check = step_with(&steps, "./scripts/semver-checks.sh");
    assert!(
        check.contains("SEMVER_RELEASE_TYPE: ${{ steps.declared.outputs.release_type }}"),
        "semver-checks no longer passes SEMVER_RELEASE_TYPE from the declaration step, so \
         either every breaking change fails the gate or none of them do",
    );

    // The `!` in the PR *title* is the only accepted declaration, and this is
    // where that is enforced. A body-only `BREAKING CHANGE:` footer must never
    // be honoured: this repo squash-merges with COMMIT_MESSAGES, so the body
    // never reaches the commit release-plz reads, and a `fix(pg-core):` subject
    // would then cut a patch release of a break the gate had waved through.
    let declared = step_with(&steps, "id: declared");
    assert!(
        declared.contains("PR_TITLE: ${{ github.event.pull_request.title }}"),
        "the breaking-change declaration is no longer read off the PR title. It cannot be \
         read from the PR body: squash_merge_commit_message is COMMIT_MESSAGES, so the body \
         never reaches the commit release-plz reads",
    );
    assert!(
        declared.contains("release_type=major"),
        "the declaration step no longer emits `release_type=major`, so the `!` in a PR title \
         grants nothing and a declared break fails the gate anyway",
    );
}

/// The reader above is line-oriented, so a reformat of `build.yml` could leave
/// it matching nothing while every assertion still passed. This is the check
/// that the instrument itself still works: the jobs the other tests read must
/// be found, distinct, and non-empty.
#[test]
fn every_job_this_test_reads_is_still_found() {
    let workflow = workflow();
    let ids = job_ids(&workflow);

    for id in [
        "wire-compat-rust",
        "wire-compat-js",
        "semver-checks",
        "wire-compat",
    ] {
        assert!(
            ids.contains(&id.to_owned()),
            "{} has no job `{id}`, and this test is what was supposed to notice",
            workflow_path().display(),
        );
        let body = job(&workflow, id);
        assert!(
            field(&body, "name").is_some() && !steps(&body).is_empty(),
            "job `{id}` read back as {} lines with no name or no steps, so the reader in \
             this file no longer understands {}",
            body.lines().count(),
            workflow_path().display(),
        );
    }

    // `wire-compat` is a prefix of the other two ids: if the reader ever stops
    // distinguishing them, the aggregator test would read the seal job and pass
    // for the wrong reason.
    assert_ne!(
        job(&workflow, "wire-compat"),
        job(&workflow, "wire-compat-rust"),
        "the job reader is matching on a prefix, so `wire-compat` and `wire-compat-rust` \
         read back as the same block",
    );
}
