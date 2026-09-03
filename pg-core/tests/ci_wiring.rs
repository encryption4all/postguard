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
//! 3. **The required check stopped being able to fail.** Worse than either, and
//!    it looks like neither: an aggregator that keeps its name, keeps its
//!    `needs` and reads neither result reports success however its halves
//!    ended. `needs` makes results available; only the step that reads them
//!    turns a red half into a red check.
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

/// The two workflow files this suite reads. Named rather than hardcoded
/// inside `workflow_path`/`workflow` (#412) so a second workflow -- first
/// `delivery.yml`, and whatever comes after it -- gets the same reader
/// instead of a copy of it.
const BUILD_WORKFLOW: &str = "build.yml";
const DELIVERY_WORKFLOW: &str = "delivery.yml";

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

/// The coverage script `delivery.yml`'s `changelog-coverage` job must call
/// (#412). Pinned so a rename of the script disarms the job -- an empty step
/// that still runs and still reports green -- rather than failing it.
const CHANGELOG_COVERAGE_COMMAND: &str = "scripts/changelog-coverage.sh";

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

/// The `pull_request` types the gates' verdicts depend on. Only `edited` is not
/// a default, and it is the load-bearing one: see
/// [`a_retitled_or_retargeted_pr_still_re_runs_the_gates`].
const PULL_REQUEST_TYPES: [&str; 4] = ["opened", "synchronize", "reopened", "edited"];

fn workflow_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(".github/workflows")
        .join(file)
}

/// The named workflow, with line endings normalised.
///
/// `read_to_string` keeps whatever git wrote, and `core.autocrlf=true` is the
/// Git for Windows default, so on a Windows checkout the `\njobs:\n` anchor
/// below is looking for bytes the file does not contain. Every reader here is
/// line-oriented and line endings carry no meaning in YAML, so normalising once
/// is cheaper and more durable than a `.gitattributes` entry: it holds however
/// the tree was checked out. (`pg-pkg/api-description.yaml` needs the
/// `.gitattributes` route because its anchors are multi-line *content*, which
/// cannot be normalised away without changing what is being matched.)
fn workflow(file: &str) -> String {
    let path = workflow_path(file);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The body of the top-level job `id`: every line indented past the job's own
/// key, with the key line itself dropped.
///
/// Scanning starts after `jobs:` because `on:`'s own keys (`push:`,
/// `pull_request:`) sit at the same indent as a job id and would otherwise match.
/// A missing job panics rather than returning an empty block, so a deleted job
/// fails here instead of vacuously satisfying every assertion about it.
fn job(workflow: &str, id: &str, file: &str) -> String {
    let body = workflow
        .split_once("\njobs:\n")
        .unwrap_or_else(|| panic!("no top-level `jobs:` in {}", workflow_path(file).display()))
        .1;

    let needle = format!("  {id}:");
    let mut lines = body.lines().skip_while(|line| line.trim_end() != needle);
    assert!(
        lines.next().is_some(),
        "{} has no job `{id}:`, so whatever this test asserts about it is vacuous",
        workflow_path(file).display(),
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
fn step_with<'a>(steps: &'a [String], needle: &str, file: &str) -> &'a str {
    let found: Vec<&String> = steps.iter().filter(|step| step.contains(needle)).collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one step containing {needle:?} in {}, found {}",
        workflow_path(file).display(),
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
    let workflow = workflow(BUILD_WORKFLOW);

    let named: Vec<String> = job_ids(&workflow)
        .into_iter()
        .filter(|id| {
            field(&job(&workflow, id, BUILD_WORKFLOW), "name").as_deref() == Some(REQUIRED_CHECK)
        })
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
        workflow_path(BUILD_WORKFLOW).display(),
    );

    let aggregator = job(&workflow, &named[0], BUILD_WORKFLOW);
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

    // `needs` only makes the halves' results *available*. What turns a red half
    // into a red required check is the step that reads them, and everything
    // above holds just as well for an aggregator that needs both and reads
    // neither: same name, same `needs`, same `if:`, green however the halves
    // ended. That is worse than the #299 rename this test was written for -- a
    // rename disarms one ruleset, this certifies a failure as a pass.
    for half in AGGREGATED_HALVES {
        assert!(
            aggregator.contains(&format!(r#""${{{{ needs.{half}.result }}}}" != "success""#)),
            "the job named {REQUIRED_CHECK:?} never reads `{half}`'s result, so it reports \
             success however that half ended",
        );
    }
    assert!(
        aggregator.contains("exit 1"),
        "the job named {REQUIRED_CHECK:?} reads both halves' results and then exits zero \
         regardless, so the repo's sole required check can never go red",
    );
}

/// The `on:` block is wiring too, and every test above reads jobs rather than
/// triggers.
///
/// `edited` is not a default `pull_request` type (the defaults are `opened`,
/// `synchronize` and `reopened`), and dropping it back to a bare `on:
/// pull_request:` leaves two verdicts attached to inputs they were not computed
/// from. Retitling a PR from `feat!:` to `fix(pg-core):` fires only `edited`, so
/// the semver gate's green -- earned with `release_type=major`, which skips
/// every lint -- stays on the unchanged head sha, and release-plz then cuts a
/// patch release of the break. A base retarget fires only `edited` too, so
/// paths-filter's "nothing relevant changed" survives against a base it never
/// compared.
#[test]
fn a_retitled_or_retargeted_pr_still_re_runs_the_gates() {
    let workflow = workflow(BUILD_WORKFLOW);
    let triggers = workflow
        .split_once("\njobs:\n")
        .expect("no top-level `jobs:`")
        .0;

    let types: BTreeSet<String> = triggers
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("types:"))
        .expect("the `pull_request` trigger declares no `types:`")
        .trim()
        .trim_matches(['[', ']'].as_slice())
        .split(',')
        .map(|kind| kind.trim().to_owned())
        .collect();

    assert_eq!(
        types,
        expected(&PULL_REQUEST_TYPES),
        "the `pull_request` trigger no longer re-runs on the events these gates' verdicts \
         depend on. `edited` is the one that is not a default: without it a retitle leaves \
         the semver gate's verdict attached to the title it was computed from, and a base \
         retarget leaves paths-filter's attached to the old base",
    );
}

/// The seal half: the filter that decides when it runs, the `push` override
/// that stops the filter answering the wrong question, and the two commands
/// that are the gate.
#[test]
fn the_rust_wire_gate_still_seals_and_opens_what_it_claims_to() {
    let job = job(
        &workflow(BUILD_WORKFLOW),
        "wire-compat-rust",
        BUILD_WORKFLOW,
    );
    let steps = steps(&job);

    assert_eq!(
        filter_paths(&job),
        expected(&WIRE_FILTER),
        "wire-compat-rust's path filter and this test disagree about what can change the \
         sealed bytes. A path dropped here does not fail the gate, it silently stops it \
         firing; if the filter was widened on purpose, widen WIRE_FILTER with it",
    );

    let gate = step_with(&steps, "id: gate", BUILD_WORKFLOW);
    assert!(
        gate.contains(PUSH_OVERRIDE),
        "wire-compat-rust's gate step no longer bypasses the path filter on `push`. On a \
         push the filter diffs only the push that triggered it, so a commit that reached \
         `main` without this gate running is never re-checked -- and the job still reports \
         green, because \"filter said no\" and \"gate passed\" are the same success (#299)",
    );

    let seal = step_with(&steps, "id: seal", BUILD_WORKFLOW);
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

    let open = step_with(&steps, OPEN_COMMAND, BUILD_WORKFLOW);
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
    let job = job(&workflow(BUILD_WORKFLOW), "wire-compat-js", BUILD_WORKFLOW);
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

    let download = step_with(&steps, "actions/download-artifact", BUILD_WORKFLOW);
    assert!(
        download.contains(SEALED_OUTPUT),
        "wire-compat-js's download is not gated on `{SEALED_OUTPUT}`, so it no longer keys \
         off the same outcome the seal did and the two halves can drift over whether to run",
    );

    // `ci`, not `install`: the readers are pinned by pg-compat-js's lockfile, so
    // a gate that quietly resolved a different reader would still run, still
    // report, and be measuring a support window COMPATIBILITY.md never declared.
    // Same silent-narrowing class as a dropped filter path.
    let install = step_with(&steps, "run: npm ci", BUILD_WORKFLOW);
    assert!(
        install.contains("working-directory: pg-compat-js"),
        "wire-compat-js no longer installs the pinned readers with `npm ci` in pg-compat-js, \
         so the gate measures whatever npm resolves rather than the declared support window",
    );

    let open = step_with(&steps, "run: npm test", BUILD_WORKFLOW);
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
    let job = job(&workflow(BUILD_WORKFLOW), "semver-checks", BUILD_WORKFLOW);
    let steps = steps(&job);

    assert_eq!(
        filter_paths(&job),
        expected(&SEMVER_FILTER),
        "semver-checks's path filter and this test disagree about which changes can break a \
         published API. A path dropped here silently stops the gate firing; if the filter \
         was widened on purpose, widen SEMVER_FILTER with it",
    );

    step_with(&steps, "./scripts/semver-checks-test.sh", BUILD_WORKFLOW);

    let check = step_with(&steps, "./scripts/semver-checks.sh", BUILD_WORKFLOW);
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
    let declared = step_with(&steps, "id: declared", BUILD_WORKFLOW);
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

/// The registry gate (#318): the job that reads the live ruleset back and
/// compares it against [`REQUIRED_CHECK`].
///
/// This file pins the name a job in `build.yml` produces; the ruleset pins the
/// name it requires; and until #318 nothing compared the two, because both
/// #272 and postguard-js#222 assumed an API read needed a credential CI could
/// not have. It does not, on a public repo. So the link is now closed from both
/// ends, and what can drift has moved: the workflow can stop calling the script.
///
/// The script's own behaviour -- drift is 1, undetermined is 2, and they are
/// never conflated -- is pinned by `scripts/ruleset-drift-test.sh`, which the
/// same job runs. This asserts only that the job still calls both.
#[test]
fn the_registry_gate_still_reads_the_ruleset_back() {
    let job = job(&workflow(BUILD_WORKFLOW), "ruleset-drift", BUILD_WORKFLOW);
    let steps = steps(&job);

    step_with(&steps, "scripts/ruleset-drift.sh", BUILD_WORKFLOW);
    step_with(&steps, "scripts/ruleset-drift-test.sh", BUILD_WORKFLOW);

    // Without a checkout there is no script to run, and the job fails in a way
    // that reads like drift rather than like a broken job.
    assert!(
        job.contains("actions/checkout"),
        "the registry gate no longer checks the repo out, so the script it runs is not there",
    );

    // The gate reads a live third-party API. If it were ever aggregated into
    // `Wire compat` -- the one context the ruleset requires and `--admin`
    // cannot bypass -- a GitHub API outage would become an unmergeable repo.
    let aggregator = self::job(&workflow(BUILD_WORKFLOW), "wire-compat", BUILD_WORKFLOW);
    assert!(
        !aggregator.contains("ruleset-drift"),
        "the registry gate has been wired into the sole required check. It reads a live API, \
         so an outage there would block every merge; keep it a separate, non-required context",
    );
}

/// The reader above is line-oriented, so a reformat of `build.yml` could leave
/// it matching nothing while every assertion still passed. This is the check
/// that the instrument itself still works: the jobs the other tests read must
/// be found, distinct, and non-empty.
#[test]
fn every_job_this_test_reads_is_still_found() {
    let workflow = workflow(BUILD_WORKFLOW);
    let ids = job_ids(&workflow);

    for id in [
        "wire-compat-rust",
        "wire-compat-js",
        "semver-checks",
        "wire-compat",
        "ruleset-drift",
    ] {
        assert!(
            ids.contains(&id.to_owned()),
            "{} has no job `{id}`, and this test is what was supposed to notice",
            workflow_path(BUILD_WORKFLOW).display(),
        );
        let body = job(&workflow, id, BUILD_WORKFLOW);
        assert!(
            field(&body, "name").is_some() && !steps(&body).is_empty(),
            "job `{id}` read back as {} lines with no name or no steps, so the reader in \
             this file no longer understands {}",
            body.lines().count(),
            workflow_path(BUILD_WORKFLOW).display(),
        );
    }

    // `wire-compat` is a prefix of the other two ids: if the reader ever stops
    // distinguishing them, the aggregator test would read the seal job and pass
    // for the wrong reason.
    assert_ne!(
        job(&workflow, "wire-compat", BUILD_WORKFLOW),
        job(&workflow, "wire-compat-rust", BUILD_WORKFLOW),
        "the job reader is matching on a prefix, so `wire-compat` and `wire-compat-rust` \
         read back as the same block",
    );
}

/// The delivery workflow's coverage half (#412): a released tag's changelog
/// entry has twice fallen silently short of the commits the tag actually
/// contains (cryptify-v0.1.36, pg-core-v0.6.5), and nothing caught either time
/// -- every check stayed green because nothing compared a tag's contents
/// against its own entry. This is the same instrument the tests above point at
/// `build.yml`, pointed at `delivery.yml` instead: read the job back and
/// assert what it runs, rather than trust that a posted patch was applied.
///
/// This assertion is RED on this branch, and that is correct. The
/// `dobby-coder` App has no `workflows: write`, so the `changelog-coverage`
/// job it looks for is posted as a patch for a maintainer to apply, not pushed
/// here. A workflow patch that is posted and never applied has already merged
/// silently twice on this repo (#272, #324) -- do not weaken, `#[ignore]`, or
/// delete this assertion to make CI green before that patch lands.
#[test]
fn the_delivery_workflow_still_checks_changelog_coverage() {
    let job = job(
        &workflow(DELIVERY_WORKFLOW),
        "changelog-coverage",
        DELIVERY_WORKFLOW,
    );
    let steps = steps(&job);

    step_with(&steps, CHANGELOG_COVERAGE_COMMAND, DELIVERY_WORKFLOW);
}
