#!/usr/bin/env bash
#
# Public-API semver gate for the two crates external consumers build against:
# pg-core (crates.io) and pg-wasm (published to npm as @e4a/pg-wasm).
#
# A breaking change to either surface fails this script unless the change is
# declared as breaking. Versions in this repo are bumped by release-plz, not by
# the PR that makes the change, so the declaration is the `!` in the
# conventional-commit PR title (plus the `BREAKING CHANGE:` footer) that
# release-plz turns into a major bump. CI translates that into
# SEMVER_RELEASE_TYPE=major; see .github/workflows/build.yml.
#
# Usage:
#   scripts/semver-checks.sh
#
# Environment:
#   SEMVER_RELEASE_TYPE   major|minor|patch. Passed to --release-type, which
#                         overrides the bump cargo-semver-checks derives from
#                         the version numbers. Set it to `major` to allow
#                         breaking changes through.
#   SEMVER_WASM_BASELINE  Git revision pg-wasm is compared against.
#                         Default: origin/main. pg-wasm is not on crates.io, so
#                         there is no registry baseline to fetch.
#
# Exit codes: 1 for an undeclared breaking change, 127 if the tool is missing,
# and cargo-semver-checks' own code for anything else. It has two distinct
# non-zero exits and they must not be conflated. 100 is a semver violation. 101
# is the tool or the build failing: an unresolvable baseline rev, a missing
# rustup target, a registry fetch failure, a compile error in the crate. Only
# 100 means "declare the break". Reporting a 101 that way would tell the author
# to add a `!` that makes release-plz cut a spurious major release, and it would
# not even clear the check, because --release-type major leaves a 101 non-zero.
# scripts/semver-checks-test.sh covers this mapping.
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

release_type=()
if [[ -n "${SEMVER_RELEASE_TYPE:-}" ]]; then
  release_type=(--release-type "$SEMVER_RELEASE_TYPE")
fi
wasm_baseline="${SEMVER_WASM_BASELINE:-origin/main}"

if ! command -v cargo-semver-checks >/dev/null; then
  echo "cargo-semver-checks is not installed: cargo install cargo-semver-checks --locked" >&2
  exit 127
fi

failed=()

# Record a semver violation (exit 100) and carry on so both surfaces get
# reported; let anything else out with the tool's own exit code.
run_check() {
  local name=$1
  shift
  "$@" && return 0
  local ec=$?
  if [[ $ec -eq 100 ]]; then
    failed+=("$name")
    return 0
  fi
  echo "cargo-semver-checks failed on ${name} (exit ${ec}): tool or build" >&2
  echo "failure, not a semver break. Adding '!' to the PR title will not" >&2
  echo "clear this." >&2
  exit "$ec"
}

# pg-core, native surface. The feature set is explicit for the same reason the
# test and clippy jobs spell it out: `web` is compile_error! off wasm32, so the
# feature heuristic cargo-semver-checks uses by default (everything except
# unstable-looking features) cannot build this crate. `test` is in the set
# because the `test` module it gates is public API that pg-compat and pg-wasm
# build against.
#
# pg-core's `web,stream` surface is deliberately NOT checked: on that feature
# combination `Unsealer` has two `unseal` methods on different instantiations
# (owned self in client/web/mod.rs, &mut self in client/web/stream.rs) and
# cargo-semver-checks 0.49 pairs them across versions by name alone, reporting
# method_receiver_mut_ref_became_owned against byte-identical source. pg-wasm
# below covers the surface those consumers actually call.
#
# `${release_type[@]+...}` rather than a bare `"${release_type[@]}"`: expanding
# an empty array aborts under `set -u` on bash < 4.4, which is macOS system bash.
echo "==> pg-core (native, features test,rust,stream)"
run_check pg-core \
  cargo semver-checks \
  --manifest-path pg-core/Cargo.toml \
  --only-explicit-features \
  --features test,rust,stream \
  ${release_type[@]+"${release_type[@]}"}

# pg-wasm has to be built for wasm32, and cargo-semver-checks passes
# `--cap-lints allow` in RUSTFLAGS, which silences the "dropping unsupported
# crate type" warnings cargo reads back when it probes rustc for wasm32 target
# info. Cargo then aborts with "output of --print=file-names missing when
# learning about target-specific information from rustc". Setting RUSTFLAGS
# ourselves keeps cargo-semver-checks from adding its own cap and lets the
# probe through.
echo "==> pg-wasm (wasm32-unknown-unknown, baseline ${wasm_baseline})"
run_check pg-wasm \
  env RUSTFLAGS="--cap-lints=warn" cargo semver-checks \
  --manifest-path pg-wasm/Cargo.toml \
  --target wasm32-unknown-unknown \
  --baseline-rev "$wasm_baseline" \
  ${release_type[@]+"${release_type[@]}"}

if [[ ${#failed[@]} -gt 0 ]]; then
  echo
  echo "Breaking public-API changes in: ${failed[*]}" >&2
  echo "Either keep the change additive, or declare the break: give the PR a" >&2
  echo "conventional-commit title with '!' (e.g. feat(pg-core)!: ...) and a" >&2
  echo "BREAKING CHANGE: footer, so release-plz cuts a major release." >&2
  exit 1
fi

echo
echo "No undeclared breaking public-API changes."
