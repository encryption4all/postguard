#!/usr/bin/env bash
#
# Regression tests for scripts/semver-checks.sh, covering the exit-code
# contract: cargo-semver-checks answers 100 for a semver violation and 101 for
# the tool or the build failing, and only 100 may be reported as a breaking
# change. See the header of semver-checks.sh.
#
# `cargo` is stubbed, so this runs in about a second and needs neither
# cargo-semver-checks nor a wasm32 toolchain.
#
# Usage:
#   scripts/semver-checks-test.sh
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

gate="$root/scripts/semver-checks.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
stubs="$tmp/bin"
mkdir "$stubs"

# Stub cargo: exits with STUB_EXIT_PG_CORE or STUB_EXIT_PG_WASM depending on the
# --manifest-path it was handed, and records its argv per crate so the tests can
# assert on what the gate passed through.
cat >"$stubs/cargo" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
crate=unknown
for arg in "$@"; do
  case $arg in
    pg-core/Cargo.toml) crate=pg_core ;;
    pg-wasm/Cargo.toml) crate=pg_wasm ;;
  esac
done
printf '%s\n' "$@" >"$STUB_ARGV_DIR/$crate.argv"
case $crate in
  pg_core) exit "${STUB_EXIT_PG_CORE:-0}" ;;
  pg_wasm) exit "${STUB_EXIT_PG_WASM:-0}" ;;
esac
exit 0
STUB
chmod +x "$stubs/cargo"

# The gate checks for cargo-semver-checks with `command -v` before running.
printf '#!/bin/sh\nexit 0\n' >"$stubs/cargo-semver-checks"
chmod +x "$stubs/cargo-semver-checks"

failures=0
argv_dir=

# Takes VAR=VALUE arguments and hands them to the gate through `env`, so nothing
# leaks into the next case the way an assignment prefixed onto a function call
# can.
run_gate() {
  argv_dir=$(mktemp -d "$tmp/argv.XXXXXX")
  set +e
  gate_out=$(env PATH="$stubs:$PATH" STUB_ARGV_DIR="$argv_dir" "$@" "$gate" 2>&1)
  gate_status=$?
  set -e
}

check() {
  local what=$1 want=$2 got=$3
  if [[ $want == "$got" ]]; then
    echo "  ok   $what"
  else
    echo "  FAIL $what: want ${want}, got ${got}"
    failures=$((failures + 1))
  fi
}

# Substring assertions take the haystack from $gate_out.
check_says() {
  local what=$1 needle=$2
  if [[ $gate_out == *"$needle"* ]]; then
    echo "  ok   $what"
  else
    echo "  FAIL $what: output does not contain '${needle}'"
    printf '%s\n' "$gate_out" | sed 's/^/       | /'
    failures=$((failures + 1))
  fi
}

check_silent_about() {
  local what=$1 needle=$2
  if [[ $gate_out != *"$needle"* ]]; then
    echo "  ok   $what"
  else
    echo "  FAIL $what: output should not contain '${needle}'"
    printf '%s\n' "$gate_out" | sed 's/^/       | /'
    failures=$((failures + 1))
  fi
}

echo "both surfaces clean"
run_gate
check "exit status" 0 "$gate_status"
check_says "reports success" "No undeclared breaking public-API changes."

echo "pg-core reports a semver violation (100)"
run_gate STUB_EXIT_PG_CORE=100
check "exit status" 1 "$gate_status"
check_says "names the crate" "Breaking public-API changes in: pg-core"

echo "both surfaces report a semver violation (100)"
run_gate STUB_EXIT_PG_CORE=100 STUB_EXIT_PG_WASM=100
check "exit status" 1 "$gate_status"
check_says "names both crates" "Breaking public-API changes in: pg-core pg-wasm"

# The regression this file exists for. Before the fix both of these landed on
# the same exit 1 and the same "declare the break" advice, which on a
# release-plz repo means a spurious major release of pg-core.
echo "pg-core fails to build (101)"
run_gate STUB_EXIT_PG_CORE=101
check "propagates the tool's exit code" 101 "$gate_status"
check_says "says it is not a semver break" "tool or build"
check_silent_about "does not claim a breaking change" "Breaking public-API changes"

echo "pg-wasm baseline does not resolve (101)"
run_gate STUB_EXIT_PG_WASM=101
check "propagates the tool's exit code" 101 "$gate_status"
check_silent_about "does not claim a breaking change" "Breaking public-API changes"

# A build failure is a build failure whatever the declared release type, so the
# escape hatch must not turn it green.
echo "pg-wasm fails to build (101) with SEMVER_RELEASE_TYPE=major"
run_gate STUB_EXIT_PG_WASM=101 SEMVER_RELEASE_TYPE=major
check "propagates the tool's exit code" 101 "$gate_status"
check_silent_about "does not claim a breaking change" "Breaking public-API changes"

# A build failure on the second surface must not throw away a real violation
# already found on the first: the author would fix the baseline, re-run, and only
# then learn about the break.
echo "pg-core violation (100) plus pg-wasm build failure (101)"
run_gate STUB_EXIT_PG_CORE=100 STUB_EXIT_PG_WASM=101
check "propagates the tool's exit code" 101 "$gate_status"
check_says "still reports the recorded break" "Breaking public-API changes in: pg-core"
check_says "says the 101 is not a semver break" "tool or build"

echo "an unrecognised exit code is not swallowed"
run_gate STUB_EXIT_PG_CORE=2
check "propagates the tool's exit code" 2 "$gate_status"
check_silent_about "does not claim a breaking change" "Breaking public-API changes"

echo "SEMVER_RELEASE_TYPE reaches both invocations"
run_gate SEMVER_RELEASE_TYPE=major
check "exit status" 0 "$gate_status"
for crate in pg_core pg_wasm; do
  if grep -qx -- '--release-type' "$argv_dir/$crate.argv" &&
    grep -qx -- 'major' "$argv_dir/$crate.argv"; then
    echo "  ok   $crate got --release-type major"
  else
    echo "  FAIL $crate did not get --release-type major"
    failures=$((failures + 1))
  fi
done

echo "the default run passes no --release-type"
run_gate
check "exit status" 0 "$gate_status"
for crate in pg_core pg_wasm; do
  if grep -qx -- '--release-type' "$argv_dir/$crate.argv"; then
    echo "  FAIL $crate got an unasked-for --release-type"
    failures=$((failures + 1))
  else
    echo "  ok   $crate got no --release-type"
  fi
done

echo "SEMVER_WASM_BASELINE reaches the pg-wasm invocation"
run_gate SEMVER_WASM_BASELINE=refs/heads/some-branch
check "exit status" 0 "$gate_status"
if grep -qx -- 'refs/heads/some-branch' "$argv_dir/pg_wasm.argv"; then
  echo "  ok   pg-wasm got the baseline rev"
else
  echo "  FAIL pg-wasm did not get the baseline rev"
  failures=$((failures + 1))
fi

# `cd "$(git rev-parse --show-toplevel)"` does not abort here: the substitution
# fails but `cd ""` succeeds, so the gate went on to check relative manifest
# paths against whatever the CWD happened to be. Assert on cargo never being
# reached, not just on the exit status, because the stub itself fails without a
# repo to record into.
echo "run from outside a git repository"
argv_dir=$(mktemp -d "$tmp/argv.XXXXXX")
set +e
outside_out=$(cd / && env PATH="$stubs:$PATH" STUB_ARGV_DIR="$argv_dir" "$gate" 2>&1)
outside_status=$?
set -e
check "exit status is non-zero" "yes" "$([[ $outside_status -ne 0 ]] && echo yes || echo no)"
if [[ -z $(ls -A "$argv_dir") ]]; then
  echo "  ok   aborts before invoking cargo"
else
  echo "  FAIL ran cargo outside the repo: $(ls -A "$argv_dir" | tr '\n' ' ')"
  printf '%s\n' "$outside_out" | sed 's/^/       | /'
  failures=$((failures + 1))
fi

echo
if [[ $failures -gt 0 ]]; then
  echo "${failures} assertion(s) failed" >&2
  exit 1
fi
echo "all assertions passed"
