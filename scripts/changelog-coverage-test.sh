#!/usr/bin/env bash
#
# Regression tests for scripts/changelog-coverage.sh, covering the exit-code
# contract: 1 means the entry is missing a commit the tag contains, 2 means
# the script could not find out. Conflating them is the failure this pins --
# see the header of changelog-coverage.sh for why.
#
# Unlike scripts/ruleset-drift-test.sh this needs no stub: the fixtures are
# already this repo's own tag history, read with `git show <tag>:...`, so the
# suite runs offline and fast without inventing a synthetic repo. The known-bad
# fixture is the point of the ticket that added this script (#412) -- testing
# the checker against a known-bad input before believing its pass on a
# known-good one.
#
# Usage:
#   scripts/changelog-coverage-test.sh
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

gate="$root/scripts/changelog-coverage.sh"

pass=0
fail=0

# Runs the gate on <package> <tag> and asserts its exit code, and optionally
# that its combined output mentions `$needle`.
expect() {
  local want=$1 desc=$2 package=$3 tag=$4 needle=${5:-}
  local got out
  set +e
  out=$("$gate" "$package" "$tag" 2>&1)
  got=$?
  set -e
  if [[ $got -ne $want ]]; then
    echo "FAIL: $desc -- wanted exit $want, got $got"
    echo "$out" | sed 's/^/      /'
    fail=$((fail + 1))
    return
  fi
  if [[ -n $needle && $out != *"$needle"* ]]; then
    echo "FAIL: $desc -- exit $got was right but output never mentioned '$needle'"
    echo "$out" | sed 's/^/      /'
    fail=$((fail + 1))
    return
  fi
  echo "ok: $desc (exit $got)"
  pass=$((pass + 1))
}

# --- known-bad: the tag whose entry is missing a commit it contains ----------
#
# `cryptify-v0.1.36` on `main` has already had its CHANGELOG.md corrected (this
# same change does that), but the *tag* is immutable and still points at the
# commit whose entry names only #406. Reading it at the tag rather than the
# working tree is what keeps this fixture meaningful after that correction
# lands -- read the header of changelog-coverage.sh before changing that.
expect 1 "cryptify-v0.1.36's entry (at the tag) is missing #408" \
  cryptify cryptify-v0.1.36 "#408"

# The second tag the issue's own measurement found, and the shape is
# different: a scoped, multi-crate commit ("docs(pg-core, pg-wasm): ...").
expect 1 "pg-core-v0.6.5's entry (at the tag) is missing #376" \
  pg-core pg-core-v0.6.5 "#376"

# --- known-good: the immediately preceding release, corrected already -------
expect 0 "cryptify-v0.1.35's entry accounts for its one commit" \
  cryptify cryptify-v0.1.35

# --- subset direction: more entries than commits must still pass ------------
#
# The regression pg-pkg-v0.6.0 would otherwise catch: release-plz also writes
# dependency-driven entries, so this tag's entry legitimately carries more
# bullets (19) than there are path-scoped commits (16). An equality check
# would fail a correct release here.
expect 0 "pg-pkg-v0.6.0's entry is a superset of its path-scoped commits" \
  pg-pkg pg-pkg-v0.6.0

# --- undetermined: no previous tag in the series -----------------------------
expect 2 "the first tag in a series has nothing to compare it against" \
  cryptify cryptify-v0.1.27

# --- undetermined: the tag does not exist ------------------------------------
expect 2 "a tag that does not exist is undetermined, not a pass" \
  cryptify cryptify-v9.9.9

# --- undetermined: bad usage --------------------------------------------------
out=$("$gate" 2>&1) && got=0 || got=$?
if [[ $got -eq 2 && $out == *usage* ]]; then
  echo "ok: no arguments is undetermined, not a pass (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: no arguments -- wanted exit 2 with a usage message, got $got: $out"
  fail=$((fail + 1))
fi

echo
echo "changelog-coverage-test: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
