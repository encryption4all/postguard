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

# --- boundary: a PR number that is a numeric prefix of another --------------
#
# No two PR numbers in this repo's real tag history happen to collide as a
# numeric prefix/suffix, so this case can't be pinned against a real tag the
# way the ones above are. Build a two-tag repo in a tmpdir instead -- same
# spirit as ruleset-drift-test.sh's curl stub: isolate the one input the gate
# actually reads (git plumbing) so the case is reachable without waiting for
# it to occur naturally.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(
  cd "$tmp"
  git init -q
  git config user.email test@example.com
  git config user.name test
  mkdir pkg
  printf '# Changelog\n' >pkg/CHANGELOG.md
  git add -A
  git commit -q -m "chore: init"
  git tag pkg-v0.1.0

  echo change >>pkg/file.txt
  git add -A
  git commit -q -m "fix(pkg): unrelated change (#48)"
  echo change >>pkg/file.txt
  git add -A
  git commit -q -m "fix(pkg): the missing change (#4)"
  cat >>pkg/CHANGELOG.md <<'EOF'

## [0.2.0]

- *(pkg)* unrelated change ([#48](https://github.com/encryption4all/postguard/pull/48))
EOF
  git add -A
  git commit -q -m "chore(pkg): release v0.2.0 (#49)"
  git tag pkg-v0.2.0
)
out=$(cd "$tmp" && "$gate" pkg pkg-v0.2.0 2>&1) && got=0 || got=$?
if [[ $got -eq 1 && $out == *"[#4]"* ]]; then
  echo "ok: #4 is not accounted for by an entry that only names #48 (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: entry naming only #48 -- wanted exit 1 naming #4, got $got: $out"
  fail=$((fail + 1))
fi
rm -rf "$tmp"
trap - EXIT

# --- undetermined: too many arguments -----------------------------------------
out=$("$gate" cryptify cryptify-v0.1.35 extra 2>&1) && got=0 || got=$?
if [[ $got -eq 2 && $out == *usage* ]]; then
  echo "ok: too many arguments is undetermined, not a pass (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: too many arguments -- wanted exit 2 with a usage message, got $got: $out"
  fail=$((fail + 1))
fi

# --- identity: a direct-push commit (no PR number) missing from the entry ----
#
# Every real fixture above has a PR number on every commit, so the fallback
# path -- match the (prefix-stripped) description against the entry text --
# has never actually run. Same reasoning as the boundary case above: build a
# tmp repo rather than wait for this repo to grow a direct push to a package
# directory.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(
  cd "$tmp"
  git init -q
  git config user.email test@example.com
  git config user.name test
  mkdir pkg
  printf '# Changelog\n' >pkg/CHANGELOG.md
  git add -A
  git commit -q -m "chore: init"
  git tag pkg-v0.1.0

  echo change >>pkg/file.txt
  git add -A
  git commit -q -m "fix(pkg): a direct push with no PR reference at all"
  cat >>pkg/CHANGELOG.md <<'EOF'

## [0.2.0]

- *(pkg)* an entry that never mentions the direct push above
EOF
  git add -A
  git commit -q -m "chore(pkg): release v0.2.0 (#2)"
  git tag pkg-v0.2.0
)
out=$(cd "$tmp" && "$gate" pkg pkg-v0.2.0 2>&1) && got=0 || got=$?
if [[ $got -eq 1 && $out == *"a direct push with no PR reference at all"* ]]; then
  echo "ok: a direct-push commit absent from the entry is still caught (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: direct-push commit missing from the entry -- wanted exit 1 naming it, got $got: $out"
  fail=$((fail + 1))
fi
rm -rf "$tmp"
trap - EXIT

# --- entry extraction: must stop at the *next* '## [', not run to EOF --------
#
# release-plz writes newest entries above older ones, so a tag's own entry
# always has another '## [' below it once a second release exists. If entry
# extraction stopped anchoring there, a commit missing from its own release
# could read as accounted for by unrelated text several releases back. #7 is
# deliberately reused as a PR number across two entries below -- an
# impossible collision in this repo's real history, but the only way to make
# the boundary bug observable without waiting for a coincidence.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(
  cd "$tmp"
  git init -q
  git config user.email test@example.com
  git config user.name test
  mkdir pkg
  printf '# Changelog\n' >pkg/CHANGELOG.md
  git add -A
  git commit -q -m "chore: init"
  git tag pkg-v0.1.0

  echo change >>pkg/file.txt
  git add -A
  git commit -q -m "fix(pkg): first release work (#6)"
  cat >>pkg/CHANGELOG.md <<'EOF'

## [0.2.0]

- *(pkg)* first release work ([#6](https://github.com/encryption4all/postguard/pull/6))
- *(pkg)* a decoy mention of a later PR ([#7](https://github.com/encryption4all/postguard/pull/7))
EOF
  git add -A
  git commit -q -m "chore(pkg): release v0.2.0 (#8)"
  git tag pkg-v0.2.0

  echo change >>pkg/file.txt
  git add -A
  git commit -q -m "fix(pkg): a change never actually named in its own entry (#7)"
  # release-plz prepends the newest entry above the older ones -- insert
  # 0.3.0's block right after the '# Changelog' heading, same as it would.
  {
    head -n1 pkg/CHANGELOG.md
    printf '\n## [0.3.0]\n\n- *(pkg)* unrelated bullet, no PR reference\n'
    tail -n +2 pkg/CHANGELOG.md
  } >pkg/CHANGELOG.md.new
  mv pkg/CHANGELOG.md.new pkg/CHANGELOG.md
  git add -A
  git commit -q -m "chore(pkg): release v0.3.0 (#9)"
  git tag pkg-v0.3.0
)
out=$(cd "$tmp" && "$gate" pkg pkg-v0.3.0 2>&1) && got=0 || got=$?
if [[ $got -eq 1 && $out == *"[#7]"* ]]; then
  echo "ok: entry extraction stops at the next '## [' -- an older entry's #7 does not account for 0.3.0's (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: entry extraction ran past the next '## [' -- wanted exit 1 naming #7, got $got: $out"
  fail=$((fail + 1))
fi
rm -rf "$tmp"
trap - EXIT

echo
echo "changelog-coverage-test: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
