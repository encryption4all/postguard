#!/usr/bin/env bash
#
# Regression tests for scripts/changelog-coverage-report.sh (#429), covering
# the exit-code contract (0/1/2, 2 dominates 1) and the filing behaviour: what
# gets deduped, what gets filed, and what happens when `gh` itself fails.
#
# Only `gh` is stubbed. scripts/changelog-coverage.sh runs for real, against
# `RELEASES` fixtures built from real tags in this repo's history, which are
# immutable -- stubbing the collaborator too would test the reporter against a
# fiction. Same reasoning as scripts/changelog-coverage-test.sh; see its
# header. The three fixtures and their outcomes:
#
#   pg-core-v0.6.6   -> the checker exits 1 (its entry omits #421)
#   cryptify-v0.1.35 -> exits 0
#   pg-core-v99.0.0  -> exits 2 (fabricated, does not exist)
#
# The `gh` stub records every invocation to $GH_STUB_LOG_DIR/call-N, one
# NUL-separated argv per file, so a test can assert not just an exit code but
# whether `issue create` ran, with what title and body, and how many times.
# Modelled on scripts/ruleset-drift-test.sh's stub-on-`PATH` construction.
#
# Usage:
#   scripts/changelog-coverage-report-test.sh
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

gate="$root/scripts/changelog-coverage-report.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
stubs="$tmp/bin"
mkdir "$stubs"

# Stub gh: understands only the two subcommands the reporter calls.
# `issue list` prints $GH_STUB_LIST_OUTPUT and exits $GH_STUB_LIST_EXIT.
# `issue create` exits $GH_STUB_CREATE_EXIT. Either failure is independent of
# the other, so line 111's defect (a failed `issue list`) and a failed
# `issue create` are reachable without touching one another.
cat >"$stubs/gh" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
dir="$GH_STUB_LOG_DIR"
n=0
for f in "$dir"/call-*; do [[ -e $f ]] && n=$((n + 1)); done
printf '%s\0' "$@" >"$dir/call-$((n + 1))"

if [[ ${1:-} == issue && ${2:-} == list ]]; then
  if [[ ${GH_STUB_LIST_EXIT:-0} -ne 0 ]]; then
    echo "stub gh: simulated issue list failure" >&2
    exit "${GH_STUB_LIST_EXIT}"
  fi
  printf '%s' "${GH_STUB_LIST_OUTPUT:-}"
  exit 0
elif [[ ${1:-} == issue && ${2:-} == create ]]; then
  if [[ ${GH_STUB_CREATE_EXIT:-0} -ne 0 ]]; then
    echo "stub gh: simulated issue create failure" >&2
    exit "${GH_STUB_CREATE_EXIT}"
  fi
  exit 0
else
  echo "stub gh: unexpected invocation: $*" >&2
  exit 1
fi
STUB
chmod +x "$stubs/gh"

export PATH="$stubs:$PATH"
export GH_TOKEN=stub-token
export GH_REPO=encryption4all/postguard

pass=0
fail=0

releases_of() {
  local package=$1 tag=$2
  printf '[{"package_name":"%s","tag":"%s"}]' "$package" "$tag"
}

# Fresh log dir per call, so each `expect` starts from zero recorded
# invocations -- a leftover call-N from a previous case must never satisfy
# this case's assertions.
reset_log() {
  rm -rf "$tmp/log"
  mkdir "$tmp/log"
  export GH_STUB_LOG_DIR="$tmp/log"
}

# Number of `gh issue create` invocations recorded in the current log dir.
create_calls() {
  local count=0 f
  for f in "$GH_STUB_LOG_DIR"/call-*; do
    [[ -e $f ]] || continue
    mapfile -d '' -t args <"$f"
    [[ ${args[0]:-} == issue && ${args[1]:-} == create ]] && count=$((count + 1))
  done
  echo "$count"
}

# The value of the first `--$1` flag in the first `gh issue create` call
# recorded in the current log dir.
create_flag() {
  local flag=$1 f
  for f in "$GH_STUB_LOG_DIR"/call-*; do
    [[ -e $f ]] || continue
    mapfile -d '' -t args <"$f"
    [[ ${args[0]:-} == issue && ${args[1]:-} == create ]] || continue
    for i in "${!args[@]}"; do
      if [[ ${args[$i]} == "--$flag" ]]; then
        echo "${args[$((i + 1))]}"
        return
      fi
    done
  done
}

# Runs the gate with RELEASES=$2 and asserts its exit code, optionally that
# its combined output mentions $4, and optionally the number of recorded
# `gh issue create` calls ($5, skipped when unset).
expect() {
  local want=$1 desc=$2 releases=$3 needle=${4:-} want_creates=${5:-}
  local got out
  reset_log
  set +e
  out=$(RELEASES="$releases" "$gate" 2>&1)
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
  if [[ -n $want_creates ]]; then
    local got_creates
    got_creates=$(create_calls)
    if [[ $got_creates -ne $want_creates ]]; then
      echo "FAIL: $desc -- wanted $want_creates \`gh issue create\` call(s), got $got_creates"
      fail=$((fail + 1))
      return
    fi
  fi
  echo "ok: $desc (exit $got)"
  pass=$((pass + 1))
}

GAP_RELEASES=$(releases_of pg-core pg-core-v0.6.6)
CLEAN_RELEASES=$(releases_of cryptify cryptify-v0.1.35)
UNDETERMINED_RELEASES=$(releases_of pg-core pg-core-v99.0.0)
GAP_AND_UNDETERMINED_RELEASES='[{"package_name":"pg-core","tag":"pg-core-v0.6.6"},{"package_name":"pg-core","tag":"pg-core-v99.0.0"}]'
GAP_TITLE="changelog: pg-core-v0.6.6 omits commits it contains"

export GH_STUB_LIST_EXIT=0 GH_STUB_LIST_OUTPUT='' GH_STUB_CREATE_EXIT=0

# --- empty RELEASES -----------------------------------------------------------
expect 0 "empty RELEASES is a clean pass" '[]' "" 0

# --- only a clean tag -----------------------------------------------------------
expect 0 "a clean tag alone exits 0, and gh issue create is never called" \
  "$CLEAN_RELEASES" "" 0

# --- a real gap, no existing issue -------------------------------------------
expect 1 "a real gap exits 1, files exactly one issue with the exact title" \
  "$GAP_RELEASES" "" 1
reset_log
RELEASES="$GAP_RELEASES" "$gate" >/dev/null 2>&1 || true
title=$(create_flag title)
if [[ $title == "$GAP_TITLE" ]]; then
  echo "ok: the filed issue's title is exactly \"$GAP_TITLE\""
  pass=$((pass + 1))
else
  echo "FAIL: the filed issue's title -- wanted \"$GAP_TITLE\", got \"$title\""
  fail=$((fail + 1))
fi
body=$(create_flag body)
if [[ $body == *"#421"* ]]; then
  echo "ok: the filed issue's body carries the checker's stdout (#421)"
  pass=$((pass + 1))
else
  echo "FAIL: the filed issue's body never mentioned #421 -- got: $body"
  fail=$((fail + 1))
fi

# --- the same gap, title already present in the stubbed issue list -----------
GH_STUB_LIST_OUTPUT=$GAP_TITLE
expect 1 "a gap whose title already exists is still exit 1, but not re-filed" \
  "$GAP_RELEASES" "not filing a duplicate" 0
GH_STUB_LIST_OUTPUT=''

# --- a fabricated tag alone ----------------------------------------------------
expect 2 "an undetermined tag alone exits 2, files nothing, says the checker did not run" \
  "$UNDETERMINED_RELEASES" "the checker did not run, this is not a changelog gap" 0

# --- dominance: a real gap and an undetermined tag together -------------------
#
# The dominance rule (#429 decision 3): a run that both found a real gap and
# hit something it could not determine must report 2, not 1 -- but the gap
# that *was* determined must still be filed. Losing either half here is wrong
# in a different way: reporting 1 hides the undetermined tag, and skipping the
# filing loses a real finding because of an unrelated failure elsewhere in the
# same run.
expect 2 "a gap and an undetermined tag together exit 2, and the gap is still filed" \
  "$GAP_AND_UNDETERMINED_RELEASES" "" 1

# --- gh issue list fails: line 111's defect, asserted as behaviour -----------
#
# This is the second instance of the shape that made #412's first finding go
# unreported: a fallible `gh` read with nothing branching on its exit code.
# Here it is branched on, deliberately, and the reporter must stop before
# checking a single tag -- proceeding on a bad read risks re-filing an issue
# that is already open, not staying silent.
GH_STUB_LIST_EXIT=1
expect 2 "a failed gh issue list exits 2 before any tag is checked" \
  "$GAP_RELEASES" "not checking any tag" 0
if [[ $(create_calls) -ne 0 ]]; then
  echo "FAIL: gh issue list failed, but changelog-coverage.sh was still invoked (issue create called)"
  fail=$((fail + 1))
else
  echo "ok: changelog-coverage.sh is never invoked once gh issue list has failed"
  pass=$((pass + 1))
fi
GH_STUB_LIST_EXIT=0

# --- gh issue create fails on a real gap --------------------------------------
GH_STUB_CREATE_EXIT=1
expect 2 "a real gap whose gh issue create fails exits 2, not 1" \
  "$GAP_RELEASES" "gh issue create failed" 1
GH_STUB_CREATE_EXIT=0

echo
echo "changelog-coverage-report-test: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
