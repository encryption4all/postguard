#!/usr/bin/env bash
#
# Regression tests for scripts/ruleset-drift-report.sh (#422), covering the
# exit-code contract (0/1/2/127, 2 dominates 1) and the filing behaviour: the
# push-to-main guard, what gets deduped, what gets filed, and what happens
# when `gh` or the checker itself fails.
#
# Only `gh` and the checker are stubbed -- `gh` on `PATH`, same technique as
# scripts/changelog-coverage-report-test.sh, and the checker through
# `RULESET_DRIFT_CHECKER`, which scripts/ruleset-drift-report.sh's own header
# comment explains cannot be a `PATH` stub: the reporter invokes it by a
# relative path after `cd "$root"`, so a same-named stub earlier on `PATH`
# would never be found.
#
# The `gh` stub records every invocation to $GH_STUB_LOG_DIR/call-N, one
# NUL-separated argv per file, so a test can assert not just an exit code but
# whether `issue create` ran and with what title and label.
#
# Usage:
#   scripts/ruleset-drift-report-test.sh
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

gate="$root/scripts/ruleset-drift-report.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
stubs="$tmp/bin"
mkdir "$stubs"

# Stub gh: understands only the two subcommands the reporter calls.
# `issue list` prints $GH_STUB_LIST_OUTPUT and exits $GH_STUB_LIST_EXIT.
# `issue create` exits $GH_STUB_CREATE_EXIT. Either failure is independent of
# the other.
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

# The checker stub. Exits $CHECKER_STUB_EXIT and prints $CHECKER_STUB_STDOUT
# to stdout / $CHECKER_STUB_STDERR to stderr, and always writes a marker file
# so a test can assert whether it ran at all -- the fail-open case (#422's
# dedupe-read-fails path) is only distinguishable from a pass if "never ran"
# leaves a trace.
checker_stub="$tmp/checker"
cat >"$checker_stub" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
: >"$CHECKER_STUB_RAN_MARKER"
[[ -n ${CHECKER_STUB_STDOUT:-} ]] && printf '%s' "$CHECKER_STUB_STDOUT"
[[ -n ${CHECKER_STUB_STDERR:-} ]] && printf '%s' "$CHECKER_STUB_STDERR" >&2
exit "${CHECKER_STUB_EXIT:-0}"
STUB
chmod +x "$checker_stub"
export RULESET_DRIFT_CHECKER="$checker_stub"

pass=0
fail=0

# Fresh log dir and marker per call, so each `expect` starts from zero
# recorded invocations and a stale marker from a previous case can never
# satisfy this case's "did the checker run" assertion.
reset_log() {
  rm -rf "$tmp/log"
  mkdir "$tmp/log"
  export GH_STUB_LOG_DIR="$tmp/log"
  rm -f "$tmp/checker-ran"
  export CHECKER_STUB_RAN_MARKER="$tmp/checker-ran"
}

checker_ran() {
  [[ -e $CHECKER_STUB_RAN_MARKER ]]
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

# Runs the gate with the given environment and asserts its exit code,
# optionally that its combined output mentions $4, and optionally the number
# of recorded `gh issue create` calls ($5, skipped when unset).
expect() {
  local want=$1 desc=$2 needle=${3:-} want_creates=${4:-}
  local got out
  reset_log
  set +e
  out=$("$gate" 2>&1)
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

TITLE="ruleset: main's required rules have drifted"

export GH_STUB_LIST_EXIT=0 GH_STUB_LIST_OUTPUT='' GH_STUB_CREATE_EXIT=0
export CHECKER_STUB_EXIT=0 CHECKER_STUB_STDOUT='' CHECKER_STUB_STDERR=''
export GITHUB_EVENT_NAME=push GITHUB_REF=refs/heads/main

# --- 1: checker 0 is a clean pass, gh issue create never called --------------
CHECKER_STUB_EXIT=0
expect 0 "checker exit 0 is a clean pass, no issue filed" "" 0

# --- 2: checker 1, push to main, no existing title: files exactly one -------
CHECKER_STUB_EXIT=1
expect 1 "a real drift on push/main files exactly one issue" "" 1
reset_log
CHECKER_STUB_EXIT=1 "$gate" >/dev/null 2>&1 || true
title=$(create_flag title)
if [[ $title == "$TITLE" ]]; then
  echo "ok: the filed issue's title is exactly \"$TITLE\""
  pass=$((pass + 1))
else
  echo "FAIL: the filed issue's title -- wanted \"$TITLE\", got \"$title\""
  fail=$((fail + 1))
fi
label=$(create_flag label)
if [[ $label == ruleset-drift ]]; then
  echo "ok: the filed issue carries --label ruleset-drift"
  pass=$((pass + 1))
else
  echo "FAIL: the filed issue's label -- wanted ruleset-drift, got \"$label\""
  fail=$((fail + 1))
fi

# --- 3: same drift, title already open: still exit 1, not re-filed ----------
GH_STUB_LIST_OUTPUT=$TITLE
expect 1 "a drift whose title already exists is still exit 1, but not re-filed" \
  "not filing a duplicate" 0
GH_STUB_LIST_OUTPUT=''

# --- 4: checker 1, pull_request event: no create -----------------------------
GITHUB_EVENT_NAME=pull_request
expect 1 "drift on a pull_request run exits 1 but files nothing" "not filing" 0
GITHUB_EVENT_NAME=push

# --- 5: checker 1, push but not to main: no create ---------------------------
GITHUB_REF=refs/heads/some-branch
expect 1 "drift on a push to a non-main branch exits 1 but files nothing" "not filing" 0
GITHUB_REF=refs/heads/main

# --- 6: checker 1, workflow_dispatch on main: no create ----------------------
GITHUB_EVENT_NAME=workflow_dispatch
expect 1 "drift on a manual run against main exits 1 but files nothing -- the runner is already reading the output" \
  "not filing" 0
GITHUB_EVENT_NAME=push

# --- 7: checker 2 is undetermined, never drift -------------------------------
CHECKER_STUB_EXIT=2
expect 2 "checker exit 2 is undetermined, not drift, and files nothing" \
  "not run to completion, this is not drift" 0
CHECKER_STUB_EXIT=0

# --- 8: checker 127 is a missing tool -----------------------------------------
CHECKER_STUB_EXIT=127
expect 127 "checker exit 127 (missing tool) is reported and files nothing" \
  "never ran, this is not drift" 0
CHECKER_STUB_EXIT=0

# --- 9: gh issue list fails: nothing checked, nothing filed ------------------
#
# The fail-open case: a dedupe read that failed must not be indistinguishable
# from a clean run. The checker must never even start.
reset_log
GH_STUB_LIST_EXIT=1
set +e
out=$("$gate" 2>&1)
got=$?
set -e
if [[ $got -ne 2 ]]; then
  echo "FAIL: a failed gh issue list -- wanted exit 2, got $got"
  fail=$((fail + 1))
elif [[ $out != *"not running the checker"* ]]; then
  echo "FAIL: a failed gh issue list -- exit was right but output never said so"
  fail=$((fail + 1))
elif checker_ran; then
  echo "FAIL: a failed gh issue list still let the checker run"
  fail=$((fail + 1))
else
  echo "ok: a failed gh issue list exits 2 before the checker ever runs"
  pass=$((pass + 1))
fi
GH_STUB_LIST_EXIT=0

# --- 10: gh issue create fails on a real drift: exit 2, not 1 ----------------
GH_STUB_CREATE_EXIT=1
CHECKER_STUB_EXIT=1
expect 2 "a real drift whose gh issue create fails exits 2, not 1" \
  "gh issue create failed" 1
GH_STUB_CREATE_EXIT=0
CHECKER_STUB_EXIT=0

# --- 11: the reporter's default checker path exists and is executable -------
#
# What makes a rename of the checker fail loudly instead of quietly: once the
# reporter shape lands, pg-core/tests/ci_wiring.rs no longer names
# scripts/ruleset-drift.sh at all -- only this case does.
default_checker="$root/scripts/ruleset-drift.sh"
if [[ -x $default_checker ]]; then
  echo "ok: $default_checker exists and is executable"
  pass=$((pass + 1))
else
  echo "FAIL: $default_checker is missing or not executable -- the reporter's default \`RULESET_DRIFT_CHECKER\` would silently find nothing"
  fail=$((fail + 1))
fi

echo
echo "ruleset-drift-report-test: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
