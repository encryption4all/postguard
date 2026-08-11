#!/usr/bin/env bash
#
# Regression tests for scripts/ruleset-drift.sh, covering the exit-code
# contract: 1 means the ruleset and the guard disagree, 2 means the script
# could not find out. Conflating them is the failure this pins -- a 2 reported
# as a 1 sends someone to edit a ruleset that is probably correct, and a 1
# reported as a 2 is the silent gate the script exists to prevent.
#
# `curl` is stubbed, so this runs in about a second, needs no network, and
# cannot be perturbed by the live ruleset it would otherwise read.
#
# Usage:
#   scripts/ruleset-drift-test.sh
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

gate="$root/scripts/ruleset-drift.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
stubs="$tmp/bin"
mkdir "$stubs"

# Stub curl: writes STUB_BODY to the path after -o, prints STUB_CODE the way
# `-w '%{http_code}'` does, and exits STUB_CURL_EXIT so the transport-failure
# path is reachable without unplugging anything.
cat >"$stubs/curl" <<'STUB'
#!/usr/bin/env bash
set -uo pipefail
out=
prev=
for arg in "$@"; do
  [[ $prev == -o ]] && out=$arg
  prev=$arg
done
if [[ ${STUB_CURL_EXIT:-0} -ne 0 ]]; then
  echo "stub curl: simulated transport failure" >&2
  exit "${STUB_CURL_EXIT}"
fi
[[ -n $out ]] && printf '%s' "${STUB_BODY:-}" >"$out"
printf '%s' "${STUB_CODE:-200}"
exit 0
STUB
chmod +x "$stubs/curl"

export PATH="$stubs:$PATH"

pass=0
fail=0

# Runs the gate with the given environment and asserts its exit code, and
# optionally that its combined output mentions `$3`.
expect() {
  local want=$1 desc=$2 needle=${3:-}
  local got out
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
  echo "ok: $desc (exit $got)"
  pass=$((pass + 1))
}

body_with() {
  local contexts=$1
  cat <<JSON
[{"type":"required_status_checks","ruleset_id":20607291,
  "parameters":{"required_status_checks":[$contexts]}}]
JSON
}

export STUB_CURL_EXIT=0
export STUB_CODE=200

# --- the happy path, reading the real constant out of the real guard ---------
#
# No RULESET_EXPECTED here on purpose: this is the assertion that the guard file
# still carries a parseable REQUIRED_CHECK, and that it is the string the
# ruleset requires today.
STUB_BODY=$(body_with '{"context":"Wire compat"}')
export STUB_BODY
expect 0 "ruleset requires exactly the guard's REQUIRED_CHECK" "Wire compat"

# --- drift: the context was dropped from the ruleset -------------------------
#
# The headline failure. The job still runs and still reports; nothing enforces
# it any more.
STUB_BODY='[]'
expect 1 "no status checks required at all is drift, not a pass" "<none"

# --- drift: the ruleset requires something else ------------------------------
STUB_BODY=$(body_with '{"context":"Wire compat (rust)"}')
expect 1 "a renamed context on the ruleset is drift" "DRIFT"

# --- drift: an extra context nobody removed ----------------------------------
STUB_BODY=$(body_with '{"context":"Wire compat"},{"context":"Extra gate"}')
expect 1 "an unexpected extra required context is drift" "Extra gate"

# --- multi-word contexts survive the round trip ------------------------------
#
# Regression: every context in this fleet contains a space ("Wire compat",
# "Build & test"). The comparison was always whole-string safe; the *report* was
# not, and an operator reading `Wire` and `compat` on two lines is being told
# something false about what is enforced. So this asserts on the rendered line,
# not just on the exit code -- an exit-code-only assertion passes with the bug
# still in place.
STUB_BODY=$(body_with '{"context":"Build & test"},{"context":"nginx config test (website)"}')
RULESET_EXPECTED='Build & test
nginx config test (website)' expect 0 \
  "contexts containing spaces and parens survive the report" \
  '    nginx config test (website)'

# --- order and duplicates are not drift --------------------------------------
STUB_BODY=$(body_with '{"context":"B check"},{"context":"A check"},{"context":"B check"}')
RULESET_EXPECTED='A check
B check' expect 0 "the required set is compared as a set, not a list"

# --- undetermined: the API said no -------------------------------------------
STUB_CODE=403 STUB_BODY='{"message":"Resource not accessible by integration"}' \
  expect 2 "HTTP 403 is undetermined, never drift" "HTTP 403"

STUB_CODE=404 STUB_BODY='{"message":"Not Found"}' \
  expect 2 "HTTP 404 is undetermined, never drift" "HTTP 404"

# --- undetermined: 200 with something that is not the documented shape -------
STUB_CODE=200 STUB_BODY='{"message":"nope"}' \
  expect 2 "a 200 that is not an array is undetermined" "did not return an array"

STUB_CODE=200 STUB_BODY='not json at all' \
  expect 2 "an unparseable 200 is undetermined"

# --- undetermined: the transport failed --------------------------------------
STUB_CURL_EXIT=7 STUB_BODY='' expect 2 "a transport failure is undetermined" "could not reach"

# --- undetermined: the guard itself moved ------------------------------------
#
# If REQUIRED_CHECK is renamed or reshaped there is nothing to compare against.
# Answering 0 there would be the worst outcome available: a green gate that
# checked nothing, which is precisely the class this whole file guards.
STUB_CURL_EXIT=0
STUB_CODE=200
STUB_BODY=$(body_with '{"context":"Wire compat"}')
echo 'const SOMETHING_ELSE: &str = "Wire compat";' >"$tmp/renamed.rs"
RULESET_GUARD="$tmp/renamed.rs" \
  expect 2 "a guard with no REQUIRED_CHECK is undetermined, not green" "nothing to compare"

echo
echo "ruleset-drift-test: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
