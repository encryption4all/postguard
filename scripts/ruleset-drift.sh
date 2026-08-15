#!/usr/bin/env bash
#
# The registry half of the wiring guards (issue #318).
#
# `pg-core/tests/ci_wiring.rs` asserts that a job in `build.yml` still produces
# the context string `Wire compat`. That is one end of a two-ended link. The
# other end lives in GitHub's API: the `main` branch ruleset has to still
# *require* that context. Both ends are load bearing and they fail differently:
#
#   * A renamed job leaves the ruleset requiring a context nothing produces.
#     Nothing then blocks, because a required check that never reports is not a
#     failing check -- `#299` measured that an *absent* check is as dangerous as
#     a red one. `ci_wiring.rs` catches this end.
#   * A context dropped from the ruleset leaves the job running and green while
#     enforcing nothing at all. Every test stays green. Nothing caught this end
#     until this script, because a test runner cannot read the API.
#
# `#272` and `postguard-js#222` both wrote this end off as "stays manual", on
# the assumption that reading a ruleset needs an admin credential in CI. That
# assumption was wrong and the spike in `#318` measured it: on a **public**
# repository the effective-rules endpoint answers 200 to the built-in
# `GITHUB_TOKEN` at *any* permission level, `permissions: {}` included, and
# across repositories. No PAT, no App token, no secret.
#
# What that measurement does *not* buy is the bypass list. `bypass_actors` is
# returned only to a caller with write access to the ruleset, so this script
# cannot see it and deliberately does not pretend to. Two traps found on the
# way, both recorded here because each looks like a working assertion:
#
#   * `current_user_can_bypass` IS returned to the Actions token -- and reads
#     `"never"` on `postguard-js`, where the `developers` team holds
#     `bypass_mode: always` (`#317`). It describes the caller, not the ruleset,
#     so asserting on it yields a false all-clear on exactly the repo that has
#     the problem. Never use it as a proxy for "nobody bypasses".
#   * The classic protection endpoint (`/branches/main/protection`) 403s for the
#     Actions token, so the classic half cannot be read from CI either.
#
# One thing comes free from using the *effective* rules endpoint rather than
# reading the ruleset by id: it omits rulesets whose enforcement is `disabled`
# or `evaluate`. So the escape hatch in root `CLAUDE.md` -- flip the ruleset to
# `enforcement=disabled`, merge, flip it back -- is reported as drift while it
# is open, which is the loud behaviour that hatch is supposed to have.
#
# Usage:
#   scripts/ruleset-drift.sh
#
# Environment:
#   RULESET_REPO     owner/name to inspect. Default: encryption4all/postguard.
#   RULESET_BRANCH   branch whose effective rules are read. Default: main.
#   RULESET_EXPECTED newline-separated contexts to expect. Default: read out of
#                    pg-core/tests/ci_wiring.rs, so the expectation has exactly
#                    one home and this script cannot drift from the test.
#   RULESET_GUARD    path the expected set is read from when RULESET_EXPECTED is
#                    unset. Default: pg-core/tests/ci_wiring.rs.
#   GH_TOKEN         optional. Sent as a bearer token when set. Unauthenticated
#                    works on a public repo but shares a 60/hour per-IP budget
#                    with every other job on the runner, so CI should pass one.
#   GITHUB_API_URL   API root. Default: https://api.github.com.
#
# Exit codes, which must not be conflated -- the same lesson
# `scripts/semver-checks.sh` records for cargo-semver-checks' 100 vs 101:
#
#   0    the ruleset requires exactly the expected contexts
#   1    drift: the required set and the expected set differ
#   2    undetermined: the API was unreachable, answered non-200, or returned
#        something this script could not parse. NOT drift. Reporting it as
#        drift would send someone to edit a ruleset that is probably correct.
#   127  a required tool is missing
#
# scripts/ruleset-drift-test.sh pins this mapping.
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

repo=${RULESET_REPO:-encryption4all/postguard}
branch=${RULESET_BRANCH:-main}
api=${GITHUB_API_URL:-https://api.github.com}
guard=${RULESET_GUARD:-pg-core/tests/ci_wiring.rs}

for tool in curl jq; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "ruleset-drift: $tool is not installed" >&2
    exit 127
  }
done

# The expected set. Reading it out of the Rust guard rather than restating it
# here is the whole point: a second copy of "Wire compat" would be a second
# thing to forget, and this script exists because of a forgotten second half.
if [[ -n ${RULESET_EXPECTED:-} ]]; then
  expected=$(printf '%s\n' "$RULESET_EXPECTED" | sed '/^$/d' | LC_ALL=C sort -u)
else
  expected=$(sed -n 's/^const REQUIRED_CHECK: &str = "\(.*\)";$/\1/p' "$guard" |
    LC_ALL=C sort -u)
  if [[ -z $expected ]]; then
    echo "ruleset-drift: no REQUIRED_CHECK constant found in $guard, so there is" >&2
    echo "  nothing to compare the ruleset against. The guard was renamed or" >&2
    echo "  reshaped; this script has to follow it." >&2
    exit 2
  fi
fi

body=$(mktemp)
trap 'rm -f "$body"' EXIT

# Spelled as an `if` rather than `[[ ... ]] && auth=(...)`: a failing test as
# the head of an `&&` list is one of the corners where `set -e` behaviour has
# varied, and this is the branch taken when no token is set -- the path that
# would only ever break in someone else's shell. `auth=("")` rather than an
# empty array for the same defensiveness: `"${auth[@]}"` on an empty array is an
# unbound-variable error under `set -u` before bash 4.4.
auth=(-H "X-Postguard-Unauthenticated: 1")
if [[ -n ${GH_TOKEN:-} ]]; then
  auth=(-H "Authorization: Bearer $GH_TOKEN")
fi

# --retry covers a blip without turning one into a red gate; a persistent
# failure still lands on exit 2 rather than being reported as drift.
code=$(curl -sS -o "$body" -w '%{http_code}' \
  --retry 3 --retry-delay 2 --retry-all-errors --max-time 30 \
  "${auth[@]}" \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  "$api/repos/$repo/rules/branches/$branch" 2>/dev/null) || {
  echo "ruleset-drift: could not reach $api" >&2
  exit 2
}

if [[ $code != 200 ]]; then
  echo "ruleset-drift: $api/repos/$repo/rules/branches/$branch answered HTTP $code" >&2
  head -c 400 "$body" >&2
  echo >&2
  exit 2
fi

jq -e 'type == "array"' "$body" >/dev/null 2>&1 || {
  echo "ruleset-drift: the effective-rules endpoint did not return an array" >&2
  head -c 400 "$body" >&2
  echo >&2
  exit 2
}

# Every required_status_checks rule in force on the branch, from whichever
# ruleset supplies it -- repository or organization. Pinning a ruleset id here
# would report a false failure when an equivalent rule arrives from another
# ruleset, and the question this asks is "is the context enforced", not "by
# which row".
actual=$(jq -r '
  [ .[]
    | select(.type == "required_status_checks")
    | .parameters.required_status_checks[]?
    | .context
  ] | .[]' "$body" | LC_ALL=C sort -u)

sources=$(jq -r '[.[] | select(.type == "required_status_checks") | .ruleset_id]
  | unique | map(tostring) | join(", ")' "$body")

# Contexts contain spaces ("Wire compat", "Build & test"), so every one of
# these has to stay a whole line: an unquoted expansion splits one context into
# two and reports a drift that is not there.
indent() { sed 's/^/    /' <<<"$1"; }

if [[ $actual == "$expected" ]]; then
  echo "ruleset-drift: OK -- $repo@$branch requires exactly:"
  indent "$expected"
  echo "  (from ruleset(s): ${sources:-none})"
  exit 0
fi

echo "ruleset-drift: DRIFT on $repo@$branch" >&2
echo >&2
echo "  required by the ruleset (from ruleset(s): ${sources:-none}):" >&2
if [[ -z $actual ]]; then
  echo "    <none -- the branch requires no status checks at all>" >&2
else
  indent "$actual" >&2
fi
echo "  expected, per $guard:" >&2
indent "$expected" >&2
echo >&2
echo "  A context this repo produces but the ruleset no longer names enforces" >&2
echo "  nothing while every test stays green. Either restore it on the ruleset," >&2
echo "  or move the guard's constant in the same change." >&2
exit 1
