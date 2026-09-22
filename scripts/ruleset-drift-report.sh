#!/usr/bin/env bash
#
# Drives scripts/ruleset-drift.sh once per run and files an issue when it
# reports drift (#422).
#
# `build.yml`'s `ruleset-drift` job used to run scripts/ruleset-drift.sh
# directly: it reddened on drift and filed nothing, and in this fleet a red
# job has gone unread for 15 days without anyone noticing (see the issue).
# This script is the reporting half that job was missing, extracted rather
# than written inline for the same reason #429 extracted
# scripts/changelog-coverage-report.sh out of delivery.yml: a `run:` block
# with no `shell:` key executes as `bash -e {0}`, so
# `output=$(scripts/ruleset-drift.sh); code=$?` inline would abort the step at
# the checker's non-zero exit, before `code=$?` is ever reached. Extracting the
# capture into a script this repo owns does not manage that shell more
# carefully with `set +e`; it makes the hazard stop existing, because the
# capture below happens inside a shell this script starts, not the one GitHub
# wraps the `run:` block in.
#
# Deliberately not `-e` here either, for the same reason: the whole point is to
# read scripts/ruleset-drift.sh's exit code deliberately rather than have a
# shell abort past it.
#
# Usage:
#   scripts/ruleset-drift-report.sh
#
# Environment:
#   GITHUB_EVENT_NAME    set by Actions. Filing only happens on `push`; see
#                        the guard below.
#   GITHUB_REF           set by Actions. Filing only happens on
#                        `refs/heads/main`; see the guard below.
#   GH_TOKEN             passed to `gh` for both the dedupe read and any issue
#                        it creates, and to scripts/ruleset-drift.sh for the
#                        ruleset read.
#   GH_REPO              passed to `gh` so it does not have to infer the
#                        repository.
#   RULESET_DRIFT_CHECKER  overrides the checker command run below. Default:
#                        scripts/ruleset-drift.sh. This override exists only
#                        so scripts/ruleset-drift-report-test.sh can drive
#                        known exit codes offline -- real drift cannot be
#                        manufactured without the network, and
#                        scripts/changelog-coverage-report-test.sh's trick of
#                        stubbing a collaborator on `PATH` does not work here:
#                        the checker is invoked below by a relative path,
#                        after `cd "$root"`, so a same-named stub earlier on
#                        `PATH` would never be found. Do not read this as a
#                        production knob; nothing sets it outside the test.
#
# Exit codes (2 dominates 1, matching scripts/ruleset-drift.sh's own
# contract and scripts/changelog-coverage-report.sh's precedent -- a real
# finding that never reached anyone is not a reported finding):
#
#   0    the checker exited 0: no drift.
#   1    the checker exited 1: drift, reported and filed (subject to the
#        push-to-main guard below) or deduped against an already-open issue.
#   2    the checker exited 2 (undetermined -- not drift, and not reported as
#        drift), or the dedupe read failed, or `gh issue create` failed.
#   127  the checker exited 127 (a required tool is missing on the runner).
#
# Only the checker's stdout goes in a filed issue's body, mirroring
# scripts/changelog-coverage-report.sh's `output=$(...)` exactly. Unlike
# scripts/changelog-coverage.sh, scripts/ruleset-drift.sh writes its DRIFT and
# undetermined diagnostics to stderr, not stdout, so that stream reaches the
# job log directly (this script never redirects it) rather than the issue
# body. That is scripts/ruleset-drift.sh's own design, unchanged here -- see
# the module comment for why this ticket does not touch it.
#
# scripts/ruleset-drift-report-test.sh pins this mapping, offline, against a
# stub in place of scripts/ruleset-drift.sh.
#
set -uo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

checker=${RULESET_DRIFT_CHECKER:-scripts/ruleset-drift.sh}

TITLE="ruleset: main's required rules have drifted"

# If this read fails there is nothing to dedupe against, so a finding already
# filed on a previous run would be filed again -- proceeding on a bad read
# risks noise, not silence, and exit 2 says so honestly rather than either
# filing a duplicate or claiming a pass. Nothing is checked and nothing is
# filed, matching scripts/changelog-coverage-report.sh's own precedent for the
# same failure.
existing_titles=$(gh issue list --state open --label ruleset-drift --json title --jq '.[].title')
list_status=$?
if [[ $list_status -ne 0 ]]; then
  echo "::error::could not read existing open ruleset-drift-labelled issues (gh issue list exited $list_status) -- not running the checker, filing nothing" >&2
  exit 2
fi

output=$("$checker")
code=$?

if [[ $code -eq 0 ]]; then
  echo "ruleset-drift-report: OK -- no drift"
  exit 0
fi

if [[ $code -eq 2 ]]; then
  echo "::error::scripts/ruleset-drift.sh could not determine whether main's ruleset has drifted (exit 2) -- the checker did not run to completion, this is not drift" >&2
  exit 2
fi

if [[ $code -eq 127 ]]; then
  echo "::error::scripts/ruleset-drift.sh reported a missing required tool (exit 127) -- the checker never ran, this is not drift" >&2
  exit 127
fi

# Only 1 (drift) remains in the checker's documented contract.
echo "::error::main's required rules have drifted from what pg-core/tests/ci_wiring.rs expects"

# The filing guard lives here, not in the calling workflow step, so the drift
# *check* keeps running -- and keeps reporting to the job log -- on every
# push and every pull request exactly as it does today. A step-level `if:`
# would have dropped the check along with the filing. `workflow_dispatch` on
# `main` deliberately falls in here too and files nothing: someone who pressed
# the button is already reading the output.
if [[ ${GITHUB_EVENT_NAME:-} != push || ${GITHUB_REF:-} != refs/heads/main ]]; then
  echo "drift found, but this run is not a push to main (event=${GITHUB_EVENT_NAME:-<unset>}, ref=${GITHUB_REF:-<unset>}) -- not filing, though the finding above is real"
  exit 1
fi

if grep -qFx "$TITLE" <<<"$existing_titles"; then
  echo "an open issue already names \"$TITLE\", not filing a duplicate"
  exit 1
fi

body=$(printf "main's required rules no longer match what \`pg-core/tests/ci_wiring.rs\`'s \`REQUIRED_CHECK\` expects.\n\nPaste-ready, from \`scripts/ruleset-drift.sh\`:\n\n\`\`\`\n%s\n\`\`\`\n" "$output")

if ! gh issue create --title "$TITLE" --body "$body" --label ruleset-drift; then
  echo "::error::gh issue create failed -- the drift above was found but not filed"
  exit 2
fi

exit 1
