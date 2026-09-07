#!/usr/bin/env bash
#
# Drives scripts/changelog-coverage.sh over every tag release-plz just cut,
# and files an issue for each real gap (#412, #429).
#
# This used to be a loop inline in delivery.yml's `changelog-coverage` step.
# A `run:` block with no `shell:` key executes as `bash -e {0}` (verified
# against the job log for run 33854598141, job 100965365720), and
# `code=$(scripts/changelog-coverage.sh "$package" "$tag"); code=$?` is a
# plain assignment whose exit status is the command substitution's -- under
# `-e` a non-zero exit there aborts the step immediately, before `code=$?` is
# even reached, so the branch that reads the exit code never ran. Extracting
# the loop into this script does not manage that shell more carefully with
# `set +e`; it makes the hazard stop existing. This script is invoked as one
# bare command, so its own non-zero exit reds the calling step correctly, and
# the exit-code capture below happens inside a shell this script owns.
#
# Deliberately not `-e` here either, for the same reason: the whole point is
# to read scripts/changelog-coverage.sh's exit code deliberately rather than
# have a shell abort past it.
#
# Usage:
#   scripts/changelog-coverage-report.sh
#
# Environment (matching what delivery.yml's `changelog-coverage` job sets):
#   RELEASES   release-plz's `releases` output, a JSON array of objects
#              carrying at least `package_name` and `tag`.
#   GH_TOKEN   passed to `gh` for both the read and any issue it creates.
#   GH_REPO    passed to `gh` so it does not have to infer the repository.
#
# Exit codes (2 dominates 1 -- a real gap that never reached anyone is not a
# reported finding):
#
#   0    every tag's entry accounts for its commits.
#   1    at least one real gap, all of them reported (in the job log) and
#        filed or deduped, and nothing was undetermined.
#   2    the gate could not speak: the existing-issue-titles read failed, a
#        tag came back undetermined, or `gh issue create` failed. Reported
#        even when real gaps were also found in the same run.
#
# scripts/changelog-coverage-report-test.sh pins this mapping, offline,
# against scripts/changelog-coverage.sh run for real over this repo's own
# immutable tags.
#
set -uo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

# If this read fails there is nothing to dedupe against, so a gap that was
# already filed on a previous run would be filed again -- proceeding to check
# tags on a bad read risks noise, not silence, and exit 2 says so honestly
# rather than either filing duplicates or claiming a pass. Nothing is checked
# and nothing is filed.
existing_titles=$(gh issue list --state open --label bug --json title --jq '.[].title')
list_status=$?
if [[ $list_status -ne 0 ]]; then
  echo "::error::could not read existing open bug-labelled issues (gh issue list exited $list_status) -- not checking any tag, filing nothing" >&2
  exit 2
fi

# `undetermined` dominates `gap_found` in the exit code below: a gap this run
# never reported is not a reported finding, and an undetermined tag alongside
# a real gap must not read as a clean pass.
gap_found=0
undetermined=0

while IFS=$'\t' read -r package tag; do
  [[ -z $package ]] && continue

  output=$(scripts/changelog-coverage.sh "$package" "$tag")
  code=$?

  if [[ $code -eq 0 ]]; then
    echo "changelog-coverage: OK -- $tag"
    continue
  fi

  if [[ $code -eq 2 ]]; then
    # Undetermined is not the same failure as "the entry is missing a
    # commit" -- see scripts/changelog-coverage.sh's own exit-code contract.
    # No issue is filed: an unrunnable checker is not a changelog gap, and
    # filing one would misreport it as one.
    undetermined=1
    echo "::error::changelog-coverage.sh could not determine coverage for $package $tag (exit $code) -- the checker did not run, this is not a changelog gap"
    continue
  fi

  gap_found=1
  echo "::error::$tag's changelog entry is missing commit(s) it contains"

  title="changelog: $tag omits commits it contains"
  if grep -qFx "$title" <<<"$existing_titles"; then
    echo "an open issue already names \"$title\", not filing a duplicate"
    continue
  fi

  body=$(printf 'The changelog entry for `%s` does not list every commit the tag contains.\n\nMissing, paste-ready:\n\n```\n%s\n```\n' \
    "$tag" "$output")
  if ! gh issue create --title "$title" --body "$body" --label bug; then
    undetermined=1
    echo "::error::gh issue create failed for \"$title\" -- the gap above was found but not filed"
  fi
done < <(jq -r '.[] | [.package_name, .tag] | @tsv' <<<"$RELEASES")

if [[ $undetermined -eq 1 ]]; then
  exit 2
fi
if [[ $gap_found -eq 1 ]]; then
  exit 1
fi
exit 0
