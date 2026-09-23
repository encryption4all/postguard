#!/usr/bin/env bash
#
# Checks the two stated budgets on the map body of #247 (#442, #445): the
# whole body must be <=153,600 bytes (150 KiB), and every entry in "##
# Decisions so far" must be <=400 bytes. Both are UTF-8 *byte* counts, not
# character counts -- several entries carry em-dashes and arrows that are 3
# bytes each, so a character-based check would pass lines that are actually
# over.
#
# Usage:
#   scripts/map-budget.sh <path-to-body-file>
#
# It takes a file, not an issue number: the fetch belongs to the caller, so
# this is testable offline with no network and no credential.
#
# What it checks:
#   * BODY_BUDGET_BYTES: the whole file. #247's own "## Notes" header
#     comment says only "keep the body under 150 KB", not an exact byte
#     count -- read as 150 KiB (153,600 bytes) to match the binary-KB
#     convention that same sentence uses for GitHub's exact 262,144-byte
#     (256*1024) hard cap.
#   * ENTRY_BUDGET_BYTES: every line beginning "- [" inside the
#     "## Decisions so far" section, stated in that section's own header
#     comment as an exact, hard 400 bytes. The section runs from the "##
#     Decisions so far" heading to the next "## " heading (or EOF, if none
#     follows).
#
# Deliberately out of scope: "## Notes"'s own 16 KiB (16,384-byte) budget
# and "## Findings not yet in Notes"'s 4,000-byte budget. Both are read by a
# human deciding what to promote, the parse surface for per-section budgets
# is larger, and #442 decided to check the two numbers the map's rules
# actually state rather than every number on the page.
#
# Exit codes (same three-way contract as scripts/ruleset-drift.sh and
# scripts/changelog-coverage.sh -- conflating "over budget" with "could not
# tell" sends someone to fix the wrong thing):
#
#   0    the body is within BODY_BUDGET_BYTES and every "Decisions so far"
#        entry is within ENTRY_BUDGET_BYTES.
#   1    a real finding: the body is over, or at least one entry is over.
#        The body's size against its budget, and every offending entry as
#        "<bytes>  <first 80 chars>", are printed so the output is
#        actionable without opening the issue.
#   2    could not determine: the file does not exist, is empty, or has no
#        "## Decisions so far" heading. Never reported as 0 -- a body that
#        cannot be parsed is not a body within budget.
#
# scripts/map-budget-test.sh pins this mapping, offline, against fixtures
# built in a temp dir plus a permanent snapshot of the real body.
#
set -euo pipefail

# 153,600 bytes (150 KiB) -- #247's "## Notes" header comment says "150 KB",
# read as binary KB per the module comment above.
readonly BODY_BUDGET_BYTES=153600
# 400 bytes, stated in #247's "## Decisions so far" header comment.
readonly ENTRY_BUDGET_BYTES=400

if [[ $# -ne 1 ]]; then
  echo "usage: map-budget.sh <path-to-body-file>" >&2
  exit 2
fi

path=$1

if [[ ! -f $path ]]; then
  echo "map-budget: '$path' does not exist" >&2
  exit 2
fi

body_bytes=$(wc -c <"$path")
if [[ $body_bytes -eq 0 ]]; then
  echo "map-budget: '$path' is empty" >&2
  exit 2
fi

if ! grep -qF '## Decisions so far' "$path"; then
  echo "map-budget: '$path' has no '## Decisions so far' heading" >&2
  exit 2
fi

# The section runs from the heading to the next '## ' heading, or EOF if
# "Decisions so far" is the last section in the file.
section=$(awk '
  /^## Decisions so far/ { found = 1; next }
  found && /^## / { exit }
  found { print }
' "$path")

offenders=()
while IFS= read -r line; do
  [[ $line == "- ["* ]] || continue
  bytes=$(printf '%s' "$line" | wc -c)
  if [[ $bytes -gt $ENTRY_BUDGET_BYTES ]]; then
    offenders+=("$bytes  ${line:0:80}")
  fi
done <<<"$section"

over_body=0
[[ $body_bytes -gt $BODY_BUDGET_BYTES ]] && over_body=1

if [[ $over_body -eq 0 && ${#offenders[@]} -eq 0 ]]; then
  echo "map-budget: OK -- $path is $body_bytes byte(s) (budget $BODY_BUDGET_BYTES), every 'Decisions so far' entry is within $ENTRY_BUDGET_BYTES bytes" >&2
  exit 0
fi

echo "map-budget: $path is over budget:" >&2
if [[ $over_body -eq 1 ]]; then
  printf '%d  body exceeds the %d-byte budget\n' "$body_bytes" "$BODY_BUDGET_BYTES"
fi
for o in "${offenders[@]}"; do
  printf '%s\n' "$o"
done
exit 1
