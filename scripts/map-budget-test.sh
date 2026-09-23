#!/usr/bin/env bash
#
# Regression tests for scripts/map-budget.sh, covering the exit-code
# contract: 1 means a real finding (over budget), 2 means the script could
# not find out. Conflating them is the failure this pins -- see the header
# of map-budget.sh for why.
#
# Entirely offline: every fixture is built in a temp dir, except the
# known-good fixture at scripts/testdata/map-247-body.md, which is a
# permanent, committed snapshot of #247's real body (#445) -- taken with
# `gh issue view 247 -R encryption4all/postguard --json body -q .body` on
# 2026-09-23, byte for byte, trailing blank lines included. It is a
# snapshot, not a live copy: #247's body will keep changing after this is
# committed, and this fixture is not meant to track it.
#
# Usage:
#   scripts/map-budget-test.sh
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

gate="$root/scripts/map-budget.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# Runs the gate on <path> and asserts its exit code, and optionally that its
# combined output mentions `$needle`.
expect() {
  local want=$1 desc=$2 path=$3 needle=${4:-}
  local got out
  set +e
  out=$("$gate" "$path" 2>&1)
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

# A "- [" line of exactly <bytes> bytes, ASCII only -- "- [" is 3 bytes, the
# rest is filler.
ascii_entry() {
  local bytes=$1
  local prefix="- ["
  local fill=$((bytes - ${#prefix}))
  printf '%s' "$prefix"
  head -c "$fill" </dev/zero | tr '\0' 'x'
}

# A minimal, valid map body: a "## Decisions so far" section (with the
# section's own header comment, same as the real one) containing whatever
# entry lines are passed, followed by a next section so the "runs to the
# next '## ' heading" boundary is exercised too, not just the EOF case.
make_body() {
  {
    printf '## Notes\n\nSome notes.\n\n'
    printf '## Decisions so far\n\n'
    printf '<!-- ONE LINE per closed ticket, 400 bytes hard. -->\n\n'
    cat
    printf '\n## Not yet specified\n\nfog.\n'
  } >"$1"
}

# --- known-good: a body inside both budgets -----------------------------
good="$tmp/good.md"
make_body "$good" <<'EOF'
- [an entry well under the byte cap](https://example.com/1) -- fine.
EOF
expect 0 "a body inside both budgets" "$good"

# --- real finding: the whole body is over 153,600 bytes -----------------
big="$tmp/big.md"
make_body "$big" <<'EOF'
- [an entry well under the byte cap](https://example.com/1) -- fine.
EOF
# Padding well past the 153,600-byte budget without touching the section
# syntax the parser looks for.
head -c 155000 </dev/zero | tr '\0' 'x' >>"$big"
expect 1 "a body over the 153,600-byte budget" "$big" "153600"

# --- real finding: one 401-byte entry ------------------------------------
over_entry="$tmp/over-entry.md"
make_body "$over_entry" <<EOF
$(ascii_entry 401)
EOF
expect 1 "a 401-byte entry" "$over_entry" "401"

# --- boundary: a 400-byte entry is within the cap (inclusive) -----------
at_cap="$tmp/at-cap.md"
make_body "$at_cap" <<EOF
$(ascii_entry 400)
EOF
expect 0 "a 400-byte entry is within the cap" "$at_cap"

# --- real finding: 400 characters but over 400 bytes ---------------------
#
# Built from em-dashes (3 bytes each in UTF-8): "- [" (3 ASCII chars) plus
# 397 em-dashes is exactly 400 *characters*, but 3 + 397*3 = 1194 *bytes*. A
# character-based check would pass this; a byte-based one must not.
em_dash=$'\xe2\x80\x94'
em_dash_entry="- ["
for _ in $(seq 1 397); do
  em_dash_entry+="$em_dash"
done
em_dash_chars=$(printf '%s' "$em_dash_entry" | wc -m)
em_dash_bytes=$(printf '%s' "$em_dash_entry" | wc -c)
if [[ $em_dash_chars -ne 400 || $em_dash_bytes -le 400 ]]; then
  echo "FAIL: em-dash fixture is not shaped as intended -- $em_dash_chars chars, $em_dash_bytes bytes"
  fail=$((fail + 1))
else
  em_dash_body="$tmp/em-dash.md"
  make_body "$em_dash_body" <<EOF
$em_dash_entry
EOF
  expect 1 "an entry that is 400 characters but over 400 bytes" "$em_dash_body" "$em_dash_bytes"
fi

# --- undetermined: the file does not exist -------------------------------
expect 2 "a nonexistent path is undetermined, not a pass" "$tmp/does-not-exist.md"

# --- undetermined: the file is empty --------------------------------------
empty="$tmp/empty.md"
: >"$empty"
expect 2 "an empty file is undetermined, not a pass" "$empty" ""

# --- undetermined: no '## Decisions so far' heading ------------------------
no_heading="$tmp/no-heading.md"
printf '## Notes\n\nSome notes, no decisions section at all.\n' >"$no_heading"
expect 2 "a body with no '## Decisions so far' heading is undetermined" "$no_heading" "Decisions so far"

# --- undetermined: a heading-level typo is not the heading -----------------
#
# "### Decisions so far" (three '#'s) must not satisfy the existence check:
# an unanchored `grep -qF` match would find "## Decisions so far" as a
# substring of that line and report found, while the awk section-extractor's
# anchored `^## Decisions so far` never matches it, so the section comes back
# empty and every entry inside it -- however far over the cap -- is silently
# skipped. That combination reported exit 0 "OK" on a body it could not
# actually parse, the case the module comment above disclaims.
typo_heading="$tmp/typo-heading.md"
make_body "$typo_heading" <<EOF
$(ascii_entry 450)
EOF
sed -i 's/^## Decisions so far$/### Decisions so far/' "$typo_heading"
expect 2 "a '### Decisions so far' heading-level typo is undetermined, not a pass despite a 450-byte entry inside it" "$typo_heading" "Decisions so far"

# --- boundary: a '- [' line outside the section is ignored -----------------
outside="$tmp/outside.md"
{
  printf '## Notes\n\n'
  ascii_entry 500
  printf '\n\n'
  printf '## Decisions so far\n\n'
  printf '<!-- ONE LINE per closed ticket, 400 bytes hard. -->\n\n'
  printf '%s\n' "- [an entry well under the byte cap](https://example.com/1) -- fine."
  printf '\n## Not yet specified\n\nfog.\n'
} >"$outside"
expect 0 "a '- [' line outside the section is ignored" "$outside"

# --- undetermined: bad usage ------------------------------------------------
out=$("$gate" 2>&1) && got=0 || got=$?
if [[ $got -eq 2 && $out == *usage* ]]; then
  echo "ok: no arguments is undetermined, not a pass (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: no arguments -- wanted exit 2 with a usage message, got $got: $out"
  fail=$((fail + 1))
fi

out=$("$gate" "$good" extra 2>&1) && got=0 || got=$?
if [[ $got -eq 2 && $out == *usage* ]]; then
  echo "ok: too many arguments is undetermined, not a pass (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: too many arguments -- wanted exit 2 with a usage message, got $got: $out"
  fail=$((fail + 1))
fi

# --- known-good: the real current body, a permanent fixture ----------------
#
# See the module comment above for what this is and where it came from.
expect 0 "the real #247 body (scripts/testdata/map-247-body.md) is within both budgets" \
  "$root/scripts/testdata/map-247-body.md"

echo
echo "map-budget-test: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
