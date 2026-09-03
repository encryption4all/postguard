#!/usr/bin/env bash
#
# Asserts that a released tag's changelog entry lists every commit the tag
# actually contains (issue #411, #412).
#
# release-plz opens a release PR whose changelog hunk is computed when the PR
# is opened. A commit that lands on `main` while that PR is still open ships
# inside the release -- it is an ancestor of the tag -- but is absent from the
# entry, and can never be added by the normal path: the next release computes
# its entry from commits since *this* tag, and the missed commit is behind it.
# Measured over this repo's whole tag history, it has happened twice
# (cryptify-v0.1.36, pg-core-v0.6.5) and both times every check stayed green,
# because nothing compared a tag's contents against its own entry.
#
# Usage:
#   scripts/changelog-coverage.sh <package> <tag>
#   e.g. scripts/changelog-coverage.sh cryptify cryptify-v0.1.36
#
# What it compares:
#   * Range: <previous tag in the package's own series>..<tag>. The series is
#     `<package>-v*`, ordered with `sort -V` (lexical order puts v0.1.9 after
#     v0.1.36).
#   * Commits: `git log --format=%s <range> -- <package>`, i.e. commits that
#     touch the package's own directory.
#   * Exclusions: release-plz's own release commits, matched on subject
#     against `^chore(\(.*\))?: release` -- both the multi-package form
#     (`chore: release (#389)`) and the single-package form
#     (`chore(cryptify): release v0.1.36 (#407)`) occur in this repo's
#     history, and missing either makes the check report false gaps on almost
#     every tag.
#   * Identity: the trailing `(#N)` in the commit subject. A commit with no
#     `(#N)` came from a direct push, and falls back to matching its
#     (prefix-stripped) description against the entry text.
#   * Direction: SUBSET, not equality. Every commit must appear in the entry;
#     extra entries are allowed and must not fail. release-plz also writes
#     dependency-driven entries (e.g. pg-pkg-v0.6.0 carries 19 entries for 16
#     path-scoped commits), so an equality check would go red on a correct
#     release -- and a gate that cries wolf on correct releases gets bypassed.
#
# Both the range and the changelog entry are read at the tag
# (`git show <tag>:...`), never from the working tree: the working tree may
# already carry a corrected entry for a tag whose historical bad state is
# exactly what a regression test needs to see.
#
# Exit codes (same three-way contract as scripts/ruleset-drift.sh, and for the
# same reason -- conflating "drift" with "could not find out" sends someone to
# fix the wrong thing):
#
#   0    every commit in the range is accounted for in the entry.
#   1    one or more commits are missing from the entry. Each is printed to
#        stdout, one per line, as a paste-ready changelog bullet.
#   2    could not determine: bad usage, the tag does not exist, there is no
#        previous tag in the package's series, the changelog has no entry for
#        that version, or the commit range could not be walked (e.g. a
#        shallow clone with no history). Never reported as 0.
#
# scripts/changelog-coverage-test.sh pins this mapping against fixtures
# already in this repo's tag history.
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

if [[ $# -ne 2 ]]; then
  echo "usage: changelog-coverage.sh <package> <tag>" >&2
  exit 2
fi

package=$1
tag=$2
pkg_dir=$package
changelog_path="$pkg_dir/CHANGELOG.md"

if ! git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  echo "changelog-coverage: tag '$tag' not found" >&2
  exit 2
fi

# The previous tag in the same package series, by version order. `sort -V`
# rather than lexical sort: v0.1.9 must not sort after v0.1.36.
prev=$(git tag -l "${package}-v*" | sort -V | awk -v t="$tag" '$0==t{print p; exit} {p=$0}')
if [[ -z $prev ]]; then
  echo "changelog-coverage: no tag before '$tag' in the ${package}-v* series -- nothing to compare it against" >&2
  exit 2
fi

range="$prev..$tag"

# The version string a changelog entry is headed with, e.g. "0.1.36" from
# "cryptify-v0.1.36".
version=${tag#"${package}"-v}

changelog=$(git show "$tag:$changelog_path" 2>/dev/null) || {
  echo "changelog-coverage: '$changelog_path' not found at $tag" >&2
  exit 2
}

entry=$(awk -v ver="$version" '
  $0 ~ "^## \\[" ver "\\]" { found = 1; print; next }
  found && /^## \[/ { exit }
  found { print }
' <<<"$changelog")
if [[ -z $entry ]]; then
  echo "changelog-coverage: no '## [$version]' entry in $changelog_path at $tag" >&2
  exit 2
fi

commits=$(git log --format=%s "$range" -- "$pkg_dir") || {
  echo "changelog-coverage: could not walk $range for $pkg_dir -- shallow clone with no history?" >&2
  exit 2
}

# Splits a commit subject into its conventional-commit scope (may be empty),
# description (type/scope prefix and every trailing "(#N)" stripped) and the
# PR numbers found, most-recent (rightmost) last. Printed as three lines so
# the caller can capture them with `mapfile` without an array-passing dance.
parse_commit() {
  local subject=$1 scope="" description prs=()
  local header_re='^[A-Za-z_-]+(\(([^)]*)\))?!?:[[:space:]](.*)$'
  local pr_re='\(#([0-9]+)\)'
  if [[ $subject =~ $header_re ]]; then
    scope=${BASH_REMATCH[2]}
    description=${BASH_REMATCH[3]}
  else
    description=$subject
  fi
  while [[ $description =~ $pr_re ]]; do
    prs+=("${BASH_REMATCH[1]}")
    description=${description/"${BASH_REMATCH[0]}"/}
  done
  description=$(sed -E 's/[[:space:]]+$//' <<<"$description")
  printf '%s\n%s\n%s\n' "$scope" "$description" "${prs[*]-}"
}

release_re='^chore(\(.*\))?: release'
missing=()
while IFS= read -r subject; do
  [[ -z $subject ]] && continue
  [[ $subject =~ $release_re ]] && continue

  mapfile -t parsed < <(parse_commit "$subject")
  scope=${parsed[0]} description=${parsed[1]}
  read -ra prs <<<"${parsed[2]}"

  accounted=0
  if [[ ${#prs[@]} -gt 0 ]]; then
    for pr in "${prs[@]}"; do
      # Boundary-anchored: a plain substring match would count #4 as
      # accounted for by an entry that only names #48, #400, etc.
      if grep -qE "#${pr}([^0-9]|$)" <<<"$entry"; then
        accounted=1
        break
      fi
    done
  else
    grep -qF "$description" <<<"$entry" && accounted=1
  fi

  if [[ $accounted -eq 0 ]]; then
    if [[ ${#prs[@]} -gt 0 ]]; then
      last_pr=${prs[-1]}
      link="https://github.com/encryption4all/postguard/pull/$last_pr"
      if [[ -n $scope ]]; then
        missing+=("- *($scope)* $description ([#$last_pr]($link))")
      else
        missing+=("- $description ([#$last_pr]($link))")
      fi
    else
      missing+=("- $description")
    fi
  fi
done <<<"$commits"

if [[ ${#missing[@]} -eq 0 ]]; then
  echo "changelog-coverage: OK -- $tag's entry in $changelog_path accounts for every commit in $range touching $pkg_dir" >&2
  exit 0
fi

echo "changelog-coverage: $tag's entry in $changelog_path is missing ${#missing[@]} commit(s) that the tag contains:" >&2
for line in "${missing[@]}"; do
  printf '%s\n' "$line"
done
exit 1
