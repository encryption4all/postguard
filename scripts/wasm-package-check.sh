#!/usr/bin/env bash
#
# Asserts that an assembled pg-wasm package directory is publishable (#427).
#
# `delivery.yml`'s `publish-wasm` job builds two wasm-pack targets
# (`bundler`, `web`) into `pg-wasm/pkg/<target>`, then its `Assemble package`
# step copies in the committed `pg-wasm/package.json` and `pg-wasm/README.md`
# and publishes whatever ends up in `pg-wasm/pkg`. Nothing checked that
# assembly before publishing: the registry has served `@e4a/pg-wasm` with no
# readme (`ERROR: No README data found!`) since the package's first release,
# because the assemble step never copied one in and nothing said so.
#
# Usage:
#   scripts/wasm-package-check.sh <assembled-dir>
#
# What it checks:
#   * `README.md` exists and is more than a token -- a length floor, not a
#     content match, so this catches an absent file and a zero-byte copy
#     without pinning prose the README is free to reword.
#   * `package.json` parses and carries every field the published manifest is
#     expected to carry: name, version, description, license, repository,
#     homepage, exports, main, types. `version` is checked for presence only,
#     never for shape -- this check runs before `npm version` rewrites the
#     field (delivery.yml's `Set version and publish` step), so the value it
#     sees is always the committed placeholder `0.0.0`, never a release
#     version.
#   * The directory's file list matches exactly what the two wasm-pack
#     targets, plus the copied README and manifest, are expected to produce.
#     The expected set is derived from TARGETS/SHARED_FILES/BUNDLER_ONLY_FILES
#     below rather than hardcoded flat, so a target added or removed changes
#     what is expected in one place. Missing entries (a dropped `.wasm`) and
#     added entries (junk left behind by a wasm-pack upgrade) are reported
#     separately, since they are different failures with different fixes.
#
# Exit codes (same three-way contract as scripts/ruleset-drift.sh and
# scripts/changelog-coverage.sh -- conflating "not publishable" with "could
# not tell" sends someone to fix the wrong thing):
#
#   0    the directory is publishable.
#   1    a real defect: README.md absent or trivially short, package.json
#        missing a required field, or the file list does not match.
#   2    could not determine: the directory does not exist, is empty, or
#        package.json is missing or does not parse. Never reported as 0 -- a
#        build that produced nothing must not read as a clean package.
#   127  a required tool is missing.
#
# scripts/wasm-package-check-test.sh pins this mapping against fixtures it
# builds in a temp dir, offline, including one built from the real published
# `0.6.6` metadata as a permanent known-bad case.
#
set -euo pipefail

for tool in jq comm; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "wasm-package-check: $tool is not installed" >&2
    exit 127
  }
done

# The two wasm-pack targets `publish-wasm` builds, and the files each leaves
# behind after the assemble step's `rm -f` cleanup removes wasm-pack's own
# package.json/.gitignore/README.md. `bundler` alone gets `index_bg.js`:
# `--target web`'s glue is self-contained in `index.js`, while `--target
# bundler` re-exports from a separate `_bg.js` file. Matches the published
# 0.6.6 tarball exactly -- see scripts/testdata/pg-wasm-0.6.6/.
TARGETS=(bundler web)
SHARED_FILES=(index.js index.d.ts index_bg.wasm index_bg.wasm.d.ts LICENSE.md)
BUNDLER_ONLY_FILES=(index_bg.js)

REQUIRED_FIELDS=(name version description license repository homepage exports main types)

if [[ $# -ne 1 ]]; then
  echo "usage: wasm-package-check.sh <assembled-dir>" >&2
  exit 2
fi

dir=$1

if [[ ! -d $dir ]]; then
  echo "wasm-package-check: '$dir' does not exist" >&2
  exit 2
fi

if [[ -z $(find "$dir" -mindepth 1 -maxdepth 1 2>/dev/null) ]]; then
  echo "wasm-package-check: '$dir' is empty -- a build that produced nothing must not read as a clean package" >&2
  exit 2
fi

manifest="$dir/package.json"
if [[ ! -f $manifest ]]; then
  echo "wasm-package-check: '$manifest' does not exist" >&2
  exit 2
fi

manifest_json=$(jq -e . "$manifest" 2>/dev/null) || {
  echo "wasm-package-check: '$manifest' does not parse as JSON" >&2
  exit 2
}

defects=()

readme="$dir/README.md"
# 40 bytes is well under any real paragraph and well over a stray newline or a
# copy that silently produced an empty file.
readme_min_bytes=40
if [[ ! -f $readme ]]; then
  defects+=("README.md is missing from $dir")
else
  readme_bytes=$(wc -c <"$readme")
  if [[ $readme_bytes -lt $readme_min_bytes ]]; then
    defects+=("README.md in $dir is $readme_bytes byte(s), under the ${readme_min_bytes}-byte floor -- looks like an empty or truncated copy")
  fi
fi

for field in "${REQUIRED_FIELDS[@]}"; do
  if ! jq -e --arg f "$field" 'has($f)' <<<"$manifest_json" >/dev/null; then
    defects+=("package.json is missing required field '$field'")
  fi
done

# README.md and package.json are deliberately left out of this set: they are
# already checked above with a defect message specific to what is wrong with
# each, and folding them in here would just print a second, vaguer line about
# the same missing file.
expected=()
for target in "${TARGETS[@]}"; do
  for f in "${SHARED_FILES[@]}"; do
    expected+=("$target/$f")
  done
done
for f in "${BUNDLER_ONLY_FILES[@]}"; do
  expected+=("bundler/$f")
done

# `LC_ALL=C` on both sides so the comparison and the `comm` diff below agree
# byte-for-byte regardless of the locale the caller's shell has set.
actual=$(cd "$dir" && find . -type f | sed 's|^\./||' | { grep -v -E '^(package\.json|README\.md)$' || true; } | LC_ALL=C sort -u)
expected_sorted=$(printf '%s\n' "${expected[@]}" | LC_ALL=C sort -u)

if [[ $actual != "$expected_sorted" ]]; then
  missing=$(LC_ALL=C comm -23 <(echo "$expected_sorted") <(echo "$actual"))
  added=$(LC_ALL=C comm -13 <(echo "$expected_sorted") <(echo "$actual"))
  if [[ -n $missing ]]; then
    defects+=("missing from $dir: $(echo "$missing" | paste -sd, -)")
  fi
  if [[ -n $added ]]; then
    defects+=("unexpected in $dir: $(echo "$added" | paste -sd, -)")
  fi
fi

if [[ ${#defects[@]} -gt 0 ]]; then
  echo "wasm-package-check: $dir is not publishable:" >&2
  for d in "${defects[@]}"; do
    echo "  - $d" >&2
  done
  exit 1
fi

echo "wasm-package-check: OK -- $dir is publishable"
