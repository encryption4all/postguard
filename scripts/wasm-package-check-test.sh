#!/usr/bin/env bash
#
# Regression tests for scripts/wasm-package-check.sh, covering the exit-code
# contract: 1 means a real defect, 2 means the script could not find out.
# Conflating them is the failure this pins -- see the header of
# wasm-package-check.sh for why.
#
# Entirely offline: every fixture is built in a temp dir, either from a
# complete synthetic package or from scripts/testdata/pg-wasm-0.6.6/'s
# committed metadata for the real, immutable, known-bad release. No wasm
# build, no network, no registry.
#
# Usage:
#   scripts/wasm-package-check-test.sh
#
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

gate="$root/scripts/wasm-package-check.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0

# A complete, publishable fixture: both wasm-pack targets, a README past the
# length floor, and a manifest carrying every required field. Every mutation
# test below starts from a fresh copy of this so one test's edit cannot leak
# into the next.
make_complete_fixture() {
  local dir=$1
  mkdir -p "$dir/bundler" "$dir/web"
  for f in index.js index.d.ts index_bg.wasm index_bg.wasm.d.ts LICENSE.md; do
    : >"$dir/bundler/$f"
    : >"$dir/web/$f"
  done
  : >"$dir/bundler/index_bg.js"
  cat >"$dir/README.md" <<'EOF'
## pg-wasm

A fixture README, used only by wasm-package-check-test.sh, well past the
40-byte length floor the real checker enforces.
EOF
  cat >"$dir/package.json" <<'EOF'
{
  "name": "@e4a/pg-wasm",
  "version": "0.0.0",
  "description": "PostGuard WebAssembly bindings for the browser",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/encryption4all/postguard.git",
    "directory": "pg-wasm"
  },
  "homepage": "https://github.com/encryption4all/postguard/tree/main/pg-wasm#readme",
  "exports": {
    ".": { "types": "./bundler/index.d.ts", "import": "./bundler/index.js" },
    "./web": { "types": "./web/index.d.ts", "import": "./web/index.js" }
  },
  "main": "./bundler/index.js",
  "types": "./bundler/index.d.ts"
}
EOF
}

# Runs the gate on <dir> and asserts its exit code, and optionally that its
# combined output mentions `$needle`.
expect() {
  local want=$1 desc=$2 dir=$3 needle=${4:-}
  local got out
  set +e
  out=$("$gate" "$dir" 2>&1)
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

# --- known-good: a complete fixture is publishable ---------------------------
good="$tmp/good"
make_complete_fixture "$good"
expect 0 "a complete fixture is publishable" "$good"

# --- real defect: README.md absent -------------------------------------------
no_readme="$tmp/no-readme"
make_complete_fixture "$no_readme"
rm "$no_readme/README.md"
expect 1 "README.md removed" "$no_readme" "README.md"

# --- real defect: README.md present but empty --------------------------------
empty_readme="$tmp/empty-readme"
make_complete_fixture "$empty_readme"
: >"$empty_readme/README.md"
expect 1 "README.md truncated to zero bytes" "$empty_readme" "README.md"

# --- real defect: manifest missing a required field ---------------------------
no_repo="$tmp/no-repository"
make_complete_fixture "$no_repo"
jq 'del(.repository)' "$no_repo/package.json" >"$no_repo/package.json.new"
mv "$no_repo/package.json.new" "$no_repo/package.json"
expect 1 "package.json missing 'repository'" "$no_repo" "repository"

# --- real defect: a stray file that has no business in the tarball -----------
stray="$tmp/stray-file"
make_complete_fixture "$stray"
echo "not part of the package" >"$stray/notes.txt"
expect 1 "an extra stray file appears in the directory" "$stray" "notes.txt"

# --- real defect: a build artifact missing -------------------------------------
no_wasm="$tmp/no-wasm"
make_complete_fixture "$no_wasm"
rm "$no_wasm/bundler/index_bg.wasm"
expect 1 "bundler/index_bg.wasm missing" "$no_wasm" "index_bg.wasm"

# --- undetermined: the directory does not exist -------------------------------
expect 2 "a nonexistent path is undetermined, not a pass" "$tmp/does-not-exist"

# --- undetermined: the directory exists but is empty --------------------------
empty_dir="$tmp/empty-dir"
mkdir -p "$empty_dir"
expect 2 "an empty directory is undetermined, not a pass" "$empty_dir"

# --- undetermined: package.json does not parse --------------------------------
bad_json="$tmp/bad-json"
make_complete_fixture "$bad_json"
printf '{ not json' >"$bad_json/package.json"
expect 2 "a package.json that does not parse is undetermined, not a real defect" "$bad_json" "does not parse"

# --- undetermined: no argument -------------------------------------------------
out=$("$gate" 2>&1) && got=0 || got=$?
if [[ $got -eq 2 && $out == *usage* ]]; then
  echo "ok: no arguments is undetermined, not a pass (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: no arguments -- wanted exit 2 with a usage message, got $got: $out"
  fail=$((fail + 1))
fi

# --- missing tool: 127, distinct from both 1 and 2 -----------------------------
#
# A `PATH` with no `jq` on it, rather than uninstalling anything -- same
# isolation idea as the stubs in ruleset-drift-test.sh and
# semver-checks-test.sh, pointed the other way: this hides a real tool instead
# of faking one. Only `bash` needs to resolve: the gate's `#!/usr/bin/env
# bash` shebang looks it up via `PATH`, and the tool check that reports 127 is
# the first thing the gate does, before anything else it calls could be
# reached.
stub_path=$(mktemp -d)
ln -s "$(command -v bash)" "$stub_path/bash"
good_for_tool_check="$tmp/good-for-tool-check"
make_complete_fixture "$good_for_tool_check"
set +e
out=$(PATH="$stub_path" "$gate" "$good_for_tool_check" 2>&1)
got=$?
set -e
rm -rf "$stub_path"
if [[ $got -eq 127 && $out == *jq* ]]; then
  echo "ok: a missing required tool is reported distinctly, not as 1 or 2 (exit $got)"
  pass=$((pass + 1))
else
  echo "FAIL: missing jq -- wanted exit 127 naming jq, got $got: $out"
  fail=$((fail + 1))
fi

# --- known-bad: the real, immutable 0.6.6 release --------------------------
#
# scripts/testdata/pg-wasm-0.6.6/ pins the actual files.txt and package.json
# of the package npm has served since #427 was filed -- no README.md in the
# tarball, no `homepage` in the manifest. Built here rather than checked
# straight from testdata/, because the fixture directory also carries its own
# README.md *about* the fixture (see testdata/pg-wasm-0.6.6/README.md), which
# must not be mistaken for the package's own missing one.
published="$tmp/pg-wasm-0.6.6"
fixture="$root/scripts/testdata/pg-wasm-0.6.6"
mkdir -p "$published/bundler" "$published/web"
while IFS= read -r f; do
  [[ -z $f ]] && continue
  : >"$published/$f"
done <"$fixture/files.txt"
cp "$fixture/package.json" "$published/package.json"
expect 1 "the real, published pg-wasm 0.6.6 tarball has no README.md" "$published" "README.md"

echo
echo "wasm-package-check-test: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
