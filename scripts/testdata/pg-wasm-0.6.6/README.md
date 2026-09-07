# pg-wasm 0.6.6 published package fixture

Real metadata from the `@e4a/pg-wasm@0.6.6` package as published on npm,
fetched 2026-09-04 for issue #427:

- `package.json`: `https://registry.npmjs.org/@e4a/pg-wasm/0.6.6`, verbatim
  (the registry's own added fields such as `_id` and `dist` stripped, since
  those never reach a package installed from the tarball).
- `files.txt`: `tar -tzf` on the published tarball
  (`https://registry.npmjs.org/@e4a/pg-wasm/-/pg-wasm-0.6.6.tgz`), with the
  `package/` tar root and `package.json` itself dropped -- the manifest is
  committed above instead.

This is a permanent known-bad fixture for
`scripts/wasm-package-check-test.sh`: this exact, immutable release shipped
with no `README.md` in its tarball and no `homepage` field in its manifest,
which is the defect issue #427 exists to catch. Because a released npm
tarball never changes, `wasm-package-check.sh` reporting exit 1 against a
directory built from these two files is a fact that cannot go stale --
unlike a fixture built from the current working tree, which a later, correct
change would turn from a known-bad case into a false failure.

Not fetched at test time: that would make the offline suite need the
network. This directory is read by the test script, which builds a temp
directory from it (touching empty placeholder files for every entry in
`files.txt`, copying `package.json` verbatim, and deliberately not creating a
`README.md`) and runs the checker against that.
