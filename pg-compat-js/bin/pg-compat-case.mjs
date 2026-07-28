#!/usr/bin/env node
//! Opens one case of the sample set with one published JS reader.
//!
//! ```text
//! node bin/pg-compat-case.mjs <artifacts-dir> <reader-id> <case-name>
//! ```
//!
//! Prints one line per failure and exits 1; exits 0 when the case opens. The
//! gate (`test/wire-compat.test.mjs`) runs one of these per reader and case, for
//! the same reason the Rust half does: a reader handed a shifted header can read
//! a garbage length prefix and try to allocate gigabytes, which takes the whole
//! process down rather than returning an error. One process per case means one
//! dead reader costs its own case and the run still reports the others.

import { findCase, readManifest } from '../src/manifest.mjs';
import { reader } from '../src/readers.mjs';
import { verifyCase } from '../src/verify.mjs';

const USAGE = 'usage: pg-compat-case <artifacts-dir> <reader-id> <case-name>';

const [dir, readerId, caseName, ...rest] = process.argv.slice(2);
if (!dir || !readerId || !caseName || rest.length > 0) {
  process.stderr.write(`${USAGE}\n`);
  process.exit(2);
}

let selected;
let manifest;
let kase;
try {
  selected = reader(readerId);
  manifest = await readManifest(dir);
  kase = findCase(manifest, caseName);
} catch (e) {
  process.stderr.write(`${e.message}\n`);
  process.exit(2);
}

// The gate checks this once per reader before it spawns anything, so this is
// for hand-runs. Without it a container version bump reaches the reader as
// shifted bytes, which is the allocation abort rather than a message.
if (manifest.wireVersion !== selected.wireVersion) {
  process.stdout.write(
    `${selected.id}: sample set claims wire version ${manifest.wireVersion}, this reader speaks ` +
      `${selected.wireVersion}\n`,
  );
  process.exit(1);
}

if (Object.hasOwn(selected.cannotOpen, kase.mode)) {
  process.stderr.write(
    `${selected.id} cannot open a ${kase.mode}-mode case: ${selected.cannotOpen[kase.mode]}\n`,
  );
  process.exit(2);
}

const failures = await verifyCase(selected, dir, manifest, kase);
for (const failure of failures) process.stdout.write(`${failure}\n`);
process.exit(failures.length === 0 ? 0 : 1);
