//! The gate: HEAD-sealed bytes must open with every published JS reader in the
//! support window.
//!
//! ```text
//! cargo run -p pg-core --features stream --example seal-samples -- target/wire-compat/artifacts
//! PG_COMPAT_ARTIFACTS=$PWD/target/wire-compat/artifacts npm --prefix pg-compat-js test
//! ```

import assert from 'node:assert/strict';
import test from 'node:test';

import { artifactsDir, readManifest } from '../src/manifest.mjs';
import { readers } from '../src/readers.mjs';
import { runCase } from '../src/run-case.mjs';

test('published JS readers open the HEAD-sealed sample set', async () => {
  const dir = artifactsDir();
  const manifest = await readManifest(dir);

  const window = readers();
  assert.ok(window.length > 0, 'no published readers configured');

  // Pin WHICH cases must be present, not just that some are. The coverage
  // invariants below are computed from the manifest, so a sealer that silently
  // stopped emitting the memory-mode cases would keep them satisfied: every
  // remaining case still has a reader, and pg-wasm still has cases in scope
  // from the stream ones. Both halves would go green having lost the only
  // coverage memory mode has (pg-js is stream-only in both directions).
  assert.deepEqual(
    manifest.cases.map((kase) => kase.name).sort(),
    ['mem', 'mem-privsig', 'stream', 'stream-multi-segment', 'stream-privsig'],
    'the sealed case set changed; update this list deliberately and check the ' +
      'readers still cover the new shape',
  );

  const failures = [];
  // Two different questions: which readers got the case open (the summary at the
  // end), and how many were pointed at it at all (the coverage invariant below).
  // A reader that tried and failed answers the second, not the first.
  const openedBy = new Map(manifest.cases.map((kase) => [kase.name, []]));
  const readersFor = new Map(manifest.cases.map((kase) => [kase.name, 0]));
  const outOfScope = [];

  for (const reader of window) {
    if (manifest.wireVersion !== reader.wireVersion) {
      // Every case would fail the same way; say it once.
      failures.push(
        `${reader.id}: sample set claims wire version ${manifest.wireVersion}, this reader speaks ` +
          `${reader.wireVersion}`,
      );
      continue;
    }

    let inScope = 0;
    for (const kase of manifest.cases) {
      if (Object.hasOwn(reader.cannotOpen, kase.mode)) {
        outOfScope.push(`${reader.id} × ${kase.name} (${kase.mode}): ${reader.cannotOpen[kase.mode]}`);
        continue;
      }

      const caseFailures = runCase(dir, reader.id, kase.name);
      failures.push(...caseFailures);
      if (caseFailures.length === 0) openedBy.get(kase.name).push(reader.id);
      readersFor.set(kase.name, readersFor.get(kase.name) + 1);
      inScope += 1;
    }

    if (inScope === 0) {
      failures.push(
        `${reader.id}: every case in the set is out of scope for it, so it is not being tested; ` +
          'either the sample set lost the modes it reads or this reader should leave the support ' +
          'window',
      );
    }
  }

  // The failure mode a gate must not have is passing without reading anything,
  // and a per-reader mode exclusion is exactly how that creeps in.
  for (const [name, count] of readersFor) {
    if (count === 0) {
      failures.push(
        `${name}: no reader in the support window reads this case at all, so nothing is holding ` +
          'it to the wire format',
      );
    }
  }

  assert.ok(
    failures.length === 0,
    'HEAD-sealed containers do not open with published pg-wasm/pg-js:\n  ' +
      `${failures.join('\n  ')}\n\nA wire change that old readers cannot follow is not additive: ` +
      'make it additive, or roll readers out before writers.',
  );

  for (const line of outOfScope) console.log(`not covered — ${line}`);
  for (const [name, readerIds] of openedBy) console.log(`${name}: opened by ${readerIds.join(', ')}`);
});
