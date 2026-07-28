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

  const failures = [];
  const openedBy = new Map(manifest.cases.map((kase) => [kase.name, []]));
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

    let opened = 0;
    for (const kase of manifest.cases) {
      if (Object.hasOwn(reader.cannotOpen, kase.mode)) {
        outOfScope.push(`${reader.id} × ${kase.name} (${kase.mode}): ${reader.cannotOpen[kase.mode]}`);
        continue;
      }
      failures.push(...runCase(dir, reader.id, kase.name));
      openedBy.get(kase.name).push(reader.id);
      opened += 1;
    }

    if (opened === 0) {
      failures.push(
        `${reader.id}: opened no case at all, so it is not being tested; either the sample set ` +
          'lost the modes it reads or this reader should leave the support window',
      );
    }
  }

  // The failure mode a gate must not have is passing without reading anything,
  // and a per-reader mode exclusion is exactly how that creeps in.
  for (const [name, readerIds] of openedBy) {
    if (readerIds.length === 0) {
      failures.push(
        `${name}: no reader in the support window opened this case, so nothing is holding it to ` +
          'the wire format',
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
