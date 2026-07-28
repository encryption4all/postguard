//! Refusing a sample set this reader does not understand.
//!
//! The worst outcome for a gate is not a red run, it is a green one that read
//! nothing. Every check here is a way that could happen.

import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { SUPPORTED_SCHEMA_VERSION, readManifest } from '../src/manifest.mjs';
import { installedVersion, reader, readers } from '../src/readers.mjs';
import { declaredNpmReaders, parseNpmReaders } from '../src/support-window.mjs';

/** A directory holding just a `manifest.json`. */
async function withManifest(manifest, body) {
  const dir = await mkdtemp(join(tmpdir(), 'pg-compat-js-'));
  try {
    await writeFile(join(dir, 'manifest.json'), JSON.stringify(manifest));
    await body(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('a newer schema version is refused rather than skipped', async () => {
  await withManifest({ schemaVersion: SUPPORTED_SCHEMA_VERSION + 1, cases: [{ name: 'mem' }] }, async (dir) => {
    await assert.rejects(readManifest(dir), /is not the 1 this reader understands/);
  });
});

test('a set with no cases is refused', async () => {
  await withManifest({ schemaVersion: SUPPORTED_SCHEMA_VERSION, cases: [] }, async (dir) => {
    await assert.rejects(readManifest(dir), /would pass without reading anything/);
  });
});

test('a missing set says how to seal one', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'pg-compat-js-'));
  try {
    await assert.rejects(readManifest(dir), /--example seal-samples/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('the support window is the npm reader list in COMPATIBILITY.md', async () => {
  // Read out of the document, not repeated here: a literal in this file would
  // only detect changes to `readers.mjs`, and the drift that matters runs the
  // other way — the window grows in the document that decides it while the gate
  // goes on testing the set it always tested.
  assert.deepEqual(
    readers()
      .map((r) => r.id)
      .sort(),
    (await declaredNpmReaders()).sort(),
    'src/readers.mjs and the reader list in COMPATIBILITY.md have drifted; the document decides',
  );
});

test('a document with nothing to compare against is an error, not an empty list', () => {
  assert.throws(() => parseNpmReaders('## Reader list\n\nprose, no block\n'), /no reader-list block/);
  assert.throws(
    () => parseNpmReaders('```\n# <registry> <package> <versions...>\ncrates.io pg-core 0.6.1\n```\n'),
    /holds no npm row/,
  );
  assert.throws(
    () => parseNpmReaders('```\n# <registry> <package> <versions...>\nnpm @e4a/pg-js\n```\n'),
    /lists no version/,
  );
});

test('every reader is labelled with the version npm installed for it', async () => {
  for (const r of readers()) {
    assert.equal(
      await installedVersion(r.specifier),
      r.version,
      `${r.id} loads the alias ${r.specifier}, which npm resolved to another version`,
    );
  }
});

test('an unknown reader id names the ones there are', () => {
  assert.throws(() => reader('@e4a/pg-js@9.9.9'), /the support window holds @e4a\/pg-wasm@0\.6\.1/);
});
