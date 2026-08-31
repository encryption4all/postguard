//! Does the gate actually go red?
//!
//! `wire-compat.test.mjs` only ever asserts that a good sample set opens, which
//! is an assertion a broken harness also satisfies. These tests hand the same
//! readers a deliberately damaged copy of the set and require a failure naming
//! the case. Damaging a byte is not the same thing as a wire change, but it goes
//! through the same reporting path, so a harness that has stopped reading shows
//! up here rather than the next time someone touches `Header`.

import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { artifactsDir, readManifest } from '../src/manifest.mjs';
import { runCase } from '../src/run-case.mjs';

const WASM_READER = '@e4a/pg-wasm@0.6.5';

/** A throwaway copy of the sample set, for `damage` to break. */
async function withDamagedSet(damage, body) {
  const source = artifactsDir();
  await readManifest(source); // fail with the "seal one first" message, not ENOENT
  const dir = await mkdtemp(join(tmpdir(), 'pg-compat-js-damaged-'));
  try {
    await cp(source, dir, { recursive: true });
    await damage(dir);
    await body(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('a flipped byte in the payload is reported, not recovered', async () => {
  await withDamagedSet(
    async (dir) => {
      const path = join(dir, 'stream.bin');
      const bytes = await readFile(path);
      // The last byte is inside the final segment's authentication tag, so this
      // is the payload-level break the gate exists to notice.
      bytes[bytes.length - 1] ^= 0xff;
      await writeFile(path, bytes);
    },
    (dir) => {
      const failures = runCase(dir, WASM_READER, 'stream');
      assert.ok(failures.length > 0, 'a corrupted payload was reported as opening cleanly');
      assert.ok(
        failures.every((f) => f.includes('stream')),
        JSON.stringify(failures),
      );
    },
  );
});

test('a truncated container is reported, not read as a shorter one', async () => {
  await withDamagedSet(
    async (dir) => {
      const path = join(dir, 'mem.bin');
      const bytes = await readFile(path);
      await writeFile(path, bytes.subarray(0, bytes.length - 32));
    },
    (dir) => {
      const failures = runCase(dir, WASM_READER, 'mem');
      assert.ok(failures.length > 0, 'a truncated container was reported as opening cleanly');
    },
  );
});

test('a case file the set does not have names the file, not Node', async () => {
  await withDamagedSet(
    (dir) => unlink(join(dir, 'stream.bin')),
    (dir) => {
      const failures = runCase(dir, WASM_READER, 'stream');
      // The reachable version of this is a partial artifact download in CI, or a
      // manifest naming a file the sealer did not write. Read through the child's
      // stdout it is an ENOENT and a path; left to Node's default handler the
      // child says nothing on stdout and the last line of its stack dump, which
      // is all the parent can salvage, is `Node.js v22.x`.
      assert.equal(failures.length, 1, JSON.stringify(failures));
      assert.match(failures[0], /stream\.bin/);
      assert.doesNotMatch(failures[0], /before it could report/);
    },
  );
});

test('a bumped wire version is reported once, before any ciphertext is opened', async () => {
  await withDamagedSet(
    async (dir) => {
      const path = join(dir, 'manifest.json');
      const manifest = JSON.parse(await readFile(path, 'utf8'));
      manifest.wireVersion += 1;
      await writeFile(path, JSON.stringify(manifest));
    },
    (dir) => {
      const failures = runCase(dir, WASM_READER, 'mem');
      assert.deepEqual(failures, [
        `${WASM_READER}: sample set claims wire version 3, this reader speaks 2`,
      ]);
    },
  );
});

test('a manifest promising the raw sender value is reported, not opened cleanly', async () => {
  // `sample_set.rs` hands the sealer this value and the manifest promises
  // `canonicalize` of it, so writing it back into the manifest is what a sealer
  // that stopped canonicalizing on its way to the wire would have produced.
  const RAW_SENDER = ' Sender@Sample.TEST ';

  await withDamagedSet(
    async (dir) => {
      const path = join(dir, 'manifest.json');
      const manifest = JSON.parse(await readFile(path, 'utf8'));
      assert.equal(typeof manifest.sender.public.con[0].v, 'string');
      manifest.sender.public.con[0].v = RAW_SENDER;
      await writeFile(path, JSON.stringify(manifest));
    },
    (dir) => {
      const failures = runCase(dir, WASM_READER, 'mem');
      assert.ok(failures.length > 0, 'a mismatched sender policy was reported as opening cleanly');
      assert.ok(
        failures.every((f) => f.includes('public signing policy is')),
        JSON.stringify(failures),
      );
      // One per recipient, each naming which one it was.
      assert.ok(
        failures.some((f) => f.includes('mem/alice')),
        JSON.stringify(failures),
      );
      assert.ok(
        failures.some((f) => f.includes('mem/bob')),
        JSON.stringify(failures),
      );
    },
  );
});

test('a manifest promising the wrong private sender value is reported', async () => {
  // The sealer canonicalizes the two sender policies in separate statements
  // (`canonical_signing_key` and `with_priv_signing_key`), so a tooth on the
  // public one leaves the private one as unguarded as no tooth at all. This is
  // also the only path that reaches the `privateSignatureVisible` branch in
  // `verify.mjs`, which the wasm reader is alone in taking.
  const RAW_MOBILE = '+31 (0)6 1234 5678';
  const MOBILE_TYPE = 'pbdf.sidn-pbdf.mobilenumber.mobilenumber';

  await withDamagedSet(
    async (dir) => {
      const path = join(dir, 'manifest.json');
      const manifest = JSON.parse(await readFile(path, 'utf8'));
      const attribute = manifest.sender.private.con.find((a) => a.t === MOBILE_TYPE);
      assert.ok(attribute, 'sender.private carries no mobile number to rewrite');
      attribute.v = RAW_MOBILE;
      await writeFile(path, JSON.stringify(manifest));
    },
    (dir) => {
      const failures = runCase(dir, WASM_READER, 'mem-privsig');
      assert.ok(
        failures.length > 0,
        'a mismatched private sender policy was reported as opening cleanly',
      );
      assert.ok(
        failures.every((f) => f.includes('private signing policy is')),
        JSON.stringify(failures),
      );
      // One per recipient, each naming which one it was.
      assert.ok(
        failures.some((f) => f.includes('mem-privsig/alice')),
        JSON.stringify(failures),
      );
      assert.ok(
        failures.some((f) => f.includes('mem-privsig/bob')),
        JSON.stringify(failures),
      );
    },
  );
});
