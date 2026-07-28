//! The reporting logic, tested without a sample set or a published SDK in
//! reach. These are the paths that only ever run when the gate is already red,
//! which is exactly why they need holding down.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import test from 'node:test';

import {
  childFailures,
  describePlaintextMismatch,
  describePolicyMismatch,
  stderrTail,
} from '../src/failures.mjs';

/** Run a shell script the way `runCase` runs the case binary. */
function run(script) {
  try {
    const stdout = execFileSync('sh', ['-c', script], { encoding: 'utf8', stdio: 'pipe' });
    return { status: 0, signal: null, stdout, stderr: '' };
  } catch (e) {
    return {
      status: e.status ?? null,
      signal: e.signal ?? null,
      stdout: e.stdout ?? '',
      stderr: e.stderr ?? '',
    };
  }
}

test('an aborting case is reported rather than taking the run down', () => {
  const out = run("echo 'memory allocation of 21474836480 bytes failed' >&2; kill -ABRT $$");
  const failures = childFailures('@e4a/pg-wasm@0.6.1: mem', out);

  assert.equal(failures.length, 1, JSON.stringify(failures));
  assert.ok(
    failures[0].startsWith('@e4a/pg-wasm@0.6.1: mem: reader died on SIGABRT'),
    failures[0],
  );
  assert.ok(failures[0].endsWith('memory allocation of 21474836480 bytes failed'), failures[0]);
});

test('a case that reports failures passes them through', () => {
  const out = run("echo '@e4a/pg-js@2.3.3: stream/alice: unseal: bad'; echo; exit 1");
  assert.deepEqual(childFailures('@e4a/pg-js@2.3.3: stream', out), [
    '@e4a/pg-js@2.3.3: stream/alice: unseal: bad',
  ]);
});

test('a case that opens reports nothing', () => {
  assert.deepEqual(childFailures('@e4a/pg-wasm@0.6.1: mem', run('exit 0')), []);
});

test('a silent non-zero exit is still a failure', () => {
  assert.deepEqual(childFailures('@e4a/pg-wasm@0.6.1: mem', run('exit 2')), [
    '@e4a/pg-wasm@0.6.1: mem: reader exited with status 2 before it could report',
  ]);
});

test('the stderr tail skips stack frames and keeps the message', () => {
  const stderr = 'RangeError: Array buffer allocation failed\n    at wasm://wasm/000f1a2b\n';
  assert.equal(stderrTail(stderr), ': RangeError: Array buffer allocation failed');
});

test('a same-length mismatch names the first differing offset', () => {
  const message = describePlaintextMismatch(
    new TextEncoder().encode('abcXe'),
    new TextEncoder().encode('abcde'),
  );
  assert.match(message, /first difference at offset 3/);
  assert.match(message, /got 0x58, expected 0x64/);
});

test('a truncated plaintext says so', () => {
  const message = describePlaintextMismatch(
    new TextEncoder().encode('abc'),
    new TextEncoder().encode('abcde'),
  );
  assert.match(message, /recovered 3 bytes, expected 5/);
  assert.match(message, /prefix/);
});

test('an attribute with no value is not the same as one with an empty value', () => {
  const withValue = { ts: 1, con: [{ t: 'pbdf.sidn-pbdf.email.email', v: '' }] };
  const withoutValue = { ts: 1, con: [{ t: 'pbdf.sidn-pbdf.email.email' }] };
  assert.ok(describePolicyMismatch('public', withValue, withoutValue));
});

test('a policy that matches reports nothing', () => {
  const policy = { ts: 1704067200, con: [{ t: 'pbdf.sidn-pbdf.email.email', v: 'a@b.test' }] };
  assert.equal(describePolicyMismatch('public', policy, structuredClone(policy)), null);
});

test('a missing identity is described rather than compared away', () => {
  const message = describePolicyMismatch('private', null, { ts: 1, con: [] });
  assert.ok(message?.startsWith('private signing policy is null'), message);
});
