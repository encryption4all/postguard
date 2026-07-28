//! Turning a finished case process into failure messages.
//!
//! Pure functions, kept apart from the readers so the interesting parts — what
//! a dead child means, what a corrupted plaintext looks like — are unit-tested
//! without a sample set or a published SDK in reach.

/**
 * Interpret a finished `pg-compat-case` run.
 *
 * A child that exits non-zero with nothing on stdout never got as far as
 * reporting. In the Rust half that is a published reader aborting on a garbage
 * length prefix; here it is the wasm reader's `RangeError`-then-abort on the
 * same bytes, or the Node heap going over. Either way: say so, name the case,
 * and let the run carry on with the other cases.
 *
 * @param {string} label `<reader>: <case>`, used when the child said nothing
 * @param {{status: number|null, signal: string|null, stdout: string, stderr: string}} result
 * @returns {string[]} one message per failure, empty when the case opened
 */
export function childFailures(label, result) {
  if (result.status === 0) return [];

  const reported = result.stdout
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line !== '');
  if (reported.length > 0) return reported;

  return [`${label}: reader ${exitDescription(result)} before it could report${stderrTail(result.stderr)}`];
}

/**
 * How the child ended, in the wording the Rust half uses so the two gates read
 * the same in a CI log.
 *
 * @param {{status: number|null, signal: string|null}} result
 * @returns {string}
 */
export function exitDescription(result) {
  if (result.signal) return `died on ${result.signal}`;
  if (typeof result.status === 'number') return `exited with status ${result.status}`;
  return 'exited abnormally';
}

/**
 * The first line of the child's stderr that says something, which for a wasm
 * reader out of memory is the allocation message and for a thrown error is the
 * error.
 *
 * Noise is dropped rather than kept: stack frames point into generated wasm
 * glue, and Node's crash dump ends with a `Node.js v22.x` banner after the
 * `node:events:NN` / `throw er;` / `^` preamble. Taking the LAST surviving line
 * surfaced that banner and dropped the actual error — on exactly the run where
 * this message matters most, a child that died before it could report (a failed
 * top-level import from a partial `npm ci`, an unhandled rejection at :84).
 *
 * @param {string} stderr
 * @returns {string}
 */
export function stderrTail(stderr) {
  const noise = /^(at |Node\.js v|node:|throw |\^+$)/;
  const first = stderr
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !noise.test(line))
    .at(0);

  return first === undefined ? '' : `: ${first}`;
}

/**
 * Describe a plaintext mismatch.
 *
 * Lengths alone are not enough. A wire change that alters the key schedule or
 * the nonce derivation corrupts the content while preserving its length, and
 * that payload-level break is exactly what the multi-segment case exists to
 * catch. This message is only ever printed when the gate is already red, so it
 * is the one place that has to carry information.
 *
 * @param {Uint8Array} got
 * @param {Uint8Array} want
 * @returns {string}
 */
export function describePlaintextMismatch(got, want) {
  const shared = Math.min(got.length, want.length);
  for (let i = 0; i < shared; i++) {
    if (got[i] !== want[i]) {
      return (
        `recovered ${got.length} bytes, expected ${want.length}; first difference at offset ${i} ` +
        `(got ${hex(got[i])}, expected ${hex(want[i])})`
      );
    }
  }

  return (
    `recovered ${got.length} bytes, expected ${want.length}; the shorter is a prefix of the longer`
  );
}

function hex(byte) {
  return `0x${byte.toString(16).padStart(2, '0')}`;
}

/**
 * A policy as a comparable string: fixed key order, and a missing attribute
 * value distinguished from an empty one.
 *
 * @param {{ts: number, con: Array<{t: string, v?: string}>}} policy
 * @returns {string}
 */
export function describePolicy(policy) {
  if (policy === null || typeof policy !== 'object') return JSON.stringify(policy ?? null);

  const con = (policy.con ?? []).map(({ t, v }) => ({ t, v: v ?? null }));
  return JSON.stringify({ ts: policy.ts, con });
}

/**
 * Compare a policy a reader recovered against the one the manifest says was
 * signed. Bytes matching is not enough on its own: a header change that shifts
 * the policy region can leave the payload intact, and the signed identity is
 * what a recipient actually acts on.
 *
 * @param {string} what `"public"` or `"private"`
 * @param {object} got
 * @param {object} want
 * @returns {string|null} a message, or null when they match
 */
export function describePolicyMismatch(what, got, want) {
  const gotText = describePolicy(got);
  const wantText = describePolicy(want);
  if (gotText === wantText) return null;

  return `${what} signing policy is ${gotText}, manifest says ${wantText}`;
}
