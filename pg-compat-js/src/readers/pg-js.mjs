//! A published `@e4a/pg-js` as a reader.
//!
//! Where the `pg-wasm` reader calls the unsealers directly, this one goes in
//! through `PostGuard#open`, the entry point every consumer in the field
//! actually uses. That covers more than the container parse: the header policy
//! map turned into a recipient list, the USK fetched for the chosen recipient,
//! the sender identity handed to the UI.
//!
//! It only sees stream-mode containers. `pg-js` decrypts through
//! `StreamUnsealer` in both of its input modes, so a memory-mode container
//! comes back as `mode is not supported: InMemory { size: N }` — a typed
//! refusal, not a wire break, and `pg-js` never writes one either (`toBytes()`
//! seals with `sealStream`). The memory-mode cases are the `pg-wasm` reader's.

import { startPkgStub } from './pkg-stub.mjs';

const MEMORY_UNSUPPORTED =
  'pg-js decrypts through StreamUnsealer in both input modes, so it neither reads nor writes a ' +
  'memory-mode container; @e4a/pg-wasm covers those cases';

/**
 * @param {{version: string, specifier: string, surfacesUnsealResult: boolean}} pin
 *   `version` as published on npm; `specifier` the npm alias it is installed
 *   under. `surfacesUnsealResult` is false for the 1.x line, which throws away
 *   what `StreamUnsealer.unseal()` returns and reports `public_identity()`
 *   instead: the header policy, unwrapped, and never the private signing
 *   policy. 2.x keeps the unseal result. Pinning that difference here rather
 *   than hiding it means a 1.x reader that suddenly does report a private
 *   policy shows up as a mismatch instead of passing quietly.
 * @returns {object} a reader (see `../readers.mjs` for the contract)
 */
export function pgJsReader({ version, specifier, surfacesUnsealResult }) {
  return {
    id: `@e4a/pg-js@${version}`,
    package: '@e4a/pg-js',
    version,
    specifier,
    cannotOpen: { memory: MEMORY_UNSUPPORTED },
    privateSignatureVisible: surfacesUnsealResult,

    async load({ verifyingKey, usks }) {
      const { PostGuard } = await import(specifier);
      const pkg = await startPkgStub({ verifyingKey, usks });
      // Keep startPkgStub last: verify.mjs returns early when load() throws and
      // never calls unload(), so anything fallible after this line leaks a
      // running server. The stub is unref'd so that leak cannot hang the child,
      // but it would still serve a case that should have failed cleanly.
      return { PostGuard, pkg };
    },

    async unload({ pkg }) {
      await pkg.close();
    },

    async open({ PostGuard, pkg }, { mode, ciphertext, recipientId }) {
      if (mode !== 'stream') throw new Error(MEMORY_UNSUPPORTED);

      const postguard = new PostGuard({ pkgUrl: pkg.url });
      const opened = postguard.open({ data: ciphertext });

      // inspect() before decrypt() is the documented consumer pattern (show
      // the recipient list, then decrypt for one of them) and it is the SDK
      // call that reads the multi-recipient header on its own.
      const { recipients } = await opened.inspect();

      // Where a browser consumer passes `element` and scans a QR code, the gate
      // passes a session callback: it hands the PKG stub the recipient id in
      // place of the Yivi JWT a deployment would send. Everything after this
      // point is the SDK's own decrypt path.
      const { plaintext, sender } = await opened.decrypt({
        recipient: recipientId,
        session: async () => recipientId,
      });

      return { plaintext, identity: normaliseIdentity(sender, surfacesUnsealResult), recipients };
    },
  };
}

/**
 * `pg-js` reports the sender as a parsed convenience object with the reader's
 * own view under `raw`. In 2.x that is the unseal result (`{public, private?}`);
 * in 1.x it is the bare header policy, so wrap it to the same shape.
 */
function normaliseIdentity(sender, surfacesUnsealResult) {
  if (!sender?.raw) return null;
  return surfacesUnsealResult ? sender.raw : { public: sender.raw };
}
