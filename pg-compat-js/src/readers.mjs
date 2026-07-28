//! The support window as readers.
//!
//! This list and the `Reader list` section of `COMPATIBILITY.md` are meant to
//! be the same list: the highest published patch of every npm line in the
//! window. A gate that needs a different set of readers changes that file
//! first.
//!
//! Adding a version is three lines: an `npm:` alias in `package.json` (an
//! alias, because several versions of one package have to coexist in one
//! `node_modules`), an entry here, and `npm install` to move the lockfile.
//!
//! ## The reader contract
//!
//! ```text
//! id                       `<package>@<version>`, used in failure messages
//! package, version         as published on npm
//! specifier                the npm alias it is installed under
//! wireVersion              the container version this reader speaks
//! cannotOpen               mode -> why this reader cannot open it
//! privateSignatureVisible  does it surface the private signing policy at all
//! load(artifacts)          prepare once per case process -> handle
//! unload(handle)           release whatever load() started (optional)
//! open(handle, case)       -> {plaintext, identity, recipients}
//! ```

import { WIRE_VERSION } from './manifest.mjs';
import { pgJsReader } from './readers/pg-js.mjs';
import { pgWasmReader } from './readers/pg-wasm.mjs';

/**
 * Every published reader in the support window.
 *
 * `wireVersion` is declared rather than read from the package: unlike the Rust
 * half, which imports the published crate's own `VERSION_V3`, nothing on the JS
 * side exports the constant. Bump it here for a reader that speaks a different
 * container version, so the mismatch is reported once per reader instead of as
 * an unreadable container per case.
 *
 * @returns {object[]}
 */
export function readers() {
  return [
    pgWasmReader({ version: '0.6.1', specifier: 'pg-wasm-0-6-1' }),
    pgJsReader({ version: '2.3.3', specifier: 'pg-js-2-3-3', surfacesUnsealResult: true }),
    pgJsReader({ version: '1.11.0', specifier: 'pg-js-1-11-0', surfacesUnsealResult: false }),
  ].map((reader) => ({ wireVersion: WIRE_VERSION, ...reader }));
}

/**
 * The reader with this id, or an error naming the ones there are.
 *
 * @param {string} id `<package>@<version>`
 * @returns {object}
 */
export function reader(id) {
  const all = readers();
  const found = all.find((r) => r.id === id);
  if (!found) {
    throw new Error(
      `no reader configured for ${id}; the support window holds ${all.map((r) => r.id).join(', ')}`,
    );
  }
  return found;
}
