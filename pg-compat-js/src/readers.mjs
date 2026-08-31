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

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

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
    pgWasmReader({ version: '0.6.5', specifier: 'pg-wasm-0-6-5' }),
    pgJsReader({ version: '2.4.0', specifier: 'pg-js-2-4-0', surfacesUnsealResult: true }),
    pgJsReader({ version: '1.11.0', specifier: 'pg-js-1-11-0', surfacesUnsealResult: false }),
  ].map((reader) => ({ wireVersion: WIRE_VERSION, ...reader }));
}

/**
 * The package npm actually installed under a reader's alias.
 *
 * The `package` and `version` declared above and the `npm:` alias in
 * `package.json` that decides which code gets loaded are independent strings,
 * and adding a reader is documented as editing both places. A typo in either
 * makes the gate run one package or version while labelling every message with
 * another, which is a support window that is quietly wrong rather than a red
 * run. Both halves are returned because either one alone leaves the other open:
 * `npm:@e4a/pg-wasm@2.5.0` under a `pg-js-2-5-0` alias has the version the
 * entry declares and not the package. `test/manifest.test.mjs` compares them.
 *
 * Read off disk rather than imported: neither published package lists
 * `package.json` in its `exports`, so `import('<alias>/package.json')` is
 * `ERR_PACKAGE_PATH_NOT_EXPORTED`.
 *
 * @param {string} specifier the npm alias the reader is installed under
 * @returns {Promise<{name: string, version: string}>} as the installed
 *   `package.json` gives them
 */
export async function installedPackage(specifier) {
  const path = fileURLToPath(
    new URL(`../node_modules/${specifier}/package.json`, import.meta.url),
  );
  const { name, version } = JSON.parse(await readFile(path, 'utf8'));
  return { name, version };
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
