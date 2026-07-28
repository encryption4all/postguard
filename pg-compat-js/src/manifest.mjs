//! Reading the sample set the Rust half seals.
//!
//! The layout is documented in `pg-compat/README.md` and is a contract between
//! the sealer, `pg-compat` and this package. Keep the checks here as strict as
//! the Rust ones: a gate that reads nothing and passes is worse than no gate.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

/** Manifest layout this reader understands. A newer set is an error, not a skip. */
export const SUPPORTED_SCHEMA_VERSION = 1;

/** Environment variable naming the directory holding the sample set. */
export const ARTIFACTS_ENV = 'PG_COMPAT_ARTIFACTS';

/** The container version the readers in the support window speak (`VERSION_V3`). */
export const WIRE_VERSION = 2;

/**
 * Locate the sample set: `$PG_COMPAT_ARTIFACTS`, or the directory the sealer
 * writes to by default. Same default as `pg-compat`, so a set sealed for one
 * half is opened by the other without re-sealing.
 *
 * @returns {string} absolute path to the artifact directory
 */
export function artifactsDir() {
  const fromEnv = process.env[ARTIFACTS_ENV];
  if (fromEnv) return fromEnv;

  return fileURLToPath(new URL('../../target/wire-compat/artifacts', import.meta.url));
}

/**
 * Read a file named by the manifest.
 *
 * @param {string} dir artifact directory
 * @param {string} name file name from the manifest
 * @returns {Promise<Uint8Array>}
 */
export async function readArtifact(dir, name) {
  return new Uint8Array(await readFile(`${dir}/${name}`));
}

/**
 * Read `manifest.json`, refusing a layout this reader does not understand.
 *
 * @param {string} dir artifact directory
 * @returns {Promise<object>} the parsed manifest
 */
export async function readManifest(dir) {
  const path = `${dir}/manifest.json`;
  let raw;
  try {
    raw = await readFile(path, 'utf8');
  } catch (e) {
    throw new Error(
      `read ${path}: ${e.message}\nSeal the sample set first:\n  cargo run -p pg-core ` +
        `--features stream --example seal-samples -- ${dir}\nor point ${ARTIFACTS_ENV} at an ` +
        'existing set.',
      { cause: e },
    );
  }

  const manifest = JSON.parse(raw);

  if (manifest.schemaVersion !== SUPPORTED_SCHEMA_VERSION) {
    throw new Error(
      `artifact schema version ${manifest.schemaVersion} is not the ` +
        `${SUPPORTED_SCHEMA_VERSION} this reader understands — update pg-compat-js alongside ` +
        'the sealer',
    );
  }
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) {
    throw new Error('the sample set lists no cases; the gate would pass without reading anything');
  }

  return manifest;
}

/**
 * The case with this name, or an error naming what the set does hold.
 *
 * @param {object} manifest
 * @param {string} name
 * @returns {object}
 */
export function findCase(manifest, name) {
  const found = manifest.cases.find((c) => c.name === name);
  if (!found) {
    const names = manifest.cases.map((c) => c.name).join(', ');
    throw new Error(`the sample set has no case named ${name}; it holds ${names}`);
  }
  return found;
}
