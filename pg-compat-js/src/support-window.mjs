//! The support window as `COMPATIBILITY.md` declares it.
//!
//! `src/readers.mjs` is this package's copy of the npm half of that list, and a
//! copy is only worth having if something compares it to the original. The
//! `Reader list` section of `COMPATIBILITY.md` is a fenced block of
//! `<registry> <package> <versions...>` rows for that reason, so the drift that
//! matters — the window growing in the normative document while the gate keeps
//! testing the set it always tested — is a red run rather than an unnoticed one.
//!
//! Reformatting that block into prose or a table breaks
//! `test/manifest.test.mjs` on purpose: the check is what makes the sentence in
//! the document true.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

/** The document the reader list is declared in. */
export const COMPATIBILITY_DOC = fileURLToPath(new URL('../../COMPATIBILITY.md', import.meta.url));

/** First line of the block, and what marks it as the one to parse. */
const HEADER = '# <registry> <package> <versions...>';

/**
 * The npm readers `COMPATIBILITY.md` declares, as `<package>@<version>`.
 *
 * @param {string} [path] the document to read
 * @returns {Promise<string[]>} in the order the document lists them
 */
export async function declaredNpmReaders(path = COMPATIBILITY_DOC) {
  return parseNpmReaders(await readFile(path, 'utf8'), path);
}

/**
 * @param {string} text the document
 * @param {string} [what] what to name when there is nothing to parse
 * @returns {string[]} one id per version on an `npm` row
 */
export function parseNpmReaders(text, what = 'the reader list') {
  const rows = readerListBlock(text);
  if (rows === null) {
    throw new Error(
      `${what} has no reader-list block: expected a fenced block whose first line is "${HEADER}"`,
    );
  }

  const ids = [];
  for (const row of rows) {
    const trimmed = row.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;

    const [registry, pkg, ...versions] = trimmed.split(/\s+/);
    if (registry !== 'npm') continue;
    if (versions.length === 0) throw new Error(`${what}: the npm row for ${pkg} lists no version`);
    for (const version of versions) ids.push(`${pkg}@${version}`);
  }

  // An empty list would compare equal to nothing and make this check vacuous,
  // which is the failure the whole package is about.
  if (ids.length === 0) throw new Error(`${what}: the reader-list block holds no npm row`);

  return ids;
}

/**
 * The rows of the fenced block whose first line is `HEADER`, or null when the
 * document has no such block.
 */
function readerListBlock(text) {
  let insideFence = false;
  let rows = null;

  for (const line of text.split('\n')) {
    if (line.trimStart().startsWith('```')) {
      if (rows !== null) return rows;
      insideFence = !insideFence;
      continue;
    }

    if (rows !== null) rows.push(line);
    else if (insideFence && line.trim() === HEADER) rows = [];
  }

  return rows;
}
