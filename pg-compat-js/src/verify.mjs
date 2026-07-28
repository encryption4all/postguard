//! What every reader is held to for one case, written once.
//!
//! Recovering the right bytes is the headline check but not the only one. A
//! header change can shift the policy region while leaving the payload intact,
//! so the recipient list and the signed sender identity are checked too — those
//! are what a consumer acts on once the container opens.

import { describePlaintextMismatch, describePolicyMismatch } from './failures.mjs';
import { readArtifact } from './manifest.mjs';

/**
 * Open one case with one reader, for every recipient it was sealed for.
 *
 * @param {object} reader from `readers.mjs`
 * @param {string} dir artifact directory
 * @param {object} manifest
 * @param {object} kase the case to open
 * @returns {Promise<string[]>} one message per failure, empty when it opened
 */
export async function verifyCase(reader, dir, manifest, kase) {
  const failures = [];
  const artifacts = await loadArtifacts(dir, manifest, kase);

  let handle;
  try {
    handle = await reader.load(artifacts);
  } catch (e) {
    return [`${reader.id}: load: ${e.message}`];
  }

  try {
    for (const recipient of kase.recipients) {
      const label = `${reader.id}: ${kase.name}/${recipient.id}`;
      let opened;
      try {
        opened = await reader.open(handle, {
          mode: kase.mode,
          ciphertext: artifacts.ciphertext,
          verifyingKey: artifacts.verifyingKeyValue,
          recipientId: recipient.id,
          usk: artifacts.uskValues[recipient.id],
        });
      } catch (e) {
        failures.push(`${label}: unseal: ${e.message}`);
        continue;
      }

      failures.push(...checkOpened(label, opened, artifacts.plaintext, manifest, kase, reader));
    }
  } finally {
    await reader.unload?.(handle);
  }

  return failures;
}

function checkOpened(label, opened, want, manifest, kase, reader) {
  const failures = [];

  if (!equalBytes(opened.plaintext, want)) {
    failures.push(`${label}: ${describePlaintextMismatch(opened.plaintext, want)}`);
  }

  const wantRecipients = kase.recipients.map((r) => r.id);
  if (!equalLists(opened.recipients, wantRecipients)) {
    failures.push(
      `${label}: header lists recipients [${opened.recipients.join(', ')}], manifest says ` +
        `[${wantRecipients.join(', ')}]`,
    );
  }

  const identity = opened.identity;
  if (!identity) {
    failures.push(`${label}: reported no verified sender identity`);
    return failures;
  }

  const publicMismatch = describePolicyMismatch('public', identity.public, manifest.sender.public);
  if (publicMismatch) failures.push(`${label}: ${publicMismatch}`);

  // A reader that does not surface the private signing policy at all is
  // expected to report it absent even for a case sealed with one — see the
  // `surfacesUnsealResult` note in readers/pg-js.mjs.
  const expectPrivate = kase.privateSigning && reader.privateSignatureVisible;
  const gotPrivate = identity.private !== undefined && identity.private !== null;
  if (gotPrivate !== expectPrivate) {
    failures.push(
      `${label}: private signature present=${gotPrivate}, expected ${expectPrivate} ` +
        `(manifest privateSigning=${kase.privateSigning}, reader reports private policies=` +
        `${reader.privateSignatureVisible})`,
    );
  } else if (expectPrivate) {
    const privateMismatch = describePolicyMismatch(
      'private',
      identity.private,
      manifest.sender.private,
    );
    if (privateMismatch) failures.push(`${label}: ${privateMismatch}`);
  }

  return failures;
}

/**
 * Everything a reader needs for one case, read once so the readers only deal
 * with bytes and strings.
 *
 * `vk.json` and `usk-*.json` are shaped like PKG responses, so both the value
 * inside (what a reader is handed) and the raw JSON (what the PKG stub serves)
 * are kept.
 */
async function loadArtifacts(dir, manifest, kase) {
  const verifyingKey = new TextDecoder().decode(await readArtifact(dir, manifest.verifyingKey));

  const usks = {};
  const uskValues = {};
  for (const recipient of kase.recipients) {
    const raw = new TextDecoder().decode(await readArtifact(dir, recipient.usk));
    usks[recipient.id] = raw;
    uskValues[recipient.id] = JSON.parse(raw).key;
  }

  return {
    verifyingKey,
    verifyingKeyValue: JSON.parse(verifyingKey).publicKey,
    usks,
    uskValues,
    ciphertext: await readArtifact(dir, kase.ciphertext),
    plaintext: await readArtifact(dir, kase.plaintext),
  };
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function equalLists(a, b) {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}
