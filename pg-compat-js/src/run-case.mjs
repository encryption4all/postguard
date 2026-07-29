//! Running one case in its own process, and reading what came back.

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { childFailures } from './failures.mjs';

const CASE_RUNNER = fileURLToPath(new URL('../bin/pg-compat-case.mjs', import.meta.url));

/**
 * Open one case with one reader in a child process and turn its outcome into
 * failure messages.
 *
 * Synchronous on purpose: the cases are opened one at a time so a run that goes
 * red reports in a fixed order, and an aborting child cannot leave an awaited
 * promise behind to cancel the rest of the suite.
 *
 * @param {string} dir artifact directory
 * @param {string} readerId `<package>@<version>`
 * @param {string} caseName case from the manifest
 * @returns {string[]} one message per failure, empty when the case opened
 */
export function runCase(dir, readerId, caseName) {
  const result = spawnSync(process.execPath, [CASE_RUNNER, dir, readerId, caseName], {
    encoding: 'utf8',
    // A reader that tries to allocate gigabytes on a shifted header should die
    // with its own message rather than hanging the job.
    timeout: 300_000,
  });

  return childFailures(`${readerId}: ${caseName}`, {
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  });
}
