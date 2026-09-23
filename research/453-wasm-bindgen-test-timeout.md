# WASM_BINDGEN_TEST_TIMEOUT: per-test or whole-run? (#453)

Researched 2026-09-23 against `origin/main` at `6114f48`. Facts only; the fix
(if any) is a separate `build.yml` ticket.

## Summary

1. `WASM_BINDGEN_TEST_TIMEOUT` is **one wall-clock deadline for the whole page
   run**, not a per-test timer. It lives in the host-side runner, not in the
   browser page. Its clock starts after the WebDriver session exists and the
   `goto` (navigate) request has returned, and it stops when `test result: `
   shows up in the scraped `#output`. The default is 20 s. When the deadline
   passes first, the runner prints `Failed to detect test as having been run.
   It might have timed out.`
2. Green Safari runs since 2026-09-10 took 18.7–30.9 s from `running 16 tests`
   to `test result` (n=22, median 27.4, p90 30.3). The harness's own
   `finished in` figure ranges up to 31.07 s. All four red Safari runs died
   26.2–27.9 s after `running 16 tests`, each at a different point in the suite.
3. 30 s is inside the Safari distribution, not above it. The top green runs
   finished under a 30 s deadline with almost nothing to spare. Twice the
   observed maximum (31.07 s) is 62.1 s, so **63 s** is the smallest whole
   number that meets #432's ~2x rule. `pg-core/tests/ci_wiring.rs` on
   `origin/main` does **not** pin `WASM_BINDGEN_TEST_TIMEOUT`.

One premise needs correcting: CI does not run `wasm-bindgen-test-runner`
0.2.121. `pg-wasm` has no committed `Cargo.lock` (it is on the workspace
`exclude` list, and 0.2.121 is the *root* `Cargo.lock`'s version). Every CI log
examined (77 of 77) shows `Compiling wasm-bindgen v0.2.128` and
`Installed package wasm-bindgen-cli v0.2.128`. I read both tags. The timeout
code is byte-identical between them (see below).

## 1. What the timer bounds (source)

Sources: `wasm-bindgen/wasm-bindgen` at tag `0.2.121` (commit `49457f2d`) and
tag `0.2.128` (commit `246946fd`). `crates/cli/src/wasm_bindgen_test_runner.rs`
is identical between the two tags. Lines 180–270 of `headless.rs` are
identical too; the only differences in that file are in Chrome/Edge
session-response parsing.

- **Env read and default.** `crates/cli/src/wasm_bindgen_test_runner.rs:321-329`
  reads `WASM_BINDGEN_TEST_TIMEOUT`, prints `Set timeout to {timeout}
  seconds...` (l.326) and falls back to `unwrap_or(20)` (l.329). A separate
  `WASM_BINDGEN_TEST_DRIVER_TIMEOUT` (l.313-319, default 5) only bounds driver
  startup.
- **Hand-off.** In browser mode the value is passed as `browser_timeout` to
  `headless::run(&addr, &shell, driver_timeout, browser_timeout, nocapture)`
  (l.464), where it becomes the `test_timeout` parameter
  (`crates/cli/src/wasm_bindgen_test_runner/headless.rs:58-64`).
- **When the clock starts.** In `headless.rs`, the WebDriver session is
  created (`client.new_session`, l.156) and the page is visited
  (`client.goto`, l.188, a `POST /session/{id}/url`, l.596-609). Only after
  that do `let start = Instant::now();` (l.205) and
  `let max = Duration::new(test_timeout, 0);` (l.206) run. Session creation
  and navigation are therefore outside the window. Whatever part of the test
  run happens while `goto` is still blocked is also outside it.
- **What it bounds.** A single loop, `while start.elapsed() < max`
  (l.211-240), polls `#output` about every 100 ms (`thread::sleep`, l.239).
  It breaks when the text contains `test result: ` (l.214 / l.235). Nothing
  resets `start` per test, and no per-test timer exists. `crates/test/src`
  (the in-page harness) contains no occurrence of "timeout" at either tag.
- **The failure message.** After the loop, if the collected output still
  lacks `test result: `, l.262-269 prints `Failed to detect test as having
  been run. It might have timed out.` (l.268). Because the output is not
  `test result: ok`, l.285-303 then dumps `#console_output` and
  `bail!("some tests failed")`. That is the path in all four red Safari logs:
  the message, then `console output:` with `Invoking test:` lines.

The comment in `build.yml:101-105` says this is *"a per-test timer running
inside the browser page"*. The source contradicts both parts of that claim.

### How the window lines up with the log, per driver

The source says the window starts when `goto` returns. How much of the test
run that return comes after depends on the driver. The logs show the
following (an observation, not read from source):

- **Chrome**: the whole output (`running 16 tests` through `test result`)
  reaches the log in one burst, 1–4 ms wide. Every Chrome run has a harness
  `finished in` of 31.6–37.0 s under a 30 s timer and still passes. So the
  runner's window did not cover the test run.
- **Firefox**: output streams in. Harness `finished in` reaches 31.9 s under
  a 30 s timer and passes, so at least ~2 s of the run fell before the window
  started.
- **Safari**: output streams in. In the four failures the deadline fired
  26.2–27.9 s after `running 16 tests`, so the window started 2.1–3.8 s
  *before* that line was logged. In green runs `running` → `test result`
  reaches 30.9 s, so the offset varies from run to run. Log timestamps record
  when a poll returned, not when the page wrote the text.

## 2. Measured durations

Method: every run of workflow "Continuous integration" created on or after
2026-09-10 (24 runs, all attempts, 78 browser jobs). Job logs came from
`gh api repos/encryption4all/postguard/actions/jobs/<id>/logs`. For each job
I measured from the log timestamp of `running 16 tests` to that of the first
`test result:` line, and also read the harness's own
`test result: ... finished in Xs`. Five of the Safari greens ran on #440's
branch before the change landed, with the timeout still at 120; the rest ran
at 30.

| browser (green jobs) | n | metric | min | median | p90 | max |
|---|---|---|---|---|---|---|
| safari | 22 | `running` → `test result` (s) | 18.7 | 27.4 | 30.3 | 30.9 |
| safari | 22 | harness `finished in` (s) | 18.85 | 27.6 | 29.88 | 31.07 |
| safari, timeout=30 only | 17 | `running` → `test result` (s) | 18.7 | 27.1 | 29.3 | 30.9 |
| firefox | 25 | `running` → `test result` (s) | 15.5 | 31.3 | 31.6 | 32.9 |
| firefox | 25 | harness `finished in` (s) | 15.63 | 31.8 | 31.89 | 33.3 |
| chrome | 26 | `running` → `test result` (s) | 0.0 | 0.0 | 0.0 | 0.0 (burst, not measurable) |
| chrome | 26 | harness `finished in` (s) | 22.45 | 31.8 | 33.91 | 36.98 |

p90 is the nearest-rank value. One Firefox job (35730910084/2) was cancelled
when its Safari sibling failed and is excluded, even though its suite had
finished (31.7 s).

### Safari green runs

| run / attempt | where | timeout | `running` → `test result` (s) | harness `finished in` (s) |
|---|---|---|---|---|
| 34451988800 / 1 | #440 | 120 | 19.8 | 19.98 |
| 34452361151 / 1 | #440 | 120 | 30.3 | 29.88 |
| 34452381254 / 1 | #440 | 120 | 27.8 | 28.07 |
| 34453079085 / 1 | #440 | 120 | 20.2 | 20.16 |
| 34453724356 / 1 | #440 | 120 | 30.8 | 30.87 |
| 34456699414 / 1 | #440 | 30 | 19.8 | 19.93 |
| 34463266164 / 1 | main | 30 | 19.8 | 19.97 |
| 34472035815 / 1 | #443 | 30 | 27.1 | 27.35 |
| 34472451768 / 1 | #443 | 30 | 18.7 | 18.85 |
| 34463363163 / 2 | release-plz-2026-09-09 | 30 | 20.9 | 20.81 |
| 35728830498 / 1 | main | 30 | 26.3 | 26.41 |
| 35729136321 / 2 | #443 | 30 | 29.4 | 29.49 |
| 35730826538 / 1 | main | 30 | 24.8 | 24.93 |
| 35833174022 / 1 | #452 | 30 | 27.6 | 27.91 |
| 35833256146 / 1 | #452 | 30 | 28.4 | 28.75 |
| 35834294226 / 1 | #452 | 30 | 28.7 | 29.3 |
| 35836390014 / 1 | #452 | 30 | 21.5 | 21.52 |
| 35837315595 / 1 | #452 | 30 | 23.9 | 24.12 |
| 35837332298 / 1 | #452 | 30 | 29.3 | 29.5 |
| 35838607779 / 1 | #452 | 30 | 30.9 | 31.07 |
| 35838709330 / 1 | #452 | 30 | 28.5 | 28.83 |
| 35839218183 / 2 | main | 30 | 28.1 | 28.29 |

### Safari red runs

All four follow the same pattern: tests pass one after another, no test
fails, and the run is cut off by `Failed to detect test as having been run`.

| run / attempt | where | tests `ok` | `running` → failure (s) | `Running headless tests` → failure (s) |
|---|---|---|---|---|
| 35729136321 / 1 | #443 | 8 / 16 | 26.2 | 45.0 |
| 35730910084 / 2 | #444 (release-plz) | 12 / 16 | 27.9 | 37.4 |
| 35836270430 / 1 | #452 | 8 / 16 | 26.2 | 42.7 |
| 35839218183 / 1 | main `6114f48` | 11 / 16 | 26.4 | 44.4 |

The ticket lists two of these; #444 and #452 add two more. None of the four
reached the 12-minute job timeout. That is the other failure mode (#416:
zero tests, ~17 min of silence), and it did not occur in this window. The
largest gap between consecutive `ok` lines in the #452 failure log is 7.7 s
(`stream::test_seal_unseal_web` → `stream::test_seal_unseal_rust_to_web`),
above the "~5s slowest single test" that `build.yml`'s comment assumes. That
gap is only an upper bound, because Safari polls can lag.

## 3. Conclusion (facts)

- **Is 30 below the Safari tail?** Yes. Median green is 27.4 s and p90 is
  30.3 s (`running` → `test result`). The maximum is 30.9 s (harness
  31.07 s), which passed only because this runner's window opens somewhat
  after the harness starts. The red runs are the same distribution cut off at
  the deadline. They are not one slow test.
- **Smallest value with the ~2x margin.** 2 × 31.07 s = 62.1 s → **63**.
  Using `running` → `test result` instead (2 × 30.9 = 61.8) gives 62. The
  worst window start seen in a red run was 3.8 s before `running`. Adding it
  gives 31.07 + 3.8 ≈ 34.9 s, whose double is ~70. The variable is set at job
  level for all three matrix legs, and the harness maxima for the other two
  are Firefox 33.3 s and Chrome 37.0 s. Chrome's window does not appear to
  cover its run, though (see §1).
- **Does `ci_wiring.rs` pin the value?** No. `git grep WASM_BINDGEN_TEST_TIMEOUT
  origin/main` matches only `.github/workflows/build.yml:106`. The #416 test
  `the_wasm_browser_job_has_an_honest_timeout_and_no_retry_wrapper`
  (`pg-core/tests/ci_wiring.rs:1146`) asserts only that `timeout-minutes` is
  present, that `nick-fields/retry` is gone, and what shape the `wasm-pack
  test` command has.
- **Version drift.** CI runs 0.2.128, not 0.2.121, because `pg-wasm` has no
  lockfile. The timeout semantics are the same in both.

## Sources

- https://github.com/wasm-bindgen/wasm-bindgen/blob/0.2.121/crates/cli/src/wasm_bindgen_test_runner.rs#L313-L329
- https://github.com/wasm-bindgen/wasm-bindgen/blob/0.2.121/crates/cli/src/wasm_bindgen_test_runner.rs#L464
- https://github.com/wasm-bindgen/wasm-bindgen/blob/0.2.121/crates/cli/src/wasm_bindgen_test_runner/headless.rs#L156-L269
- https://github.com/wasm-bindgen/wasm-bindgen/blob/0.2.128/crates/cli/src/wasm_bindgen_test_runner/headless.rs#L180-L270
- https://github.com/wasm-bindgen/wasm-bindgen/blob/0.2.121/crates/cli/src/wasm_bindgen_test_runner/index-headless.html
- GitHub Actions job logs for the runs listed above (workflow `.github/workflows/build.yml`, job `test-wasm-browsers`).
- `origin/main` `6114f48`: `.github/workflows/build.yml:93-106`, `pg-core/tests/ci_wiring.rs:1125-1180`.
