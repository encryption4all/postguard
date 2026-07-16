# Canonical condiscon examples

Test vectors for `POST /v2/{irma|request}/start` request bodies, pinned by
`../irma-auth-request.schema.json` and **executable** against the server's
actual parser (`pg-pkg/tests/contract_examples.rs`): every `valid/` file must
parse as `pg_core::api::IrmaAuthRequest`, every `invalid/` file must be
rejected. JSON has no comments and the parser rejects unknown fields (so a
`$comment` key would itself make an example invalid) — the commentary lives
here instead.

## valid/

| File | What it pins |
|---|---|
| `flat-legacy.json` | The pre-condiscon shape every deployed client sends: a flat conjunction of attribute objects. Must keep parsing forever. |
| `condiscon-name-disjunction.json` | The postguard-website sender-signing request verbatim: email, a skippable disjunction over four name sources (leading empty alternative), optional phone and date of birth. |
| `optional-attribute.json` | `optional: true` on a top-level attribute; the PKG expands it into a disjunction with an empty option. |
| `optional-discon-empty-alt.json` | A skippable disjunction: the empty conjunction marks it optional (Yivi convention, conventionally listed first). Ordering is presentational; either order parses. (Historical: apps before irmamobile v8.1.0 mis-rendered empty-first — irmamobile#360, fixed.) |
| `value-constrained.json` | `v` constrains disclosure to an exact value. |

## invalid/

| File | The mistake |
|---|---|
| `missing-con.json` | `con` is required. |
| `con-not-array.json` | `con` must be an array, not a bare attribute object. |
| `attr-missing-type.json` | Every attribute needs `t`. |
| `type-not-string.json` | `t` must be a string. |
| `validity-not-number.json` | `validity` is a number of seconds, not a string. |
| `discon-missing-conjunction-level.json` | The classic nesting mistake: a disjunction entry is an array of **conjunctions** (arrays), not of attributes. Wrap each alternative: `[[{...}]]`. |
| `unknown-attribute-field.json` | A misspelled field (`vaule` for `v`) is **rejected**, never silently ignored — silently dropping a value constraint would widen the disclosure the caller intended. The 400 names the field. |
| `unknown-top-level-field.json` | Same strictness at the request's top level (`validty` for `validity`). |
