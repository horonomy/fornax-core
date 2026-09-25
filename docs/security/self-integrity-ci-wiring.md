# FORNX-382 self-integrity CI wiring (recommendation, not applied)

Ticket FORNX-382 (parent epic FORNX-376, target v0.3.0) built a
self-integrity invariant registry (`crates/fornax-bench/src/self_integrity.rs`)
and property-based tests for several required trust-kernel invariants. This
document is the recommended CI wiring for AC6 ("CI separates fast invariant
smoke from periodic/deep verification while release assurance can require
the full suite") — it is deliberately **not applied** to
`.github/workflows/*` by this ticket. Modifying pipeline definitions
requires human review under this repository's own change-review policy,
which sits above this ticket's ordinary engineering scope; applying (or
declining) this recommendation is left to whoever reviews it.

## Current state (as of this PR)

All new FORNX-382 tests added in this PR run in well under a second each
(pure in-memory `proptest` generators over `Evidence`/`Claim` structs, plus
one 64-task `tokio` concurrency test that completes in milliseconds). None
of them currently need to be excluded from the default `cargo test
--workspace` path on latency grounds alone — the existing `rust` required
check's runtime was not measurably affected by this PR (verified locally:
full workspace test run stayed at ~85s before and after).

This wiring is a **forward-looking mechanism**, not a fix for a problem
this PR introduced — it exists so that future, genuinely slow additions to
this invariant program (heavier `proptest` case counts, `cargo-fuzz`
corpora, a mutation-testing tool integration, exhaustive `loom` models if a
finer-grained concurrency primitive is ever introduced) have a place to go
without silently inflating the required `rust` check's runtime on every PR.

## Recommended tiering mechanism

Use Rust's built-in `#[ignore]` attribute as the tier boundary, not a new
Cargo feature flag — it needs no `Cargo.toml` changes, works uniformly
across every crate in this workspace, and is what `cargo test`'s own
`-- --ignored` flag is designed for:

- **Fast lane (default, every PR):** `cargo test --workspace` — unchanged.
  Any new self-integrity test that runs in a similar order of magnitude to
  the ones added in this PR (sub-second) stays un-ignored and runs here.
- **Deep lane (periodic / release-triggered):** a test whose real
  contribution requires materially more cases or wall-clock time — a
  `PROPTEST_CASES=10000` sweep, a `cargo-fuzz` corpus replay, a
  mutation-testing run — should be marked `#[ignore = "FORNX-382 deep lane"]`
  and invoked explicitly via:

  ```bash
  cargo test --workspace -- --ignored
  ```

  `release-readiness.sh` / `release-qa-gate` (this repo's existing
  release-assurance mechanisms) are the natural place to require the deep
  lane's exit code as a gate — they already run outside the per-PR fast
  path per `docs/release-assurance-policy.md`.

## Recommended workflow change (for human review, not applied here)

If/when a genuinely slow test is added under the `#[ignore = "FORNX-382 deep
lane"]` convention above, the suggested addition to `.github/workflows/ci.yml`
(illustrative, not a diff to apply verbatim — read the current file's job
structure before adapting) is a **separate scheduled or release-triggered
job**, not a change to the existing `rust` job:

```yaml
# illustrative only -- adapt to this file's actual existing job/trigger shape
self-integrity-deep:
  # trigger: schedule (e.g. nightly) and/or a release-preparation workflow_call,
  # never on every PR push
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - run: cargo test --workspace -- --ignored
```

This keeps the existing `rust` required check exactly as fast as it is
today, and gives release assurance a place to require the deeper sweep
without it ever blocking or slowing ordinary PR iteration.

## Non-goals

This document does not claim any specific deep-lane test exists yet beyond
what this PR already added to the fast lane (none required tiering out).
It also does not claim passing the eventual deep lane proves the whole
distributed system correct — see FORNX-382's own Non-goals.
