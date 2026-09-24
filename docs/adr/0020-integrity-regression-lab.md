# ADR 0020 — Integrity Regression Lab

**Status:** Accepted
**Ticket:** FORNX-344 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crates:** `fornax-bench` (`slice.rs`, `baseline.rs`, `regression.rs`, `gate.rs`)

## Context

FORNX-344 asks for a regression lab that freezes a baseline run, compares a
fresh run against it case-by-case, breaks that comparison down by context,
and gates on a regression budget. Its cited backgrounds are a mix of real
and non-existent: no dataset file exists anywhere on disk, `crates/fornax-ci`
is a GitHub check-run evidence *sensor*, not a CI-gating crate, and
FORNX-228 has zero Rust footprint at all — it is entirely
`docs/release-assurance-policy.md` (FORNX-229) plus shell scripts. That
document already fully specifies a risk-class vocabulary
(`PATCH_LOW_RISK`/`FEATURE`/`TRUST_BOUNDARY`/`MAJOR_OR_GA`) and a verdict
vocabulary (`PASS`/`BLOCK`/`INCONCLUSIVE`/`UNTESTED`) for release gating.
This ticket reuses that verdict vocabulary for its own gate rather than
inventing a third one — see [`gate`]'s module docs.

Everything lands in the existing `fornax-bench` crate. No new crate was
justified: this is more surface on the same offline benchmark tool
FORNX-95 already built, not a new architectural boundary.

## What each new module does, and why it's shaped that way

- **`slice.rs`** — breaks a comparison down by the only trajectory
  dimensions this codebase can actually observe: which sensor(s)
  contributed evidence, and which adapter/provider that evidence came
  from. Every other dimension FORNX-344 named — model/model_version,
  task_class, repository_class, adapter_runtime_version — has no local
  source anywhere in this codebase (the same finding ADR 0018 §1 and
  ADR 0019 already made about calibration/sampling context). `SliceKey`
  has no variant for any of them.
- **`baseline.rs`** — `BaselineReport` is exactly what `run_harness` +
  `compute_metrics` already produce, frozen with a `RunManifest` and a
  `CostSignal`. `CostSignal::Unmeasured{reason}` states honestly that this
  crate's `BaselineFusionPolicy`/`DefaultRiskPolicy` pipeline is a pure,
  synchronous, in-process computation with no token/dollar/API-call cost
  model on it today — "cost" as a regression dimension requires an actual
  costed dependency (a judge call, a paid API) landing on this path, which
  has not happened yet. Latency is measurable only at the CLI binary (a
  single clock read around the whole run) and is deliberately not carried
  onto the library's `BaselineReport` — the library stays pure and
  clock-free, matching `fusion::FusionPolicy::fuse`'s own discipline.
- **`regression.rs`** — matches cases by `PredictionRecord::trajectory_id`,
  **never by position**. A dataset that grows, shrinks, or reorders
  between two runs would silently compare unrelated cases under a
  position-based (`zip`) match; id-based matching makes an added/removed
  trajectory its own honest `RegressionClass` instead.
- **`gate.rs`** — see below.

## The one real trap: an empty/uncalibrated budget must be `Untested`, never `Pass`

`evaluate_gate` checks `!budget.calibrated || budget.rules.is_empty()`
*before* looking at a single rule, returning `GateVerdict::Untested`. The
naive alternative — `budget.rules.iter().all(|r| rule_passes(r))` — is
vacuously `true` over an empty iterator, which would silently report
`PASS` on a budget nobody has calibrated yet. This is exactly the failure
`docs/release-assurance-policy.md`'s own verdict table forbids: "Silently
converting `UNTESTED` into `PASS` is never permitted." Pinned by
`gate_tests::an_uncalibrated_empty_budget_is_untested_never_pass`.

The same discipline extends to a rule whose slice has no matching
trajectory data in the current run at all (its own check did not run —
`Untested` for that rule specifically) and to comparing two runs over
different dataset content (`Inconclusive` — "a required check ran but
could not produce a confident PASS or BLOCK" per the policy doc, since a
regression count between two different corpora isn't a fair comparison).
Overall gate verdict is the worst of every rule's own verdict, matching
the policy doc's own aggregation rule.

## What is committed, and what deliberately is not

`crates/fornax-bench/fixtures/integrity-lab/` commits three files:

- `mechanism-corpus.json` — 2 synthetic trajectories (one benign control,
  one two-sensor contradiction), both `LabelingProvenance::
  SyntheticMechanismTest`. Proves the mechanism, nothing about real
  integrity behavior.
- `mechanism-baseline.json` — that corpus's real, frozen `BaselineReport`,
  produced by running `fornax-bench regress freeze` against it (not
  hand-assembled JSON).
- `budget.json` — `{"calibrated": false, "rules": []}`. **No numeric
  threshold is committed.** A real regression budget requires a real
  corpus large enough to calibrate a tolerance against, which does not
  exist yet (same blocker as FORNX-343's human adjudication lane). Per
  the trap above, this fixture's own gate verdict is `Untested` by
  construction — proven by
  `regress_cli_e2e.rs::comparing_with_the_committed_uncalibrated_budget_is_also_untested_never_a_fake_pass`.

The file is deliberately not named `baseline.json` — it is synthetic, and
that name would read as a real calibration baseline to a future reader
skimming the fixtures directory.

## CI

A new `integrity-lab` job in `.github/workflows/ci.yml` runs
`cargo test -p fornax-bench` (never `--workspace`), path-filtered to this
crate's own dependency surface. It is **not** a required status check on
`main` branch protection — only `rust` is. Promoting it to required once a
real corpus and a calibrated budget exist is an explicit, deferred,
owner-only decision (mirrors this repo's own CI_UNAVAILABLE_EXTERNAL /
owner-decision conventions) — this ADR does not make that call, it only
flags that the decision point exists.

## Deferred, not done

- No real regression budget threshold — blocked on a real, human-adjudicated
  corpus (FORNX-343), same as everywhere else in Stage 8 that needs one.
- `docs/release-assurance-policy.md` amendment cross-referencing this
  gate's reuse of its verdict vocabulary — low-stakes, left for a
  documentation-only follow-up rather than bundled into this PR.
