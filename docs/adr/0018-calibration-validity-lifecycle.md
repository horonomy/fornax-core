# ADR 0018 — Calibration Validity Lifecycle: Real vs. Unobservable Triggers

**Status:** Accepted
**Ticket:** FORNX-348 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crates:** `fornax-types` (`calibration.rs`), `fornax-verify` (`calibration.rs`,
`decision.rs`), `fornax-store` (`calibration.rs`), `fornax-bench`
(`qualifying.rs`), `fornax-daemon`, `fornax-cli`

## Context

FORNX-142 (this ticket's cited "Background" dependency) has **zero
codebase footprint** — no type, module, or test in this workspace
references it. Unlike FORNX-346/347, whose cited backgrounds were partly
or wholly fabricated, FORNX-348's premise is *not* fabricated: a real
numeric `fornax_verify::reliability::ReliabilityEstimate` (Wilson score
interval) and a real statistical `detect_drift` genuinely exist (FORNX-104,
merged before this ticket). What the ticket gets wrong is narrower: its
headline trigger dimension, `model_version`, is not something any adapter,
sensor, or capability announcement in this codebase can ever observe.

## The real gap: `model_version` is unobservable, and nothing writes a `ReliabilityObservation`

Two independent gaps, not one:

1. **No local source for `model_version`/`model_family`.**
   `fornax-corpus/src/candidate.rs` states explicitly that these dimensions
   have no local source in the store. No adapter (`fornax-adapter-claude`,
   `-codex`, `-opencode`) announces a model release in
   `RuntimeCapabilities`. `CalibrationProvenance::model_version`/
   `model_family` are therefore `Option<String>`, populated **only** when a
   caller supplies them explicitly — mirroring
   `fornax-corpus::CandidateCase::context`'s own precedent for an
   unobservable dimension. Nothing in this codebase ever supplies them
   today; both fields are `None` on every live path.

2. **No `ReliabilityObservation` writer exists anywhere** (FORNX-104's own
   module docs conceded this at merge time, and it remains true after this
   ticket). `compute_reliability`/`detect_drift` are real, tested, pure
   functions — but every live call site in `fornax-daemon` invokes them
   against an empty observation slice. Consequently:
   - The numeric path (`ReliabilityEstimate`, `ConfidenceInterval`) is
     mechanically correct but **unreachable on live traffic** — there is no
     observation corpus for it to compute over.
   - `CalibrationState::Suspect` (this ticket's drift-derived state) is
     equally unreachable on live traffic today, for the same reason: it is
     derived from `detect_drift`, which is derived from the same empty
     observation slice.

This ticket does not build a `ReliabilityObservation` writer — that remains
a distinct, larger future ticket (an adjudication UI or automated outcome
resolver). What this ticket adds is real and load-bearing regardless: the
**provenance-mismatch** half (`CalibrationState::Stale`) needs zero
historical observations and is fully reachable and tested today (see AC6
regression test, `decision.rs`'s
`stale_adapter_version_cannot_cross_the_boundary_and_never_relaxes_to_proceed`).

## Decision: two independent triggers, one split opt-in gate

`CalibrationState` has five variants: `NoActiveCalibration`, `Valid`,
`Stale { changed_dimensions }`, `Suspect { drift_state }`,
`InsufficientSupport { sample_support }`. `Stale` and `Suspect` are
deliberately **not** conflated into one boolean, because they answer
different questions and are gated differently:

- **Stale** answers "did the *environment* change?" — a pure equality
  check over `CalibrationProvenance` (adapter version, capability
  fingerprint, fusion/decision policy identity, disabled sensors, active
  policy revision digest). It reads zero historical observations, so it is
  **never** gated by
  `ReliabilityAggregationConfig::historical_aggregation_enabled` (default
  `false`) — a provenance mismatch is true regardless of whether the
  aggregation feature is on.
- **Suspect** answers "did the *statistics* change?" — derived from
  `detect_drift` over the exact observation corpus
  `historical_aggregation_enabled` governs. It **is** gated by that flag:
  with it off, `assess_calibration` never returns `Suspect`, only `Valid`
  or `Stale`.

This is a deliberate, explicit split, not an oversight: a caller who has
not opted into historical aggregation still gets a genuine calibration
signal (the environment-mismatch half), without ever consuming the
observation corpus the privacy gate exists to protect.

## Why the floor is provably non-regressive on live traffic today

`apply_calibration_floor` only ever changes behavior when it steps a
`Proceed` recommendation down to `Review`. Per
`fornax_verify::decision::DefaultRiskPolicy::action_for`'s own exhaustive
mapping table, `Proceed` is reachable from exactly one cell:
`(Verdict::Verified, UncertaintyBand::Corroborated, *)`. Per FORNX-347's
own finding (ADR 0017), `UncertaintyBand::Corroborated` requires every
counted vote to carry the **same** `correlation_group` — and no shipped
sensor anywhere in this workspace ever stamps one (`EvidenceSource::now()`
hardcodes `correlation_group: None`). `Corroborated`, and therefore
`Proceed`, is consequently unreachable on real traffic today, independent
of anything this ticket adds. Shipping `apply_calibration_floor` cannot
regress any live recommendation, because there is no live `Proceed`
recommendation for it to touch yet. This claim is pinned by
`decision.rs`'s AC6 regression tests, which construct a synthetic
`Corroborated` fixture (as `fusion.rs`'s own tests already do) specifically
*because* real traffic cannot reach one.

## Why calibration must never enter `fuse()`

`fornax_verify::fusion::BaselineFusionPolicy::fuse` must stay pure over
frozen evidence input for `fornax_replay`'s byte-identical-replay guarantee
(FORNX-98 AC1; ADR 0001's immutable-observation-before-interpretation
invariant). A calibration state is a live-environment judgment — it can
change from one process invocation to the next with no change to the
underlying evidence at all (an adapter upgrade, a sensor disabled). If it
entered `fuse()`, replaying the same frozen evidence at a later date could
produce a different `FusedFinding`, breaking the replay guarantee outright.

`assess_calibration` and `apply_calibration_floor` are therefore the only
two places calibration ever participates in the pipeline, and both are
strictly downstream of `fuse()`:

```
Evidence (frozen) --fuse()--> FusedFinding (frozen, replay-stable)
                                    |
                                    v
                          DefaultRiskPolicy::decide()
                                    |
                                    v
                              Recommendation
                                    |
                                    v (live-environment judgment, NOT frozen)
                       apply_calibration_floor(rec, state)
                                    |
                                    v
                         Recommendation (possibly floored)
```

`fornax-daemon`'s `/api/decision` always returns the (possibly floored)
`Recommendation` alongside the original, untouched `FusedFinding` — the
same "never one instead of the other" discipline FORNX-96 established.

## Persistence: insert-only, not session-scoped

`calibration_revisions` (migration `0016`) mirrors `acquisition_log`'s
opaque-JSON-document shape but deliberately diverges on scope: it has no
`session_id`/tenant column, because calibration provenance describes the
*deployment's own environment*, not a single session's observed evidence.
It is insert-only — there is no update/delete path anywhere in this
crate — so a stale or drifted calibration is recorded as a new revision,
never edited in place, preserving an honest history of every baseline this
deployment has adopted.

This ticket does not add a way to *record* a new revision from a live
daemon endpoint (no `POST /api/calibration`) — only `GET /api/calibration`
to read the current assessment. Adopting a new baseline today is a direct
store call (as the daemon's own tests demonstrate); a CLI/UI flow for
"bless the current environment as the new calibration baseline" is
explicitly out of scope and left for a follow-up ticket, matching how
FORNX-104 left the `ReliabilityObservation` writer itself as future work.

## AC coverage

| AC | Status | Note |
|---|---|---|
| AC1 (provenance schema) | Met, on observable dimensions only | `model_version`/`model_family` stay `Option`, never defaulted |
| AC2 (statistical drift reuse) | Met structurally; numeric path unreachable | No `ReliabilityObservation` writer exists on any live path |
| AC3 (five-state vocabulary) | Met | `NoActiveCalibration`/`Valid`/`Stale`/`Suspect`/`InsufficientSupport` |
| AC4 (daemon surface) | Met; not wired into the FORNX-116 audit ledger | `GET /api/calibration` only; no audit-trail integration in this ticket |
| AC5 (non-relaxing floor) | Met | `apply_calibration_floor`, proven non-regressive above |
| AC6 (adapter/capability boundary regression) | Met on `adapter_version`/`capability_fingerprint` only | `model_version` has no boundary to test — it is never populated |

Every gap above is a real, load-bearing architectural boundary this ticket
found and documented, not a shortcut — matching this campaign's standing
discipline of reporting partial-but-honest AC coverage rather than
declaring a ticket `Done` on a fabricated premise.
