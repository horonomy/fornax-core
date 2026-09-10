# ADR 0015 — Value-of-Information Evidence Planner: Ranking Boundary and Named Gaps

**Status:** Accepted
**Ticket:** FORNX-345 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crate:** `fornax-verify` (`voi.rs`)

## Context

FORNX-345's own ticket prose assumed a three-tier `AUTO_SAFE`/
`REQUIRE_APPROVAL`/`FORBIDDEN` availability model and reuse of "FORNX-178
experiment safety". Neither exists in this repository. The real safety
primitives are `fornax_types::experiment::{SideEffectClass,
SideEffectAllowList}` (deny-by-default) and
`fornax-experiment-runner::policy::{GlobalExperimentPolicy, is_permitted}`
(the two-layer host/spec grant check), plus
`fornax_types::capabilities::RuntimeCapabilities`/`SignalAvailability` and
`fornax_types::sensor_config::SensorDisableConfig`. This module is built on
those real primitives, not the fabricated one the ticket described.

## Decision: rank acquisition candidates, decide nothing, execute nothing

`fornax_verify::voi::VoiPolicy::plan` takes a `PlanInput` (the same
claim/graph/evidence/`FusedFinding` `fornax_verify::decision` already
consumes, plus `RuntimeCapabilities` and an `AcquisitionPolicy`) and returns
an `EvidencePlan`: a list of `EvidenceGap`s, a ranked list of
`AcquisitionCandidate`s, and a separate `unavailable` list for anything
`Unavailable`/`Forbidden` — never silently dropped. `EvidencePlan` carries no
executable action and no field that could be mistaken for one; this planner
recommends what evidence *would* help, `FORNX-346`'s executor is the only
thing that will ever act on a candidate.

## Three real gap sources, deliberately all three

`derive_gaps` reads:

1. `fused.rationale` — what fusion already flagged
   (`AllSupportDiscounted`/`StaleSupportDemoted`/`IndependenceUnverified`),
   plus `fused.unresolved_conflict` and a same-shared-correlation-group check
   across every counted link (`SingleSourceCorroboration`).
2. `graph.missing` — what a verifier explicitly noted absent, filtered to a
   concerning `SignalAvailability` state
   (`Unsupported`/`Unavailable`/`CollectionFailed`/`Redacted`/`Disabled`).
3. `capabilities` — what this runtime cannot observe *at all*, even when no
   verifier ever noted it missing. This is the only source that surfaces a
   `ProcessResult` gap on real traffic today, since nothing shipped writes a
   `ProcessResult` `MissingEvidence` row yet.

An empty graph (zero links, zero missing notes) is its own gap,
`NoEvidenceAtAll` — "nobody looked at all" is distinct from "something was
looked for and found missing".

## Probes are a closed, named enum with a real referent

`ProbeKind` (`RerunTest`/`InspectVcsState`/`QueryCiStatus`/
`VerifyArtifactHash`/`BoundedReplayExperiment`/`HumanReview`) maps to gaps
via `probes_for_gap`, and to signal classes via `probes_for_class` — every
class outside `{ProcessResult, ToolTrace, ToolResultPayload}` falls back to
`HumanReview` only, since this codebase has no automated way to observe
`FinalResponse`/`RawReasoning`/etc. independently. Each `EvidenceRequest`
declares its own `required_side_effects` — `HumanReview` always declares
none, which is why a gap always has at least one candidate that can reach
`Available` regardless of granted side effects (see the daemon e2e test
below).

## Availability is gated by the real primitives, checked in a fixed order

`classify_availability` checks, in order: (1) `FilesystemWriteOutsideWorktree`
is always `Forbidden` — never approvable through this planner, no matter
what policy grants; (2) the target signal class's real
`SignalAvailability` on this runtime (`Unavailable`/`Disabled` states);
(3) whether `AcquisitionPolicy::granted_side_effects` permits every side
effect the request needs (`RequiresApproval { missing_grant }` naming the
exact class, never a bare "denied"); (4) whether a `NetworkCall`-bearing
request additionally needs `cloud_sync_allowed()`/egress. This ordering
means a forbidden class is reported as forbidden even under a policy that
happens to grant it — forbidden is a stronger, non-overridable refusal.

## Independence is read from real structure, never assumed

`independence_of` compares a candidate probe's `expected_trust_class`
against `counted_trust_classes`/`counted_correlation_groups` — structural
readers over `FusedFinding::counted_link_ids` → graph links → evidence →
`EvidenceSource::correlation_group`/`trust_class`. A probe whose trust class
was never counted is `IndependentOfCounted`; one whose class was counted but
recorded no correlation group is `Unverified` (not rewarded as independent);
one that shares a real correlation group is `SameSourceAsCounted`. This is
the direct enforcement of the North Star invariant that correlated evidence
must never be counted as independent — it is checked per-candidate here, not
asserted in a comment.

## Scoring is a named, deterministic formula — not a fabricated probability

`DeterministicVoiPolicy::score` combines discrimination points (60/30/10),
an independence numerator (100/40/70/10) applied as a percentage multiplier,
a recency bonus, and a `saturating_sub` penalty from cost/latency/
action-risk/privacy. This is an authored ranking heuristic with named,
documented weights — not a Bayesian value-of-information calculation and
not presented as one. No candidate or `UtilityEstimate` ever serializes a
numeric score; only the enum-valued dimensions do (pinned by the
`no_candidate_or_utility_estimate_ever_serializes_a_numeric_score` unit
test), so a caller cannot mistake the ranking heuristic for a calibrated
probability.

## Daemon wiring reuses `compute_fusion`, adds no new fusion path

`GET /api/evidence-plan` reuses `compute_fusion` (the same graph-loading/
projection logic behind `/api/fusion`/`/api/decision`/`/api/judge`) and
`DefaultRiskPolicy` (the `/api/decision` precedent), then builds
`AcquisitionPolicy` from the daemon's own startup-loaded
`GlobalExperimentPolicy`/`SensorDisableConfig`/`cloud_sync_allowed()` state.
It reads `Store::capabilities_for_session` (all announcing providers) rather
than the in-memory single-provider `state.caps` cache, matching
`/api/capabilities`'s own choice — a second announcing provider's signals
must not be silently dropped from gap derivation.

## Cannot be verified without FORNX-346

The following are true of this ticket's implementation and are explicitly
**not** claimed as verified real-world behavior:

1. **AC3 (independence discounting) is fixture/unit-test-only.** No shipped
   sensor stamps `EvidenceSource::correlation_group` yet (the same
   documented gap `fusion.rs`/ADR 0013 already record), so
   `independence_of` returning `SameSourceAsCounted` has never been
   exercised against real captured evidence — only against a hand-built
   fixture.
2. **Cost and latency are declared constants, never measured.** `cost_for`/
   `latency_for` are authored per-`ProbeKind` lookup tables, not derived
   from any observed acquisition — a real `RerunTest` might take
   milliseconds or minutes; the planner has no telemetry loop to correct
   its own estimate.
3. **Discrimination is an authored judgement, unvalidated against outcomes.**
   `discrimination_for` returns `High` for a 2+-gap candidate and otherwise
   a per-`ProbeKind` constant — there is no dataset yet in which "this
   probe actually discriminated the verdict" was measured.
4. **`Recency::FreshObservation` is an assumption, not a measurement.**
   Every acquisition candidate is scored as if executing it now yields a
   fresh observation; nothing in this module checks how stale the
   *counted* evidence itself is beyond the `StaleSupport`/`StaleSupportDemoted`
   gap already surfaced by fusion.
5. **`RequiresApproval` has no consumer yet.** Nothing in this repository
   presents a `RequiresApproval` candidate to a human and records a grant
   decision — the field exists and is rendered by `fornax evidence-plan`,
   but the approval loop itself is out of scope for FORNX-345.
6. **`PlanOutcome::NoGapIdentified` is fixture-only on purpose.** It is only
   reachable for a `Verified` verdict under `UncertaintyBand::Corroborated`,
   itself documented unreachable on real traffic (same reason as #1) — real
   traffic always yields at least one gap today.
7. **Ranking quality has no ground truth.** There is no corpus (FORNX-343 is
   paused pending real human adjudication) against which "candidate ranked
   #1 was actually the most useful acquisition" could be checked. The
   ranking is internally consistent and unit-tested for its own invariants
   (cheap-independent beats expensive-correlated, correlated evidence never
   scored as independent, reproducible for a pinned input) — it has not
   been validated against outcomes.

## Verification

14 unit tests in `fornax-verify::voi` cover gap derivation from all three
sources, independence discounting, side-effect gating (including the
always-forbidden filesystem-outside-worktree case and the always-available
zero-side-effect fallback), ranking order, and reproducibility for a pinned
input. A real end-to-end daemon test
(`api_evidence_plan_surfaces_a_real_independence_gap_and_gates_its_candidates`)
persists a real claim/evidence/link to a seeded store and calls
`api_evidence_plan` against it — not a fixture — confirming the daemon
wiring reaches the same per-candidate gating the unit tests prove in
isolation. `fornax evidence-plan` renders the full plan; a matching CLI/
daemon flow has not been driven through a real spawned binary the way
`fornax-cli/tests/corpus_cli_e2e.rs` drives `fornax corpus`.
