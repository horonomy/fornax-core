# ADR 0019 — Human Feedback Loop and Active Sampling

**Status:** Accepted
**Ticket:** FORNX-349 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crates:** `fornax-corpus` (`feedback.rs`, `sampling.rs`), `fornax-store`
(`feedback.rs`, `retention.rs`, migration `0017_review_feedback.sql`),
`fornax-cli` (`feedback_cmd.rs`, `adjudicate_cmd.rs`)

## Context

FORNX-349 asks for two things that are easy to conflate and dangerous to
conflate: (1) a channel for product/operator feedback on a live finding, and
(2) a policy that prioritizes which mined cases most need real human
adjudication. Its own acceptance criteria warn against the trap directly —
"avoiding the trap of automatically treating user clicks or model
suggestions as ground truth" — and AC3 requires that "feedback from a
model/agent cannot masquerade as human adjudication."

## Central decision: feedback ≠ adjudication, structurally

`ReviewFeedback` (`fornax-corpus/src/feedback.rs`) carries a
`FeedbackDisposition`, never a `CaseLabel` or `ReviewOutcome`, and no
conversion function from one to the other exists anywhere in the crate. Its
`FeedbackAuthor` enum has two variants — `LocalOperator { operator_ref }` and
`AutomatedAgent { agent_ref }` — and it is safe for an `AutomatedAgent` to
submit feedback at all only *because* no path from either variant reaches
`fornax_corpus::adjudication::ReviewerRef`/`ReviewOutcome`/`CaseLabel`/
`promote_gold_label`/`GoldLabelRevision`. This is pinned by a guard test,
`feedback_module_never_references_adjudication_label_or_gold_types` in
`feedback.rs`, which scans the module's own (comment-stripped) source for
those identifiers and fails if any appear.

**Rejected alternative:** add `ReviewerKind::AutomatedAgent` to the existing
adjudication reviewer taxonomy instead of a separate `feedback` module. This
was rejected because it is a weaker guarantee — it relies on every future
call site correctly checking `ReviewerKind` before treating a review as
ground truth, instead of making the unsafe path impossible to reach at the
type level by keeping agents out of `adjudication_reviewers` entirely.

Feedback only ever raises a case's priority for review via
`fornax adjudicate sample` (below). It never mutates a candidate, a gold
label, or production calibration directly — `fornax feedback submit` writes
to the new `review_feedback` table only.

## Active sampling reuses `fornax_verify::voi::derive_gaps`, not a new metric

`DeterministicSamplingPolicy` (`fornax-corpus/src/sampling.rs`) derives each
case's `SamplingSignal` set from three already-real sources, deliberately
choosing not to invent a fourth:

1. `fornax_verify::voi::EvidenceGapKind`, via `derive_gaps` — reused as-is,
   not duplicated, mapping `UnresolvedConflict` /
   `AllVotesDiscounted` / `IndependenceUnverified` /
   `SingleSourceCorroboration` / `NoEvidenceAtAll` onto sampling signals.
2. `fornax_corpus::mining::MiningStrategy` already recorded on the candidate
   at mining time (`SensorDisagreement`, `HighUncertainty`,
   `VerdictChangedAcrossFindings`).
3. `CandidateCase::sanitization_altered_outcome()` and, new in this ticket,
   `ReviewFeedback::disposition.is_disagreement()` matched against the
   candidate's own id.

`derive_gaps` is called with an **empty `capabilities: &[]` slice**,
deliberately, so that the same corpus always produces the same
`SamplingPlan` regardless of which machine or session capabilities happen to
be live when `sample` runs — reproducibility was judged more valuable here
than the marginal extra discrimination `RuntimeCapabilities`-aware gaps would
add, since sampling only needs a *ranking*, not a diagnosis.

`fornax_verify::voi::ProbeKind::HumanReview` is scored last among VoI probes
(`Discrimination::Low`, `Cost::Expensive`, `Latency::Long`) precisely because
requesting a human probe is expensive — it is not reused for cross-case
priority ranking, which is a different question (which cases most need the
probe) from VoI's own question (is this probe worth running on this one
case).

### Near-duplicate bounding (AC4)

`PatternKey` groups cases by `(claim.subject, sorted mined_by, local_verdict)`
— a deliberately coarse SHA-256-derived key. `ReviewBudget` caps selection at
`max_per_pattern` (default 2) per pattern regardless of how many cases share
it, so one repeated mining shape cannot consume the whole review budget.
`DeterministicSamplingPolicy::rank` sorts by signal-set size, then by
signal-set lexical order, then by `case_id`, before applying the budget and
pattern cap — fully deterministic, so the CLI's stdout is stable across runs
against an unchanged corpus.

## Ground-truth corrections found while designing this

- `QueueEntry.selection_reason: String` already existed
  (`fornax_corpus::adjudication::state`) — `SelectedCase.selection_reason`
  is written there verbatim, so enqueuing a sampled case required zero
  schema change.
- `TrustClass`/`SignalClass` naming assumed during early drafting
  (`FornaxMeasured`/`ProcessObservation`) do not exist; the real variants
  are `HostObserved`/`ToolTrace`, already used correctly elsewhere in this
  codebase (see FORNX-346).
- Four sampling criteria named in FORNX-349's own scope — "novel context,
  suspected drift, model/judge disagreement" (beyond disagreement already
  covered), "expected information gain" as a standalone metric — have **no
  real source anywhere in this codebase** today: no adapter announces model
  identity, no drift detector output is wired to per-case granularity, and
  no second-judge/model-comparison pipeline exists. `sampling.rs`'s module
  doc comment states this gap directly rather than fabricating a signal for
  any of the four.

## Acceptance-criteria status (honest, as of this PR)

| AC | Status | Basis |
|---|---|---|
| A human review outcome is stored with exact provenance and can become a candidate case without becoming automatic truth | **Closed** | `ReviewFeedback::bound_to: FeedbackBinding` (`from_candidate()`) freezes `candidate_schema_version`/`fusion_policy_name`+`version`/`decision_policy_name`+`version`/`adapter_provider`/`adapter_runtime_version`/`disabled_sensors` verbatim from the candidate's own `ReplayManifest`. Structural guard test proves it can never become a `CaseLabel`/`ReviewOutcome`. |
| High-uncertainty/disagreement/novel cases rank above routine high-confidence duplicates under the default sampling policy | **Partial** | Uncertainty, cross-sensor disagreement, and human-feedback disagreement are real, sourced signals that do rank a case above a no-signal duplicate. "Novel context" cannot close — `CandidateCase::context: Option<CohortIdentity>` is `None` on every real path today (see ADR 0018 §1's identical finding for calibration), so novelty is structurally unobservable, not merely unimplemented. |
| Feedback from a model/agent cannot masquerade as human adjudication | **Closed** | See "Central decision" above; enforced by a source-scanning guard test, not by convention. |
| Duplicate/near-duplicate sampling is bounded so reviewer budget is not consumed by one repeated pattern | **Closed** | `ReviewBudget::max_per_pattern`, tested in `sampling.rs`. |
| Opt-out/deletion propagates to feedback-derived research artifacts according to policy | **Closed** | `review_feedback` is wired into the existing `RetentionClass::SanitizedCandidate` lineage (`fornax-store/src/retention.rs`'s `KNOWN_RECORD_TABLES`, `retention_class_for_table`, both delete match-arm blocks) — the same mechanism that already governs `corpus_candidates`/`acquisition_log`, not a new one. |
| At least one evaluation demonstrates whether active sampling yields more benchmark-relevant information per reviewed case than naïve/random sampling, or records non-value honestly | **Records non-value honestly** | See below. |

### Why AC6's evaluation was not built, and why that is the AC's own answer

A `--compare-random` harness was drafted and deliberately not implemented,
for two independent reasons found before writing it:

1. **The comparison would be analytically trivial, not empirical.**
   `DeterministicSamplingPolicy` selects by signal-count descending;
   uniform random selection does not select by anything. "The signal-sorted
   policy selects more high-signal cases than an unsorted one" is guaranteed
   by the comparator itself for any non-degenerate corpus — running the
   harness would prove nothing beyond what the sort function already states.
   The one thing such a harness *could* show without begging the question —
   pattern-diversity under a fixed budget — is already covered by AC4 above,
   not a new measurement.
2. **There is no benchmark to be relevant to.** The real, live
   `$HOME/.fornax/fornax.db` on the machine this ticket was implemented on
   has never run any corpus-mining migration — `corpus_candidates` and
   `review_feedback` do not exist as tables in it at all (verified via a
   read-only `sqlite3 .tables`, no rows read). Zero `GoldLabelRevision`s
   with `ReviewerKind::Human` exist anywhere in this codebase's history.
   "Benchmark-relevant information per reviewed case" requires a benchmark —
   a body of frozen gold labels large enough for `MIN_KAPPA_CASES` (20, per
   `fornax_corpus::adjudication::agreement`) — and none exists. Measuring
   "value" against zero ground truth would fabricate precision FORNX-349's
   own AC1 explicitly forbids.

**The precondition that makes AC6 measurable:** once the FORNX-343
adjudication playbook (`docs/research/fornx-343-adjudication-playbook.md`)
produces at least `MIN_KAPPA_CASES` frozen `GoldLabelRevision`s from a real
human reviewer, a `--compare-random --seed` harness becomes a real
evaluation — it can then measure agreement between `fornax adjudicate
sample`'s top-K and the surviving gold `CaseLabel::{Unreliable,
Contradicted, ...}` distribution against a matched random draw. Until that
corpus exists, building the harness would only measure the harness's own
synthetic fixture.

## Follow-up

`docs/research/fornx-343-adjudication-playbook.md` (merged, PR #131) predates
both `fornax feedback` and `fornax adjudicate sample`. Its pilot-batch
selection step is updated in this PR to route through
`fornax adjudicate sample --budget <n>` instead of hand-picking cases via
`enqueue` — `sample` is strictly the better selection path and is the actual
point of AC2/AC4, so the founder's first real adjudication batch should be
drawn by policy, not by hand.
