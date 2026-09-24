# ADR 0014 — Corpus Adjudication: Boundary, Blinding Limits and Named Gaps

**Status:** Accepted
**Ticket:** FORNX-342 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crate:** `fornax-corpus::adjudication` (+ `fornax-store::adjudication`, `fornax-cli::adjudicate_cmd`)

## Context

FORNX-341 built the mechanism to mine sanitized candidate integrity cases.
This ticket builds the mechanism to convert those candidates into a
human-adjudicated gold corpus with explicit uncertainty, disagreement and
provenance — **the most important data rule remains: do not fabricate the
real corpus.** No LLM/Fornax-generated label may be stored as
`HumanAdjudicated`; no inter-rater agreement figure may be manufactured;
ambiguous cases must stay explicitly `Unresolved`/`NotEvaluable`, never
collapsed into a resolved label.

## Anti-fabrication is structural, not a policy to remember

- `ReviewerKind::Human` requires a non-empty `attested_by` at registration
  (`ReviewerRef::new`) — there is no way to register a human reviewer
  silently.
- `promote_gold_label` selects `LabelingProvenance::HumanAdjudicated` only
  when **every** contributing reviewer is `Human`; a single
  `MechanismTestFixture` reviewer anywhere in the chain routes the whole
  export to `SyntheticMechanismTest`. This crate's entire test suite,
  including the real end-to-end CLI test
  (`crates/fornax-cli/tests/adjudicate_cli_e2e.rs`), uses only
  `MechanismTestFixture` reviewers — no test in this repository registers a
  `Human` reviewer or reports a real inter-rater agreement figure.
- `AdjudicationState` is **derived, never stored** (`derive_state`) — there
  is no mutable state column any write path could use to silently overwrite
  disagreement.
- `ResolutionBasis` has no `MajorityVote` variant. The ticket's own
  non-goal ("no assumption that majority vote equals truth") is enforced by
  that variant simply not existing.
- `cohens_kappa`/`AgreementStat` never return a fabricated number:
  `Insufficient` below `MIN_KAPPA_CASES` (20) double-reviewed cases,
  `Undefined` on degenerate marginals or a zero denominator.
- `GoldLabelRevision` is insert-only and metadata-only, deserializes via
  `#[serde(try_from)]` re-validating `revision >= 1`, non-empty
  `contributing_review_ids`, and a recomputed digest — a hand-forged JSON
  row is rejected before construction, and `Store::insert_gold_label`
  refuses a second insert at an existing `(case_id, revision)`.

## Blind review is presentational, not sealed — a named limit

`blind()` destructures `CandidateCase` exhaustively by field name, so a new
field added to that type later is a compile error here until someone
decides whether it leaks the model's judgment. That is the real guarantee.
**What this does not claim:** a reviewer with direct SQLite access, or who
runs `fornax corpus export` themselves, can still read `local_verdict`. The
guarantee is narrower and real — the rendered view a reviewer is shown
(`BlindedCase`) contains no verdict field at all — not a sealed/encrypted
view immune to a determined bypass.

## Why `HumanOverride`/`majority-vote`/a third `ReviewOutcome` variant were rejected

- No override/break-glass concept exists anywhere in `fornax-store` today
  (same gap FORNX-341's mining strategies already documented) — adding a
  mining or review concept for it would misrepresent what this mechanism
  detects.
- A `NotEvaluable`-vs-`Unresolved` routing distinction is carried by a
  `"not_evaluable:"` string prefix on an adjudicator's `Unresolved { reason
  }`, rather than a third `ReviewOutcome` variant — one routing distinction
  did not justify widening the enum every future match arm must handle.

## Persistence: what is and is not tenant-deletable

`adjudication_queue`/`adjudication_views`/`adjudication_reviews` are
lineage-tagged exactly like `corpus_candidates` and are removed by
`delete_records_for_tenant`/`sweep_expired_records`. Two tables are
deliberately **not**:

- `adjudication_reviewers` — a reviewer identity is not one session's data
  and is not scoped to any tenant.
- `gold_labels` — insert-only and metadata-only (no free text, no session
  content), so there is nothing for a tenant delete to need to touch. After
  a tenant delete removes a case's candidate, `fornax adjudicate export`
  excludes the now-orphaned gold label with an explicit reason rather than
  emitting a trajectory with no evidence.

## Cross-case tamper detection: digest chain + audit ledger, not a new crypto primitive

`GoldLabelRevision::revision_digest` chains to the previous revision's
*number* (not its digest) per case — enough to prove a specific revision
was not fabricated after the fact within its own case's history. It does
**not** prove the whole `gold_labels` table has not been reordered or had
a row removed; that is the audit ledger's job (`fornax adjudicate freeze`
also appends a `GoldLabelFrozen` event, verifiable via
`Store::verify_audit_chain`). No signing keys, no blockchain, no
per-review cryptography beyond this digest.

## Named gaps carried into this ticket, not resolved by it

- FORNX-341's gaps still apply: no `HumanOverride` mining strategy,
  `CandidateCase::context` still usually `None`.
- **No cross-machine reviewer identity.** Reviewer ids are local, opaque
  strings with no external/cross-machine attestation.
- **`round` numbering is derived from prior gold-label revision count**,
  not from an explicit re-open action — a case that has never been frozen
  is always round 1, matching the common case, but this is a simplification
  worth revisiting if a future need arises to re-open a case's review round
  without freezing an intermediate revision.

## Cannot be verified without a real human reviewer — do not fabricate

The mechanism above is fully exercised end-to-end with
`MechanismTestFixture` reviewers. These specific claims are **not**
established by any test in this repository and must stay pending until a
real person actually uses `fornax adjudicate`:

1. **Real inter-rater agreement.** Any kappa/agreement figure this
   mechanism produces in-repo comes from fixture reviewers and is a
   mechanism demonstration only.
2. **A real frozen gold label / real gold dataset.** No `HumanAdjudicated`
   dataset can exist until a real registered human reviewer submits real
   reviews. `fornax-bench run`/`ablate` against in-repo output correctly
   reports `contains_synthetic_labels: true` — that is the honest state,
   not a gap to paper over.
3. **That blinding actually reduces confirmation bias.** The code hides the
   verdict from the rendered view; whether that changes human judgment in
   practice is an empirical claim requiring real reviewers.
4. The AC "a candidate case can move through blinded review → … → frozen
   gold label with complete provenance" is verified *as a mechanism*
   (`adjudicate_cli_e2e.rs`) but not *with real human provenance* — those
   are two different claims, and only the first is checked off here.
