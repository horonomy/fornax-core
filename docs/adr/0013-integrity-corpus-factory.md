# ADR 0013 — Integrity Corpus Factory: Boundary and Named Gaps

**Status:** Accepted
**Ticket:** FORNX-341 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crate:** `fornax-corpus`

## Context

FORNX-95/97/107 are mechanism-complete but blocked on a real, adjudicated
corpus — no such data exists in this repository (owner directive: do not
fabricate one). This ticket builds the repeatable path that turns real
Fornax sessions into candidate integrity cases a human can later adjudicate,
without centralizing protected raw evidence or letting a mined/synthetic
case be mistaken for a real human-adjudicated label.

## Decision: no new schema

A `CandidateCase` is a `fornax_replay::ReplayManifest` (FORNX-98 — already
frozen, versioned, self-contained) plus mining/withholding metadata. This
crate depends on `fornax-types`/`fornax-verify`/`fornax-replay`/`fornax-bench`
and reuses their existing primitives rather than duplicating them:
`EvidenceGraph::conflict()` for contradiction, `FusedFinding::uncertainty`
for uncertainty, `EvidenceSource::sensor_name` for sensor disagreement,
`fornax_bench::dataset::LabelingProvenance`/`content_hash_of` for the
label-provenance gate and manifest digest, and `fornax_types::redact`/
`RetentionClass` for redaction and lineage.

## The redaction/classification boundary is a kind allowlist, not a new redactor

`fornax_corpus::sanitize` keeps only `EvidenceKind::{ExitCode,
ProcessObservation}` — `ToolResult`/`TranscriptExcerpt`/`FileDiff` never
leave, independent of `redact_json`. This is deliberately conservative:
`fornax_types::redact`'s own tests document known misses (e.g. short
passwords, username-shaped paths), so re-running redaction is not treated as
a guarantee. If `redact_json` changes a kept-kind payload at all, the whole
item is withheld rather than exported partially redacted — a redactor that
fired once is exactly the item most likely to carry an adjacent, unfired
secret. Withheld items keep only an id/kind/timestamp/payload fingerprint
(`hex(sha256(payload)[..8])`, same shape as `fornax_types::home_identity`),
never the payload.

**What this does not claim:** no code path in this crate asserts "no secret
can ever leave." It asserts a specific, named guarantee — only two evidence
kinds are eligible at all, and any payload the shared redactor flags is
withheld whole — bounded by `redact.rs`'s own documented gaps.

## Mining is a closed enum, not a trait/registry

`MiningStrategy` (`EvidenceContradiction`, `HighUncertainty`,
`SensorDisagreement`, `VerdictChangedAcrossFindings`, `BenignControl`) plus
one pure `evaluate()` function — mirrors `fornax_verify::fusion::FusionRule`'s
shape. `BenignControl` is mined deliberately (a `Verified` claim, no
conflict, no other strategy) so a corpus is never only positive-case
harvesting (FORNX-341 AC), and `build_corpus_manifest` refuses to build a
non-empty corpus with zero controls, structurally, not just documented.

`HighUncertainty` fires only on `Undetermined`/`Conflicted` — never "not
`Corroborated`", since `Corroborated` is documented unreachable on real
traffic today (no shipped sensor stamps `correlation_group`); treating "not
Corroborated" as high uncertainty would fire on effectively all real cases.

### Named gap: no `HumanOverride` strategy

There is no override/break-glass concept anywhere in `fornax-store` today.
Adding a variant for it would misrepresent what this mechanism actually
detects — it is documented here as a real, current gap rather than shipped
as a strategy that structurally cannot fire.

## The label boundary is enforced by type absence, not a flag

`CandidateCase` has no `adjudicated_expected_outcome` field and no
`labeling_provenance` field at all. `promote_to_labeled_trajectory` is the
only path to a `fornax_bench::dataset::LabeledTrajectory`, and it takes the
adjudication *fields* (`labeled_by`/`labeled_at`), constructing
`LabelingProvenance::HumanAdjudicated` internally — a caller cannot pass
`SyntheticMechanismTest` here even by mistake. There is no code path from
mining to a labeled trajectory that skips a real human adjudication record.

## Persistence reuses FORNX-106 unchanged

`corpus_candidates` (migration `0013`) stores each candidate as opaque
canonical JSON, following `evidence.payload`'s precedent — `fornax-store`
has no dependency on `fornax-corpus` and never parses the document.
`RetentionClass::SanitizedCandidate` and `Store::insert_corpus_candidate`
wire straight into the existing lineage/deletion/sweep mechanism
(`delete_records_for_tenant`, `sweep_expired_records`) exactly like
`insert_finding` — no bespoke deletion path. `insert_corpus_candidate` is
the actual enforcement point for `FORNAX_CORPUS_MINING_ENABLED`; nothing
upstream of it already checks that gate.

### Named gap: `context` is usually `None`

`CandidateCase::context` (a `CohortIdentity`) requires every
`RawReliabilityContext` dimension via `aggregate_context` — but
`model_family`/`model_version`/`task_class`/`repository_class` have no local
source in the store (the same reason `fornax reliability` takes them as CLI
flags). The initial `fornax corpus mine` does not yet accept those flags, so
`context` is always `None` today. This is honest absence, not a fabricated
`"unknown"` value threaded through `aggregate_context`.

## Verification

`fornax corpus mine`/`fornax corpus export` were run end-to-end against a
real seeded local store (`crates/fornax-cli/tests/corpus_cli_e2e.rs`,
spawning the actual compiled binary) — not merely unit-tested. Verifying
against real captured Claude Code and Codex sessions (rather than a seeded
fixture) is tracked as follow-up acceptance work, not claimed complete here.
