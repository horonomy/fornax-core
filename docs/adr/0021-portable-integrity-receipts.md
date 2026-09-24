# ADR 0021 — Portable Integrity Receipts

**Status:** Accepted
**Ticket:** FORNX-350 · **Epic:** FORNX-340 (Stage 8 / Active Evidence Intelligence)
**Crates:** `fornax-types` (`receipt.rs`), `fornax-receipt` (new crate), `fornax-cli` (`receipt_cmd.rs`)

## What a receipt proves, and what it does not

A receipt is **not** a cryptographic proof that a semantic claim is true. It
is a verifiable package describing what claim was assessed, what evidence/
version/policy produced the finding, what remains missing, and whether the
package itself has been altered. Receipt authenticity/integrity never
proves the underlying semantic claim is true beyond the evidence
represented — weak evidence, faithfully receipted, is still weak evidence.
A `Verified`/`Proceed` receipt with a fully populated `coverage` block is a
statement "this is exactly what Fornax observed and decided, unaltered
since issuance" — not a statement "this claim is objectively correct."

## Ground-truth corrections found

- **`fornax-ci` is an evidence sensor, not a gate consumer.** It queries
  GitHub check-runs and emits evidence *into* fusion — the same correction
  ADR 0020 already made for FORNX-344. The downstream consumer this ticket
  needed was built fresh (`fornax receipt verify`'s exit-code contract plus
  the `receipt-gate` CI job), not adapted from `fornax-ci`.
- **No signing identity exists anywhere in this workspace.** `SigningKey`/
  `Signer` appear only in `#[cfg(test)]` code across the repo.
  `fornax_types::policy::bundle`'s and `audit_checkpoint.rs`'s own module
  docs state this as a deliberate invariant ("Rust is only ever the
  verifier"). `fornax_types::sensor_config::home_identity()` is a
  non-secret pseudonym for detecting cross-`$FORNAX_HOME` mixups — it
  authenticates nothing, and is carried on `ReceiptBody.home_identity` as
  exactly that: a pseudonym, never mistaken for a signing identity.
- **The envelope/payload split was already precedented.** `SignedPolicyBundle`/
  `SignedAuditCheckpoint` are both `{schema_version, payload_b64,
  signatures}`, with the typed payload parsed only after signature
  verification returns raw bytes. `verify_signed_envelope`'s
  `VerifiedEnvelope` is `pub(crate)` specifically so a sibling top-level
  module can reuse it (`audit_checkpoint.rs` already does) — no visibility
  change was needed to add `fornax_types::receipt`.
- **`CalibrationProvenance` (FORNX-348) already is the receipt's provenance
  block.** Reused verbatim via the newly-extracted
  `fornax_verify::calibration::live_provenance`. `model_version`/
  `model_family` stay `None` on every CLI-issued receipt today — no local
  source observes a model release (same finding as ADR 0018 §1, ADR 0019,
  ADR 0020).
- **`Verdict::Verified` + `RecommendationAction::Proceed` is reachable only
  through `UncertaintyBand::Corroborated`**, which itself requires two or
  more counted links stamping *distinct* `correlation_group`s — no shipped
  sensor does this on real traffic yet (the same finding ADR 0017 made).
  This surfaced directly while writing this ticket's own e2e test: a
  single generic supporting evidence item lands in `Qualified` (an
  `IndependenceUnverified` caveat fires) and decides `Review`, never
  `Proceed`. The default gate policy's `allowed_actions: [Proceed]` is
  therefore honest but narrow today — most real findings will `Hold`/
  `Reject` on `recommendation_not_allowed` until independence-stamping
  sensors exist, not because the gate is wrong, but because `Proceed`
  itself is rare on real traffic.

## Central architectural decisions

### D1 — Split on the envelope/payload seam

The signed envelope and signature verification stay in `fornax-types`
(`receipt.rs`, a top-level sibling of `audit_checkpoint.rs`), reusing the
existing `pub(crate) verify_signed_envelope` under a new
`RECEIPT_SIGNING_DOMAIN`. The typed `ReceiptBody`/`IntegrityReceipt`,
issuance, freshness, and gate logic live in a **new crate**,
`fornax-receipt`, because they need `fornax-verify` types
(`UncertaintyBand`, `RecommendationAction`, `EvidenceGapKind`,
`FamilyBasis`) that `fornax-types` cannot depend on without inverting the
crate graph.

### D2 — Verification-only, by explicit owner decision (FORNX-350)

**Fornax does not sign receipts in production in this ticket.** There is no
`SigningKey`/`Signer` import anywhere in `fornax-types::receipt` or
`fornax-receipt`'s non-test code — signing is exercised only by a
`#[cfg(test)]` signer. A receipt signed by something else may be verified
here; an unsigned receipt is represented explicitly as
`SignatureStatus::Unsigned` — never treated as invalid, and never silently
treated as authenticated. This preserves the existing "Fornax is primarily
the verifier" invariant `fornax_types::policy::bundle`/`audit_checkpoint.rs`
already state, and keeps the wire format stable so a separately-designed
signing capability (key ownership, provisioning, storage, rotation,
revocation, compromise recovery — none of which is decided here) can be
added later without a schema break.

**Honesty limit that follows from this**: a bare, unsigned receipt's own
digest (`#[serde(try_from = ...)]`, recompute-and-reject on mismatch —
the same tamper detector `PublishedPolicyRevision` already uses) catches
*accidental or naive* mutation, since anyone can recompute a SHA-256 digest
over an edited body. Only a verified signature is adversarial
tamper-evidence. `fornax receipt verify`'s output and `docs/receipt-consumer-guide.md`
both say this plainly.

### D3 — A third verdict vocabulary, reused ordering discipline

`GateOutcome` (`Accept`/`Reject`/`Hold`/`Untested`) answers "may this
receipt authorize this downstream pipeline step to proceed?" — distinct
from `fornax_types::Verdict` (what was observed) and
`RecommendationAction` (what Fornax recommends). Mirrors
`fornax_bench::gate::GateVerdict`'s identical three-vocabulary discipline
and its worst-of-many aggregation rule.

### D4 — The empty/uncalibrated-policy trap, lifted verbatim

`evaluate_receipt_gate` checks `!policy.calibrated ||
(allowed_verdicts.is_empty() && allowed_actions.is_empty())` before
evaluating a single rule, returning `GateOutcome::Untested`. Lifted
directly from `fornax_bench::gate::evaluate_gate`'s identical fix for the
same `Iterator::all`-over-empty-set vacuous-`Pass` failure mode. The
committed `uncalibrated-policy.json` fixture exercises this in the real
CLI e2e test.

### D5 — Default gate policy (owner decision, FORNX-350)

`ReceiptGatePolicy::require_proceed_no_critical_gaps()` blocks by default
only on `EvidenceGapKind::NoEvidenceAtAll`/`UnresolvedConflict`/
`AllVotesDiscounted` — the gaps judged unambiguously critical.
`IndependenceUnverified`/`SingleSourceCorroboration`/`StaleSupport` are
reported in the receipt's own `coverage.gaps` but are **not** default
blockers: no shipped sensor stamps `correlation_group` yet, so making
`IndependenceUnverified` a default hard blocker would reject nearly every
real finding, turning an evidence-quality signal into an unusable default
policy. `require_signature: false` is the honest default given D2's scope
— a high-assurance deployment can set it once it controls its own trust
store (`FORNAX_RECEIPT_TRUST_STORE` / `<home>/receipt-trust.json`, mirroring
`fornax_types::policy::trust_store`'s precedence exactly).

### D6 — No revocation service

Real-time revocation needs network infrastructure outside this codebase's
local-first critical path (ADR-0001 D2). The existing policy revocation
mechanism (`docs/adr/0009-policy-revocation-and-emergency-control.md`) is a
*signed list imported from a file*, not a live service — `fornax-receipt`
does not build a stub seam for one. Freshness is scoped to what is honestly
buildable offline: a declared `not_after` plus a clock-skew tolerance
(`fornax-receipt::freshness`). `NoExpiryDeclared` is its own state, never
folded into "fresh forever."

## What is committed, and what is deliberately not

`crates/fornax-cli/fixtures/receipts/`:

- `uncalibrated-policy.json` — `{"calibrated": false, ...}`, proving D4
  end-to-end against the real CLI binary.
- `require-signature-policy.json` — `require_signature: true`, proving an
  unsigned receipt `Hold`s (never `Accept`s or silently passes) under a
  stricter policy.

No signed-receipt fixture is committed: doing so would require generating
and shipping a real (even if test-only) Ed25519 keypair artifact, which
adds no coverage `fornax_types::receipt`'s own unit tests (a `#[cfg(test)]`
signer, exercising the identical `verify_signed_envelope` code path) don't
already provide.

## CI

A new `receipt-gate` job in `.github/workflows/ci.yml`, cloned from
FORNX-344's `integrity-lab` job: path-filtered to this ticket's own
dependency surface, runs `cargo test -p fornax-receipt -p fornax-cli
--test receipt_cli_e2e` (never `--workspace`), and is **not** a required
status check on `main` branch protection — only `rust` is. Promoting it is
an explicit, deferred, owner-only decision, same as `integrity-lab`'s.

## AC-by-AC honest status

| AC | Status |
|---|---|
| Same finding generates a deterministic versioned receipt, inspectable offline | Closed — `canonical_bytes`/`digest_of`/`derive_id`, byte-identical across repeat `issue_receipt` calls; `fornax receipt verify` is entirely file/argument-driven with an offline-reachability test |
| Tampering with protected fields detected by digest/signature when enabled | Closed, with a stated limit — digest catches accidental/naive edits (recompute-and-reject on deserialize); only a verified signature is adversarial tamper-evidence, and no production signer exists in this ticket (D2) |
| Missing/raw-local evidence stays explicit without forcing source/prompts in | Closed — `EmbedPolicy::ReferenceOnly` is the only variant; every evidence item is a reference plus a `payload_fingerprint`, never the raw payload; claim text is fingerprinted only after redaction |
| Stale/expired receipt cannot silently pass a time-sensitive gate | Partial — expiry/freshness is closed and fail-closed (`NoExpiryDeclared` → `Hold` under the default policy); real-time revocation is not closeable offline (D6) |
| At least one real CI/GitHub/deployment-style consumer accepts valid, rejects invalid/stale/insufficient | Closed — `fornax receipt verify`'s 0/10/11/12 exit contract, 2 committed fixtures, a real-binary e2e test, and the `receipt-gate` CI job |
| Docs state authenticity/integrity ≠ semantic truth | Closed — this ADR's lead section, `fornax_receipt`'s crate docs, and `docs/receipt-consumer-guide.md` |

## Deferred, not done

- Production receipt signing — explicitly out of scope (D2); needs its own
  ticket for key ownership/provisioning/storage/rotation/revocation/
  compromise recovery.
- Real-time revocation — needs network infrastructure this codebase's
  local-first critical path does not have (D6).
- A live `/api/receipt` daemon route — `receipt issue` is CLI + store-direct
  only in this ticket, matching `corpus`/`timeline`/`audit`'s precedent.
