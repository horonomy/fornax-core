# ADR 0009: Policy revocation and emergency control

Status: Accepted
Date: 2026-09-03
Jira: FORNX-123 (child of FORNX-69, Stage-7/v0.6.0)

## Context

ADR-0007 (FORNX-118) named "no revocation" as residual risk #3: the only
lever available to stop a validly-signed bundle from being trusted was key
retirement via a `TrustedKey`'s `not_after`, which retires *every* bundle
that key ever signed, not one specific compromised artifact. ADR-0008
(FORNX-119) built the local cache and activation machinery but did not
close that gap either — it names it again in its own "honest partial
closure" section. FORNX-123 is the fornax-core half of a cross-repo,
admin-triggered "emergency policy control" capability: an operator
discovers a published bundle was wrong (compromised signing key, a policy
that shipped with a bug, a revision that leaks something it shouldn't) and
needs a way to say "that specific artifact must never be trusted again" —
independent of, and faster than, publishing a corrected bundle and waiting
for every device's normal cache-refresh cycle. `fornax-cloud` implements
the admin-triggered side (building revocation artifacts) in parallel, in a
separate repo; this document is the single authority for the wire contract
between them.

## Decision

### A new, separately-signed artifact type — not a bundle field

Revocation is `SignedRevocationList`, its own top-level artifact, not a
field added to `SignedPolicyBundle`. Three reasons converge on this:

1. **A revoked bundle's signature is still perfectly valid.** No check
   inside `verify_bundle` can ever detect revocation — the entire point is
   that the artifact was correctly signed and is being un-trusted anyway,
   for a reason external to its own signature. Bolting a revocation flag
   onto the bundle schema would suggest the opposite: that some future
   `verify_bundle` change could catch it. It cannot, by construction.
2. **Different signing domain, different producer cadence.** A bundle
   publish and a revocation are different events with different urgency
   (revocation is the "break glass" path) and should not force a
   `bundle_schema_version` bump on `fornax-cloud`'s bundle producer just
   because the revocation shape needs to evolve, or vice versa.
3. **Different sequence space.** See below.

`SignedRevocationList`/`RevocationPayload`/`RevocationEntry`/
`RevocationTarget` (`crates/fornax-types/src/policy/revocation.rs`) are the
canonical wire shapes:

```
SignedRevocationList {
    revocation_schema_version: u32,
    payload_b64: String,          // base64 of the exact signed RevocationPayload bytes
    signatures: [BundleSignature], // reused verbatim from bundle.rs
}

RevocationPayload {                // parsed only after signature verification
    revocation_schema_version: u32,
    issuer: String,
    sequence: u64,                 // per-issuer, DISJOINT from policy_sequence_high_water
    issued_at: String,             // RFC3339
    entries: [RevocationEntry],    // the COMPLETE current set, never a delta
}

RevocationEntry {
    target: RevocationTarget,      // { target_kind: "revision_digest" | "payload_digest", digest }
    revoked_at: String,            // RFC3339
    reason: String,                // non-empty, enforced at verify time
    audit_ref: Option<String>,
    superseded_by: Option<RevisionDigest>,
}
```

`RevocationTarget` is internally tagged on `target_kind` with a
`#[serde(other)]` `Unrecognized` tail: one entry naming a `target_kind` a
given binary doesn't understand yet must never make the whole list
unparseable. It is counted (`RevocationSet::unrecognized_entry_count`),
surfaced as a `PolicyRevocationEntryNotUnderstood` warning, and is
un-actionable but never fatal to the rest of the list — the same
forward-compat discipline ADR-0006 established for `ActionClass`/
`PolicyFieldId`'s own `Unrecognized` tails.

### Signing domain: `REVOCATION_SIGNING_DOMAIN`

```rust
pub const REVOCATION_SIGNING_DOMAIN: &[u8] = b"fornax-policy-revocation/v1\n";
```

Distinct from `BUNDLE_SIGNING_DOMAIN` (`b"fornax-policy-bundle/v1\n"`).
Domain separation is a real, tested boundary here, not decoration: a
revocation payload signed under the bundle's domain is rejected by
`verify_revocation_list`, and a bundle payload signed under the
revocation's domain is rejected by `verify_bundle` — both directions
proven in `revocation_tests.rs`'s T88. Without this, a signature valid for
one artifact type could be replayed as if it verified the other, since
both reuse the same `ed25519_dalek::Signature::verify_strict` call and (in
the common case) the same signing keys.

### Reused, not duplicated: the extracted envelope-verification helper

`verify_bundle`'s envelope/signature-verification steps (signature-count
bounds, strict base64 decode + size bound, the per-signature loop with its
4-level precedence — `verified` > `SignatureInvalid` (tampering, a trusted
current key whose signature simply doesn't check out) > `first_skip_reason`
(deterministic: the first known-but-unusable key's reason) > `UnknownKeyId`
— and the "loop always runs to completion, never returns early on the
first unusable key" rule that makes D4 key rotation work) are identical
regardless of which artifact type is being verified. `bundle.rs` now
exposes a `pub(super)` `verify_signed_envelope(payload_b64, signatures,
domain, max_payload_bytes, trusted, now)` helper, parameterized by domain,
returning `Result<VerifiedEnvelope, EnvelopeVerificationError>` —
deliberately **not** `BundleRejection`, so that `verify_revocation_list`
does not inherit a rejection variant (like a `tolerance_seconds`-bearing
expiry check) for a validation this function never performs. Both
`verify_bundle` and `verify_revocation_list` map `EnvelopeVerificationError`
1:1 into their own exhaustive rejection enum. This refactor is
behavior-preserving by construction and by test: the full FORNX-118
acceptance suite (T28–T53 in `policy/tests.rs`) passes with the identical
pass/ignore count before and after the extraction.

### Enforced at the cache layer, never inside `verify_bundle`

This is the load-bearing design decision, and it is directly testable
(T78, "the trap test," named first): a bundle that `verify_bundle` still
**accepts** — valid signature, unexpired, trusted current key — must be
**rejected** on activation with `ActivationRejection::Revoked`. If that
test can be made to pass by any change inside `bundle.rs`, the design was
implemented wrong.

`RevocationSet::hit(revision_digest, payload_digest)` is checked **first**
in `evaluate_activation`, before the pre-existing lineage/issuer check —
"must never be trusted again" outranks every other rejection reason,
including a legitimate sequence advance. Symmetrically,
`try_generation_usable` (the cache's reload path) checks
`RevocationSet::hit` **first** in its per-member loop, before the envelope
bytes are even read — a revoked member makes the whole generation
unusable, preserving the pre-existing "a generation is never served
partially loaded" invariant from ADR-0008.

Two digest kinds are checked, keyed independently:

- `revision_digest` — catches every envelope that ever wraps the same
  underlying revision content, including a bundle "re-wrapped" under a
  different `bundle_id`/`sequence` (same content, different transmitted
  bytes, therefore a different `payload_digest` but the same
  `revision_digest`).
- `payload_digest` — catches one specific transmitted artifact exactly,
  useful when an operator has a specific leaked/compromised envelope in
  hand and wants to name it precisely without asserting anything about
  its revision content being bad per se.

### Sticky, union-only, no expiry — deliberately

Once a digest is revoked locally, it stays revoked:

- **Sticky**: nothing in this design ever un-revokes a digest. Not a
  newer revocation list, not a trust-store edit that removes the signing
  key that originally signed the now-revoked bundle (T84 proves both
  directions — remove the key, still revoked; restore the key, still
  revoked), not `rollback_policy_to_last_known_good` (T91 — rolling back
  into a revoked last-known-good does not resurrect it).
- **Union-only**: `evaluate_revocation_ingest` computes new entries as a
  set difference against what is already stored. A newer list from the
  same issuer that omits a previously-seen entry never removes it (T86).
  `entries` in the wire payload is always the complete current set, never
  a delta — the union-only rule lives in the ingest function, not in an
  assumption about delta encoding.
- **No expiry**: no `not_before`/`expires_at` exists on a revocation list
  or on an individual entry, and `verify_revocation_list` performs no
  window check at all. An expiring revocation would let a bad artifact
  resurrect itself once the clock passed a date that the artifact's own
  signed content — or a merely misconfigured issuer — controls the shape
  of. A revocation is not a lease; it is a permanent local fact once
  observed.

### Sequence: per-issuer, disjoint from `policy_sequence_high_water`

`RevocationPayload.sequence` is a per-issuer monotonic counter,
**completely disjoint** from `policy_sequence_high_water`'s
`(issuer, policy_id)`-keyed counter. A revocation list has no `policy_id`
at all — it names digests directly, across whatever lineage they came
from — so conflating the two counters would be a category error, not a
naming collision. `evaluate_revocation_ingest`'s rule:
`sequence < high_water` rejects (`SequenceNotAdvanced`);
`sequence == high_water` is `AlreadyCurrent` (idempotent re-import, no
duplicate rows — T85); `sequence > high_water` computes the new-entries
set difference and applies.

### Issuer convention and cross-tenant isolation caveat

Proposed issuer convention: `fornax-cloud:<organization_id>` — stable,
tenant-scoped, and makes a future `IssuerMismatchForLineage`-style check
meaningful if one is ever added for revocation (none exists today; nothing
in this ticket needs it, since revocation intentionally has no
`policy_id`-keyed lineage concept to protect).

**Issuer-agnostic on the device, by design, with a named caveat.** A
revocation entry from *any* trusted issuer revokes the named digest —
`RevocationSet` does not partition by issuer when answering `hit()`. This
is a deliberate simplification: cross-tenant isolation (issuer A cannot
revoke issuer B's bundles) is enforced by `fornax-cloud`'s own
authorization at publish time — the cloud only lets an organization's
admin build a revocation list naming that organization's own artifacts. It
is not device-verifiable, and this design does not attempt to fake that
verification locally. A device that somehow received a revocation list
from an issuer it should not have trusted for that purpose has a larger
problem (its trust store itself is misconfigured) that this ticket does
not solve and is not scoped to solve.

### `PolicyPosture`: converting a silent fail-open into a loud one

**A real, pre-existing gap this design surfaces, not introduces, and does
not silently fix.** When a generation becomes wholly unusable — by
revocation or by any other cause ADR-0008 already covers — `resolve()`
returns baseline, whose `enforcement_rules` is an **empty** `Vec`.
`EffectivePolicy::enforcement_outcome_for` therefore returns `ObserveOnly`
for every action class, because the FORNX-119 staleness floors are
rule-anchored (`staleness_floor` only ever tightens an existing rule's
outcome) and there are zero rules to anchor to. **Revocation does not, on
its own, tighten enforcement — it only stops the revoked artifact from
being loaded/trusted.** T93 ("the honest test") pins this as tested
behavior: with `usable = []` and `ever_configured = true`,
`enforcement_outcome_for` reads `ObserveOnly` for every
action-class/verdict pair.

This ticket does not invent a default per-action-class risk assumption to
paper over that gap — doing so would contradict ADR-0006's fail-open
selector philosophy and `action_classification.rs`'s explicit "never a
silently invented risk assumption" discipline. Instead, `PolicyPosture` —

```rust
enum PolicyPosture { Normal, Degraded { reason: PolicyDegradationReason } }
enum PolicyDegradationReason { Revoked, Unverifiable, TrustStoreUnavailable, NoUsableGeneration }
```

— makes the condition loud and machine-readable: `compute_posture`
degrades only when `usable` is actually empty (a successful fallback to a
clean last-known-good, even after a revocation forced it, is `Normal` —
something is still being enforced), with an explicit precedence when
multiple diagnostic causes are present at once (`Revoked` >
`Unverifiable` > `TrustStoreUnavailable` > `NoUsableGeneration` — the
most-specific cause wins), and treats a fresh install that has never had a
bundle imported as `Normal`, mirroring `freshness`'s own `Unconfigured`
tier philosophy: no penalty is invented merely because nothing has ever
been configured. **Wiring `PolicyPosture` into an actual enforcement
decision is explicitly out of this ticket's scope** — a future
enforcement-wiring ticket's job; this ticket only computes and surfaces
the posture.

### Store layer: three tables, an append-only artifact log

Migration `0009_policy_revocation.sql` adds three tables — a deviation
from the design sketch that showed only two
(`policy_revocation_state`/`policy_revocations`) but required, in prose,
an append-only artifacts table so `fornax policy status` has real
provenance and "immutable and reconstructable" (this ticket's AC5) is
literally true on-device, not merely asserted:

- `policy_revocation_artifacts(issuer, sequence, envelope, received_at)` —
  append-only, the signed envelope bytes exactly as received, one row per
  `(issuer, sequence)` ever successfully ingested. Never re-verified after
  ingest (the sticky rule means there is no reason to), but gives a real
  audit trail.
- `policy_revocation_state(issuer, max_sequence, last_payload_digest,
  last_seen_at, unrecognized_entry_count)` — the latest-pointer table, one
  row per issuer, never lowered. `unrecognized_entry_count` accumulates
  across every list ever ingested from that issuer, since an
  `Unrecognized`-kind entry carries no digest to key an actionable row on
  and is therefore never given a row in the next table.
- `policy_revocations(issuer, target_kind, target_digest, reason,
  revoked_at, audit_ref, superseded_by, first_seen_sequence,
  first_seen_at)` — the union-only, sticky set. `INSERT OR IGNORE` keyed
  on `(issuer, target_kind, target_digest)`: a row is written once, the
  first time a digest is observed, and never updated or deleted
  afterward.

`Store::submit_policy_revocation` mirrors `Store::submit_policy_bundle`'s
normative order and crash-safety argument exactly (ADR-0008's own section
on this is unchanged and still applies verbatim): verify **outside** any
transaction (an invalid list never opens one) → `BEGIN IMMEDIATE` → load
state → `evaluate_revocation_ingest` → persist → `COMMIT`. T89 proves this
the same way ADR-0008's T71 did — open a transaction, write an uncommitted
competing update, drop the connection without committing, reopen: prior
state is byte-for-byte intact.

`rollback_policy_to_last_known_good` is **not modified** by this ticket.
Revocation does not need it to change: the load path already handles a
revoked last-known-good correctly on its own (falls through to
`usable = []`, per T91), and `policy_sequence_high_water` remains
completely untouched by anything in this ticket (disjoint counter,
different table, as above).

### Surfaces

- `IngestMessage::PolicyRevocation { envelope: String }` — additive
  variant, the same fire-and-forget UDS path as `PolicyBundle`.
  `handle_policy_revocation_ingest` mirrors
  `handle_policy_bundle_ingest`'s structure and refreshes
  `AppState.policy` after every successful `Applied`/`AlreadyCurrent`
  outcome, exactly like the bundle path — this is what makes revocation
  take effect immediately in a running daemon rather than at next
  restart.
- `fornax policy import <path>` dispatches on the artifact's own
  top-level shape (`bundle_schema_version` vs `revocation_schema_version`)
  and sends the matching `IngestMessage` variant — an emergency responder
  must not have to remember which subcommand imports which artifact type
  during an incident. An ambiguous (both keys present) or unrecognized
  (neither key present) shape refuses with a clear message rather than
  guessing.
- `GET /api/policy` gains `revocations: { entry_count,
  unrecognized_entry_count, max_sequence_by_issuer }` and `posture`,
  additive to the existing response shape. `fornax policy status` renders
  both as their own lines — posture is never collapsed into the
  pre-existing `degraded` boolean, which answers a different question
  (any diagnostic present, or merely serving from last-known-good) than
  posture does (is anything actually being enforced right now).
- `DiagnosticCode` gains `PolicyCacheRevoked` (Error),
  `PolicyRevocationEntryNotUnderstood` (Warning), and
  `PolicyRevocationRejected` (Warning), additive to the closed enum — the
  same cross-repo-consumer caveat ADR-0008 already noted for its own
  additions applies here: a consumer built against a prior version of this
  enum (e.g. `fornax-cloud`'s authoring UI) must be updated to handle
  these.

### Local-attacker boundary — unchanged

This design does not invent a new defense against a local attacker with
`$FORNAX_HOME` write access. ADR-0008's existing section on this boundary
applies verbatim: anyone who can write to the local SQLite file can already
do worse than un-revoke a digest. Revocation's sticky/union-only guarantees
are about a *remote* issuer/attacker's ability to un-revoke something via
the normal ingest path, not about local filesystem tampering.

## Honest limits (named, not hidden)

1. **There is no cloud→device delivery channel yet.** "Emergency" response
   time today is however fast a human runs `fornax policy import` on each
   device. This is the biggest gap and the natural next ticket — a push or
   poll mechanism that gets a revocation list onto a device without a
   human in the loop per device.
2. **An offline device keeps using a revoked policy until it reconnects.**
   Forced by ADR-0001 D2 (no cloud dependency on the local critical path,
   local-first by design) — not fixable within this design, and not a
   defect of this ticket specifically. A device that never talks to
   anything cannot learn anything it wasn't told locally.
3. **A transport attacker who delivers bundles but selectively drops
   revocations defeats revocation undetectably.** Nothing in a bundle
   payload today attests to "the minimum revocation sequence this bundle's
   issuer expects you to already have" — an attacker (or an unreliable
   network) that lets bundles through while silently dropping revocation
   lists leaves a device fully functional and fully unaware anything was
   revoked. The fix — an issuer-attested `min_revocation_sequence` field
   inside the *signed bundle payload*, checked at activation time against
   the device's own revocation high-water mark — is a concrete, named,
   deferred requirement. It needs a `bundle_schema_version` bump, and no
   bundle producer exists anywhere yet (see out-of-scope below), so there
   is nothing to retrofit it into today.
4. **The FORNX-119 gap this ticket surfaces is inherited, not
   introduced.** Full cache loss (by any cause — expiry, key retirement,
   corruption, or now revocation) degrades enforcement to `ObserveOnly`
   for every action class, never to `Block`, because the staleness floors
   are rule-anchored and baseline carries zero rules. This was already
   true before FORNX-123; this ticket's contribution is `PolicyPosture`,
   which makes the condition observable instead of silent — it does not
   change what enforcement actually does.

## Closing ADR-0007's residual risk #3

ADR-0007 listed "no revocation" as an open residual risk, with the only
lever being wholesale key retirement. This ticket closes it **for
artifacts that reach a device**: a specific compromised bundle (by
`revision_digest` or `payload_digest`) can now be named and permanently
un-trusted without retiring the key that signed it, which may have signed
many other still-good bundles. It remains **open** for the two cases named
above: withholding (honest limit #3) and offline devices (honest limit
#2) — both are inherent to the architecture (ADR-0001 D2's local-first
posture, and the absence of any transport-level delivery guarantee), not
oversights of this specific ticket.

## Out of scope (prerequisite follow-up tickets, not built here)

- **Cloud→device policy distribution channel** — the biggest named gap
  (honest limit #1). **Closed by ADR-0010 (FORNX-311)** on the device
  (fornax-core) side; the fornax-cloud fetch-endpoint half lands as a
  separate PR in that repo.
- **A `SignedPolicyBundle` producer in `fornax-cloud`** — a separate
  ticket. `fornax-cloud`'s FORNX-123 half builds revocation artifacts
  only, not policy bundle artifacts; no bundle producer exists anywhere
  in either repo yet. **Closed by fornax-cloud's own FORNX-311 PR** (out
  of this repo) — ADR-0010 references but does not build or review it.
- **Enforcement wiring that consumes `PolicyPosture`/`EffectivePolicy`'s
  outcome to actually change what gets blocked** — a future
  enforcement-wiring ticket.
- **`min_revocation_sequence` anti-withholding binding** (honest limit
  #3) — needs a `bundle_schema_version` bump and a bundle producer that
  doesn't exist yet.
- **Human-authenticated audit attribution** for who triggered a
  revocation — currently `device_id`-only provenance, pending FORNX-111
  (human-auth) elsewhere in the platform.

## Test coverage

`crates/fornax-types/src/policy/revocation_tests.rs`, T78 onward
(continuing `policy/tests.rs`/`policy/cache_tests.rs`'s T1–T70):
T78 (the trap test); T82/T83 (payload_digest vs. revision_digest
revocation reach); T86 (sequence discipline, union-only); T87 (the
`#[serde(other)]` forward-compat parse half); T88 (domain separation, both
directions); T92 (single-byte-mutation property test); T93 (the honest
test). `crates/fornax-store/src/policy_cache.rs`'s own test module, T79-T81
and T84/T85/T87(store half)/T89/T91 (continuing its own T71–T77): the
store-integration and crash-safety scenarios that need a real
SQLite-backed `Store` — cached-then-revoked; fallback to a clean
last-known-good; revoked-in-both degrades posture; stickiness across a
trust-store edit in both directions; idempotent re-import with a row-count
proof of no duplication; the unrecognized-entry persistence half; crash
safety; and rollback into a revoked last-known-good never resurrecting it.
The full FORNX-118 acceptance suite (T28–T53) is the regression gate for
the `verify_signed_envelope` extraction and passes unmodified.
