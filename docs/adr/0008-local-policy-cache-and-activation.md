# ADR 0008: Local policy cache and activation

Status: Accepted
Date: 2026-09-03
Jira: FORNX-119 (child of FORNX-69, Stage-7/v0.6.0)

## Context

FORNX-116 (ADR-0006) defined policy as immutable, digested data. FORNX-118
(ADR-0007) added signature verification (`verify_bundle`) so a bundle's
provenance can be authenticated. Neither ticket persisted anything: every
verified bundle lived only for the duration of one `resolve()` call. A
device that never re-fetches a policy has no memory of what it was told, no
defense against a rolled-back (older, previously-superseded) bundle being
replayed, and no way to detect that a previously-trusted signing key has
since been retired. FORNX-119 closes that gap: a local, crash-safe,
rollback-resistant cache of verified bundles, with an explicit contract for
what happens when cached content goes stale or a key is retired out from
under it.

## Decision

### Generations as sets, not single-revision slots

A policy **slot** (`active`/`pending`/`last_known_good`) does not point at
one revision. It points at a **generation** — an immutable set of
[`CachedBundleRef`]s, at most one per `policy_id` lineage. `resolve()`
layers multiple lineages together (an org policy and a device policy are
two different `policy_id`s, both active simultaneously); a single-revision
slot cannot express that. This is a deliberate deviation from the ticket's
literal wording, which spoke of caching "the policy" as if there were one.

`pending` is modelled — the type, the schema column, the always-null API
field — but never populated in v0.6.0. No caller exists yet for staging a
generation before promoting it; leaving the slot un-wired would be dead
code with no exerciser. A future ticket that adds a two-phase
stage-then-promote flow (e.g. for canary rollout) has the shape ready.

### Rollback defense: `(issuer, policy_id)` high-water, never per-bundle

[`SequenceHighWater`] is keyed on `(issuer, policy_id)`, not on
`bundle_id`. A rollback attack replays an **older, validly-signed** bundle
for a lineage the device has already advanced past; the defense has to
remember "the highest sequence number I have ever accepted for this
issuer's this policy," independent of which slot currently holds it. The
high-water table is a separate, independently-persisted structure from the
slots — `rollback_policy_to_last_known_good` moves the `active` pointer
back to `last_known_good` but leaves every high-water row untouched,
deliberately: if rollback also lowered the high-water mark, an attacker who
can induce a post-activation failure (forcing a rollback) could reopen the
exact downgrade window the high-water mark exists to close.

**Producer-contract assumption, unconfirmed.** This design assumes
`fornax-cloud`'s `sequence` counter is issued **per issuer**, not per
`(issuer, policy_id)` lineage and not globally across all issuers — i.e.
that two different `policy_id` lineages from the same issuer may
legitimately advance their sequence numbers independently and out of lockstep
with each other (this is exactly what T60 in `cache_tests.rs` proves:
`issuer-a` emitting `p1@seq7` then `p2@seq6` must both be accepted). If
`fornax-cloud` instead issues one global monotonically-increasing sequence
counter per issuer that all of that issuer's policy lineages share, this
cache's behavior is still correct (a shared global counter is a strict
subset of "sequence is monotonic per lineage"), but the "cross-lineage
independence" property this cache advertises would be vacuous — every
lineage from that issuer would happen to advance in lockstep anyway. This
repo has no visibility into `fornax-cloud`'s implementation; confirm the
producer's actual sequence-issuance contract before relying on cross-lineage
independence as a load-bearing property in a future ticket.

### Rewind rationale and its bounded residual risk

On reload, an expired cached bundle is re-verified once at the real clock,
and — **only** if the specific failure is `BundleExpired` — a second time
at the `expires_at` value carried by that rejection. That value is
authenticated: it came out of the signed payload bytes, and `verify_bundle`
confirms it (step 9, after signature verification) before ever returning
the `BundleExpired` error. Rewinding to it is not trusting an unauthenticated
clock; it is asking "was this bundle ever legitimately usable," which the
signature already answers. Any other failure — `KeyRetired`, `UnknownKeyId`,
`SignatureInvalid`, `MalformedEnvelope`, tampering of any kind — gets no
rewind. This is what makes key retirement a real revocation lever: a key
pulled from the trust store after a bundle was cached makes that bundle
permanently unusable on the next reload, with no rewind able to resurrect it.

**Residual risk.** The one-time rewind means a bundle whose `expires_at`
has passed is briefly treated as "was once valid" rather than immediately
discarded — this is intentional (see "expiry never discards content"
below), but it does mean a device that never talks to the network again
will keep serving a single expired snapshot indefinitely at content level,
with only the compiled-in staleness floors tightening enforcement over
time. This is the accepted trade-off of a purely local, offline-first cache:
availability over hard expiry, with policy-authored staleness floors as the
compensating control.

### Freshness table and floor table

Freshness is evaluated per `(member, RiskClass)`, not once per member:

```
tier(member, R) = GraceExpired  if now > confirmed_at + max_age(R) + offline_grace
                 = Stale         if now > confirmed_at + max_age(R)  OR  now > expires_at
                 = Fresh         otherwise
```

`confirmed_at` — not `first_activated_at` — is the freshness clock, and it
only advances on an explicit `Confirm` (a re-submission of the same
sequence and bytes), never on mere re-activation of a different lineage in
the same generation. A generation's tier for a given `RiskClass` is the
**strictest** tier across its members (`RiskClassTiers::meet`, per-field
max) — one stale lineage degrades the whole generation's posture for that
risk class, it does not stay siloed.

Staleness never discards cached content. Instead it ratchets a **compiled-in**
enforcement floor — never policy-authored, because a stale policy must
never be able to lower its own floor:

| RiskClass | Fresh/Unconfigured | Stale | GraceExpired |
|---|---|---|---|
| Low       | — | — | — |
| Elevated  | — | — | Warn |
| High      | — | Warn | Warn |
| Critical  | — | Warn | Block |

`effective_outcome = max(resolved, floor)`, using `EnforcementOutcome`'s
existing strictness `Ord` — monotone, staleness only ever tightens
(`cache_tests.rs`'s T68 proves this as a property over every
`(RiskClass, FreshnessTier, EnforcementOutcome)` triple). `Unconfigured`
(no cache has ever been populated) carries no floor at all, for a different
reason than `Fresh`: a fresh install must never silently acquire blocking
power it was never given a policy to justify.

### SQLite vs. a file store, and the trade-off it accepts

`retention.rs` already established the precedent of persisting a
`fornax-types` domain model as `fornax-store` SQLite tables rather than
loose files. The same reasoning applies here, more sharply: activation must
be atomic across several related writes (an envelope row, a generation
row, N member rows, the slot pointers, and a high-water upsert) — a crash
between two of those writes must never leave a generation half-written or a
slot pointing at a generation with no rows. SQLite's transaction semantics
(`BEGIN IMMEDIATE` ... `COMMIT`) give this for free; a hand-rolled
file-based store would need to reinvent atomic multi-file rename/fsync
choreography to get the same guarantee, and get it exactly right under
every crash point.

**The trade-off this accepts.** The policy cache now shares a durability
domain with the evidence store — `agent_events`/`claims`/`evidence`/
`findings` and the policy cache tables live in the same `fornax.db` file,
the same WAL, the same connection pool. A corruption event or a lock
contention issue affecting one affects the other. This was judged
acceptable: both are local, single-process, single-user data; there was no
existing isolation boundary between them to preserve, and splitting into a
second SQLite file would only relocate the atomicity problem to "how do two
separate databases commit together," not solve it.

### Crash-safety argument

`Store::submit_policy_bundle` performs step 1 (`verify_bundle`) **before**
opening any transaction — an invalid bundle never opens a transaction, so
it can never touch `last_known_good` or anything else (`cache_tests.rs`'s
T55, `policy_cache.rs`'s persistence tests). Once verification succeeds,
one `BEGIN IMMEDIATE` transaction covers: loading current state (serializing
concurrent submits against each other), `evaluate_activation`'s decision,
and every write the decision implies. A crash before `COMMIT` leaves the
previous generation wholly intact — SQLite rolls back an uncommitted
transaction the moment its connection closes, which is exactly what a real
crash does to an open connection. A crash after `COMMIT` leaves the new
generation wholly intact. There is no third, half-written state
(`policy_cache.rs`'s T71 proves this directly: a transaction is opened,
written to, and the connection dropped without a commit; reopening the
store shows the prior generation and un-advanced high-water, byte for
byte).

### Threat-model boundary

This cache defends against:

- **A transport attacker** who can intercept, delay, replay, or attempt to
  inject a bundle in transit — signature verification (ADR-0007) and the
  sequence high-water mark (this ADR) both apply regardless of transport.
- **Silent staleness** — a device that stops receiving updates does not
  silently keep enforcing yesterday's policy at yesterday's strictness
  forever; the freshness/floor mechanism visibly and monotonically
  tightens enforcement the longer contact has been lost.

This cache does **not** defend against:

- **A local attacker with `$FORNAX_HOME` write access.** Anyone who can
  write to the SQLite file directly can insert arbitrary rows — including a
  fabricated high-water row, a fabricated slot pointer, or a stored
  envelope whose bytes happen to still verify against a key still in the
  trust store (if such bytes exist). This cache's guarantees are about
  bundles that arrive over the ingest channel and are evaluated through
  `evaluate_activation`/`submit_policy_bundle`; a local attacker with raw
  file access bypasses that evaluation path entirely, the same way local
  root access defeats most application-level integrity mechanisms. This
  matches ADR-0001's threat model, which has never claimed protection
  against a local attacker with equivalent privilege to the daemon itself.

### Honest partial closure of ADR-0007's two residual risks

ADR-0007 named two residual risks it left open for this ticket:

**Rollback — closed.** The `(issuer, policy_id)` sequence high-water mark,
persisted independently of the slots and never lowered (not even by
rollback), is a real, tested defense (`cache_tests.rs` T56-T59, T61;
`policy_cache.rs` T77). A validly-signed but superseded bundle can no
longer be replayed to downgrade a device that has already advanced past it.

**Binding-omission — only partially closed, and this is worth stating
plainly rather than implying otherwise.** Per-lineage freshness clocks mean
that withholding updates to an **already-known** lineage is observable: if
a device has previously cached a `policy_id`, and the issuer stops sending
new bundles for it, that lineage's member clock keeps advancing toward
`Stale`/`GraceExpired`, which visibly degrades enforcement for the risk
classes that lineage governs. That is a real, working detection mechanism
for "an issuer went quiet on a lineage I already know about."

It does **not** detect withholding at **first contact**. If an issuer
should have told a device about `policy_id` B (a lineage the device has
never heard of) and simply never does, there is no local signal that
anything is missing — the wire format carries no signed manifest of
"the complete set of policy_ids this device should expect." A device with
zero cached lineages and a device that is missing one lineage out of three
it should have look identical from the inside: both show `ever_configured`
possibly `true`, both show whatever lineages they *do* have as `Fresh`, and
neither shows an error for the lineage it doesn't know exists. Closing this
fully would require a signed, versioned manifest of expected `policy_id`s
per device/scope — out of scope for this ticket, and worth flagging as a
concrete requirement for whatever ticket eventually addresses it.

### Additive `DiagnosticCode` variants

Seven variants were added to `DiagnosticCode`: `PolicyCacheStale`,
`PolicyCacheExpired`, `PolicyCacheUnverifiable`, `PolicyCacheUnavailable`,
`PolicyRollbackRejected`, `PolicyIssuerMismatch`, `TrustStoreUnavailable`.
`DiagnosticCode` is a closed enum (no `Unrecognized` tail, by design — see
ADR-0006) — a cross-repo consumer built against a prior version of this
enum (e.g. `fornax-cloud`'s authoring UI, if it ever deserializes
`DiagnosticCode` values this crate emits) must be updated to at least
tolerate these new variants before upgrading to a `fornax-core` version
that can emit them. This is the standard cost of a closed diagnostic enum
gaining new members; it is not a wire-format break for anything that only
serializes (never deserializes into a Rust enum) these values, which is the
common case (a browser dashboard, a log line).

### FORNX-121 refresh-transport prerequisite (a real, named footgun)

The staleness floors defined here ship **inert** in v0.6.0. Nothing calls
`effective_outcome`/`EffectivePolicy::enforcement_outcome_for` from any real
enforcement decision point yet — FORNX-121 (already merged) built the
`EnforcementOutcome`/`VerdictOutcomes` machinery this ADR's floors compose
with, but did not wire staleness into it. A future ticket must do that
wiring.

**The footgun to name now, not fix now:** with file-import (`fornax policy
import`) as the *only* ingress this ticket provides, `confirmed_at` never
advances after a bundle's initial import — nothing re-submits the same
bundle to trigger a `Confirm`. That means every device's cached policy
marches inexorably toward `Critical = Block` on a fixed clock
(`max_age(critical) + offline_grace` after import), with no way to reset
that clock short of re-importing the exact same file by hand. Wiring the
staleness floors to real enforcement **before** a refresh transport exists
(some periodic re-fetch-and-resubmit mechanism, out of scope here) would
turn this cache from a safety mechanism into a ticking outage timer for
every device that uses it. The correct sequencing is: build a refresh
transport first, then wire enforcement to consume these floors.

**Closed by ADR-0010 (FORNX-311).** A background policy poll transport now
exists; the refresh-transport prerequisite named above is satisfied.
Enforcement wiring itself remains a separate, still-open future ticket.

## Consequences

- Local policy state now survives a daemon restart and a period of offline
  operation, degrading enforcement predictably rather than either failing
  open forever or failing closed the moment connectivity is lost.
- Key retirement is now a real, working revocation lever against
  previously-cached content, not just against newly-submitted bundles.
- The policy cache and the evidence store share one SQLite file's
  durability domain — accepted, not an oversight (see above).
- Enforcement wiring, and the refresh transport that must precede it, are
  both explicitly out of scope and explicitly named as prerequisites for a
  future ticket — this ADR does not claim FORNX-119 alone makes staleness
  floors operative.
