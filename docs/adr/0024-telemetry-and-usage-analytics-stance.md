# ADR 0024: Telemetry and usage-analytics stance

Status: accepted (documents an existing, already-implemented design stance;
FORNX-366, GA prep)

## Context

Fornax's GA readiness scope (FORNX-148) calls for "GA telemetry/product
analytics that respect privacy boundaries." A repo survey ahead of this ADR
found **no product-usage telemetry implementation and no dedicated ADR** —
but it also found the underlying design stance already exists, is
consistent, and is stated in multiple places. This ADR consolidates that
existing stance into one canonical, discoverable document; it does not
introduce any new data collection.

## Decision

**Fornax collects no product-usage telemetry by default.** This is stated
today in `README.md`: "there is no telemetry and no hosted Beta/production
service to opt out of, because none exists at this version," and enforced
in code by three independent, default-closed opt-in gates in
`crates/fornax-types/src/privacy.rs`:

| Gate | Function | Default | Covers |
|---|---|---|---|
| Cloud sync | `cloud_sync_allowed()` | `false` (`FORNAX_CLOUD_SYNC_ENABLED`) | Whether any Fornax-originated data may leave this machine at all. |
| Longitudinal reliability collection | `longitudinal_reliability_collection_allowed()` | `false` (`FORNAX_LONGITUDINAL_COLLECTION_ENABLED`) | Whether raw per-session local evidence may be aggregated *across sessions* into reliability statistics (FORNX-106). |
| Corpus mining | `corpus_mining_allowed()` | `false` (`FORNAX_CORPUS_MINING_ENABLED`) | Whether real sessions may be mined into sanitized `fornax-corpus` candidate cases (FORNX-341). |

Each gate answers a distinct question — "has the user explicitly opted in
to something beyond ordinary local operation?" — and none of the three is
implied by another; a user can enable one without the others. See the
module doc in `crates/fornax-types/src/privacy.rs` for the full rationale
behind keeping them separate, and `docs/privacy-redaction-policy.md` for
the broader redaction/local-first policy these gates sit inside ("cloud
sync is opt-in, never assumed").

None of these three gates constitute product-usage analytics (page views,
feature-usage counters, crash reporting, etc.) — no such mechanism exists
in `fornax-core` today. If GA introduces one, it must be a new, explicitly
opt-in gate following this same shape, documented as a change to this ADR,
not folded silently into an existing gate.

## Explicit boundary with FORNX-327

FORNX-327 ("[Website Analytics] Integrate GA4 web stream into
fornax.horo.run") is a separate, already-in-progress workstream: GA4 on the
**marketing website** (`fornax-website`), which is a different system from
the local-first Rust runtime this ADR covers. This ADR does not affect, and
is not affected by, FORNX-327's scope. If either surface's stance changes,
update both documents rather than assuming one covers the other.

## Non-goals

- This ADR does not introduce new telemetry, analytics, or data collection.
- This ADR does not decide GA pricing/entitlement/support terms.
- This ADR does not restate `crates/fornax-types/src/privacy.rs` or
  `docs/privacy-redaction-policy.md` in full — see those directly for
  implementation and broader redaction policy detail.
