# ADR 0011: Canonical Audit Event Model

- Status: Accepted
- Date: 2026-09-03
- Ticket: FORNX-314 (epic FORNX-20)

## Context

Fornax has two independent places that already produce audit-shaped log
lines but no shared vocabulary between them:

- `fornax-cloud`'s permission-check path
  (`backend/src/fornax_cloud_backend/core/permissions.py`) logs every
  authorization decision as free-text with `outcome=`, `subject_type=`,
  `permission=` fields — never persisted as a structured record.
- `fornax-core`'s policy revocation model
  (`crates/fornax-types/src/policy/revocation.rs`, ADR-0009) carries an
  `audit_ref: Option<String>` field on `RevocationEntry` and a matching
  `audit_ref TEXT` column on `policy_revocations`
  (`crates/fornax-store/migrations/0009_policy_revocation.sql`) that has
  never had a defined shape — it is nullable, has no foreign key, and no
  document has ever said what a non-`None` value should look like.

This ADR defines the canonical `AuditEvent` shape those two things can grow
into, and the string form `audit_ref` resolves to, without requiring either
side to be rewritten today.

Per the precedent set by ADR-0009 (`fornax-cloud` was built against that
ADR's text alone, before any Rust crate merged), **this document is written
to be a complete, standalone wire contract**. A Python engineer implementing
`fornax-cloud`'s side of this needs nothing from this repository's Rust
source to produce or consume a conforming `AuditEvent`.

## Decision

### 1. The `AuditEvent` shape

```json
{
  "schema_version": 1,
  "event_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
  "occurred_at": "2026-09-03T14:22:05Z",
  "actor": { "actor_kind": "device", "actor_id": "device-7e2a1c" },
  "action": "policy_revocation_ingested",
  "target": { "target_kind": "revocation_entry", "target_id": "sha256:ab12..." },
  "outcome": "granted",
  "export_class": "metadata",
  "correlation_id": "3fae2b41-9df0-4c1b-8f3a-1e6a2b9c9d40",
  "attributes": { "issuer": "horonomy-policy-issuer-1", "sequence": 42 }
}
```

Field-by-field:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema_version` | integer | yes | Version of this event's own wire shape. Currently `1`. See "Compatibility rules" below. |
| `event_id` | string (UUID) | yes | Stable identity for this one event. Producer-assigned, globally unique. |
| `occurred_at` | string (RFC3339) | yes | When the audited action happened, not when the event was written to storage. Matches the RFC3339-string convention used throughout this repo (`RevocationEntry.revoked_at`, `BundlePayload.issued_at`, etc.) — never a numeric epoch. |
| `actor` | `AuditActor` object | yes | Who/what performed the action. See §2. |
| `action` | `AuditAction` string | yes | What happened. See §2. |
| `target` | `AuditTarget` object | yes | What the action was performed on. See §2. |
| `outcome` | `AuditOutcome` string | yes | The result. See §2 — this is a superset of `fornax-cloud`'s existing permission-log outcome strings. |
| `export_class` | `AuditExportClass` string | yes | Which classification tier this event's own content falls into for cloud-export purposes. See §3. |
| `correlation_id` | string (UUID) or `null` | no | Links this event to other events/records produced by the same logical operation (e.g. one permission check may emit both an activation record and this audit event). `null`/absent when there is nothing to correlate. |
| `attributes` | object | no | Loosely-typed catch-all for action-specific detail. **Explicitly not an event lake** — see §5. Defaults to `{}` when absent. |

Any additional top-level key not listed above must be preserved by a
conforming implementation (never dropped) and does not by itself invalidate
the event — see "Compatibility rules."

### 2. Three enums: `AuditActor`, `AuditAction`, `AuditOutcome` (plus `AuditTarget`)

#### `AuditActor`

A tagged object, not a bare string, because an actor needs both a kind and
an identifier:

```json
{ "actor_kind": "device", "actor_id": "device-7e2a1c" }
```

`actor_kind` is one of:

| Wire tag | Meaning |
|---|---|
| `device` | A Fornax daemon instance acting under a device identity — mirrors `fornax-cloud`'s existing `PermissionSubjectType.DEVICE`. |
| `user` | A human-authenticated principal — mirrors `fornax-cloud`'s existing `PermissionSubjectType.USER`. |
| `service_token` | A non-interactive service credential (e.g. a CI integration's own token). **New in this ADR** — `fornax-cloud`'s `PermissionSubjectType` enum has only `USER` and `DEVICE` today (`backend/src/fornax_cloud_backend/models/enums.py`); no existing subject-type vocabulary covers a service-token caller, so this is a minimal net-new addition, not a duplication of something that already exists elsewhere. |
| `system` | The Fornax system itself acting with no external caller (e.g. an automatic, unattended state transition such as sticky revocation ingest). **New in this ADR**, for the same reason as `service_token` — there is no "the system did this, unprompted" concept in the existing subject-type vocabulary. |
| _(any other string)_ | Forward-compatibility catch-all — see "Compatibility rules." |

`actor_id` is a free-text string identifying the specific actor (a device
id, a user id, a token id) and is `null`/absent for `actor_kind: "system"`,
which has no singular identity to name.

#### `AuditAction`

An open string enum (`snake_case` wire values). The canonical set defined by
this ADR:

| Wire tag | Meaning |
|---|---|
| `permission_check` | An authorization decision was evaluated (mirrors `fornax-cloud`'s `permissions.py` check path). |
| `break_glass_activated` | An emergency break-glass grant was activated. |
| `policy_bundle_activated` | A signed policy bundle was verified and activated locally (ADR-0007/0008). |
| `policy_revocation_ingested` | A signed revocation list was verified and its entries ingested (ADR-0009). |
| `role_assignment_changed` | A `RoleAssignment` was created, modified, or removed. |
| `evidence_purged` | FORNX-319: a `RetentionClass::RawLocal` evidence row's payload was purged by the local retention sweep (`fornax-store::retention`) once its retention window elapsed. |
| _(any other string)_ | Forward-compatibility catch-all. |

This set is deliberately small and will grow additively as new
audit-worthy actions are identified — it is not meant to be exhaustive at
publication time.

#### `AuditOutcome`

An open string enum. **This is a strict superset of the outcome strings
`fornax-cloud`'s `permissions.py` already emits today** — every literal
string that file logs via its `outcome=` log field must appear here
verbatim:

| Wire tag | Already emitted by `fornax-cloud` today? | Meaning |
|---|---|---|
| `granted` | yes (`permissions.py:235`) | An ordinary role-based permission check succeeded. |
| `denied` | yes (`permissions.py:220`, `262`) | A permission check failed (either no identity, or role-based check failed). |
| `granted_via_break_glass` | yes (`permissions.py:249`) | A permission check succeeded only because an active break-glass grant overrode an otherwise-failing role check. |
| `break_glass_activated` | yes (`permissions.py:474`) | A break-glass grant was activated (distinct from its later *use*, which logs `granted_via_break_glass`). |
| `revoked` | no — new in this ADR | An artifact (bundle, key, grant) was revoked as the result of this action. |
| `expired` | no — new in this ADR | The action's target had already expired at evaluation time. |
| _(any other string)_ | — | Forward-compatibility catch-all. |

`fornax-core`'s Rust `AuditOutcome` type is tested to enumerate exactly
these four already-emitted strings as literals, proving none of
`fornax-cloud`'s current vocabulary is missing (see `audit.rs`'s
`every_fornax_cloud_permission_outcome_string_has_an_audit_outcome_variant`
test).

#### `AuditTarget`

Same tagged-object shape as `AuditActor`:

```json
{ "target_kind": "revocation_entry", "target_id": "sha256:ab12..." }
```

| Wire tag | Meaning |
|---|---|
| `policy_bundle` | A `SignedPolicyBundle`/`VerifiedPolicyBundle`, identified by its `bundle_id`. |
| `revocation_entry` | A `RevocationEntry`, identified by its target's digest. |
| `role_assignment` | A `RoleAssignment` row. |
| `permission` | An abstract permission name being checked (not a stored row). |
| `device` | A device identity. |
| `evidence` | FORNX-319: an `evidence` row, identified by its id — the target of an `evidence_purged` action. |
| `organization` | A `fornax-cloud` organization. |
| _(any other string)_ | Forward-compatibility catch-all. |

### 3. `AuditExportClass` — a new, third, orthogonal classification axis

`AuditExportClass` governs **how much of one `AuditEvent`'s own content may
leave the local device toward `fornax-cloud`.** It is deliberately a
separate axis from the two classification systems this project already
has:

| Axis | Type | Question it answers | Defined in |
|---|---|---|---|
| `RetentionClass` | `RawLocal` / `SanitizedReplayFixture` / `AggregatedFeature` / `DerivedFinding` | *How long* should this record live, and at what aggregation level? | `crates/fornax-types/src/reliability_context.rs` |
| `ContentClass` | `ToolTelemetry` / `ProviderDiagnostic` / `ExperimentalSignal` / `RawProviderMetadata` | *What category* of provider-extension data is this? | `crates/fornax-types/src/extension.rs` |
| `AuditExportClass` (this ADR) | `Metadata` / `FindingSummary` / `SensitiveEvidenceRef` / `RawContent` | *How exportable* is this specific audit event's content? | `crates/fornax-types/src/audit.rs` |

These three axes describe orthogonal properties of a record and are not
substitutable for one another:

- A `RetentionClass::RawLocal` record can still be `AuditExportClass::Metadata`
  (short-lived and freely exportable are independent properties — e.g. a
  transient `permission_check` audit event).
- A `ContentClass::ToolTelemetry` extension payload has no `AuditExportClass`
  at all; it isn't an audit event. Conversely an `AuditEvent` has no
  `ContentClass` — it isn't provider-extension data.
- Two `AuditEvent`s with the identical `AuditAction`/`AuditOutcome` can carry
  different `AuditExportClass` values depending on what ended up in
  `attributes` (e.g. a `permission_check` that only names a permission
  string is `Metadata`; one whose `attributes` happens to embed a snippet of
  raw evidence content is `RawContent`).

**`AuditExportClass` is the last classification axis this project adds.**
Any future export/retention/content nuance must be expressed as a value
within one of these three existing enums (or a field alongside them), not as
a fourth axis.

The four `AuditExportClass` values, from most to least exportable:

| Wire tag | Meaning |
|---|---|
| `metadata` | Only structural fields (actor kind, action, outcome, timestamps) — no content that could itself be sensitive. Freely exportable. |
| `finding_summary` | A summary/verdict derived from evidence, with no raw content attached. Exportable under an org's standard egress policy (ADR-0006). |
| `sensitive_evidence_ref` | References (ids, digests) to evidence that itself may be sensitive, without embedding the evidence content. Exportable only when policy explicitly allows referencing sensitive evidence. |
| `raw_content` | Embeds raw content directly (e.g. a redacted-but-still-substantive payload excerpt in `attributes`). The most restrictive — exportable only under an explicit raw-content allowance. |
| _(any other string)_ | Forward-compatibility catch-all — see §4's safe-default rule. |

**Safe-default rule for an unrecognized `export_class`:** an unrecognized
(`Unrecognized(String)`) or otherwise unresolvable `AuditExportClass` value
**must be treated as if it were `RawContent`** — i.e. maximally restrictive,
non-exportable by default — never as `Metadata`. This mirrors the "fail
closed" trust discipline `bundle.rs` already applies to signature algorithm
recognition (an algorithm this binary doesn't recognize is always rejected,
never silently trusted): an export-class tag this binary doesn't recognize
must always be refused for export, never silently allowed through. This is
the inverse of `CollectionMethod`/`ClockSource`'s "safest" default in
`sensor.rs`, which is an honest-*unknown* marker (`PreProvenance`), not a
restrictiveness ordering — `AuditExportClass` has no such
predates-this-field case, so its unrecognized-value default is a genuine
restrictiveness choice, not an honesty marker.

### 4. Compatibility rules

- **Unknown enum variant.** Any of `AuditActor.actor_kind`,
  `AuditAction`, `AuditOutcome`, `AuditTarget.target_kind`, or
  `AuditExportClass` may carry a string this reader does not recognize. A
  conforming reader must parse the event successfully, preserve the
  original string verbatim, and re-serialize it back to that same original
  string — never fail, never substitute a different value, never drop the
  field.
- **Unknown top-level field.** Any additional top-level key on the
  `AuditEvent` object beyond §1's table must be preserved verbatim across a
  read-then-write round trip, not silently discarded — a tolerant reader on
  an older binary must never destroy a newer producer's data on rewrite.
- **Unsupported `schema_version`.** A `schema_version` not in this ADR's
  supported set **must fail loudly** at parse/construction time, naming
  both the offending version and the full supported set in the error
  message — never silently coerced, never partially parsed. This is the
  same asymmetry `ExtensionEnvelope` already enforces
  (`crates/fornax-types/src/extension.rs`): an unrecognized *field value* is
  forward-compatible noise; an unrecognized *schema version* is a hard
  incompatibility.
- Currently supported: `[1]`.

### 5. `attributes` is not an event lake

`attributes` is a bounded escape hatch for action-specific detail that does
not warrant a canonical field yet (e.g. `{"issuer": "...", "sequence": 42}`
on a `policy_revocation_ingested` event). It carries **exactly the same
non-goal** ADR-0005 already states for `ExtensionEnvelope.fields`
(`docs/adr/0005-schema-evolution.md`, "No generic schemaless event lake"):
this field must never become a dumping ground for arbitrary application
data in place of adding a proper canonical `AuditAction`/`AuditTarget`
variant or a new named field on `AuditEvent` itself. That non-goal is
referenced here, not re-litigated — see ADR-0005 for the full reasoning.

### 6. `audit_ref` resolution format

`RevocationEntry.audit_ref: Option<String>` (`crates/fornax-types/src/policy/revocation.rs`)
and the matching `policy_revocations.audit_ref TEXT` column
(`crates/fornax-store/migrations/0009_policy_revocation.sql`) have existed
since ADR-0009 with no defined shape: nullable, no foreign key, no
documented semantics for what a non-`null` value should contain.

This ADR defines that shape as a stable string form referencing one
`AuditEvent`:

```
<issuer-scope>:<event_id>
```

- `issuer-scope` — the same non-empty issuer string used elsewhere in this
  repo (e.g. `RevocationPayload.issuer`, `BundleProvenance.issuer`). Must
  not itself contain a `:` character — the format resolves by splitting on
  the **first** `:` only, so an issuer-scope containing a colon would be
  mis-parsed.
- `event_id` — the referenced `AuditEvent.event_id` (a UUID), verbatim.

Example: `horonomy-policy-issuer-1:d290f1ee-6c54-4b01-90e6-d701748f0851`.

**`RevocationEntry.audit_ref: None` remains valid forever.** Every
revocation entry created before this ADR (and any created after it where no
corresponding audit event exists) has `audit_ref: None`, and that remains a
fully valid, permanent state — **existing revocations are never backfilled**
with a synthesized `audit_ref` merely because this format now exists. A
`None` value means exactly "no audit event is linked," not "not yet
migrated."

This ADR defines the string format and its parser/formatter
(`fornax-types::audit::AuditRef`) only. Changing
`RevocationEntry.audit_ref`'s Rust type from `Option<String>` to
`Option<AuditRef>` is explicitly **out of scope** for FORNX-314 — see the PR
description for the follow-up ticket carve-out.

## Non-goals (explicit)

- **No database table, no store integration, no HTTP route, no CLI
  command, no network or file I/O of any kind.** This ADR and its
  accompanying `fornax-types::audit` module define the wire shape and pure
  in-memory validation only — exactly the same scope boundary FORNX-116 held
  for the policy model before ADR-0007/0008/0009 built storage and
  activation on top of it.
- **No redaction logic.** `attributes` may contain content that needs
  redaction before export; that redaction is `crates/fornax-types/src/redact.rs`'s
  existing job, applied by whichever future caller persists or exports an
  `AuditEvent` — this ADR does not re-specify or duplicate it.
- **No fourth classification axis**, ever, per §3.
- **No backfill of existing `audit_ref: None` revocation entries.**

## Consequences

- `fornax-cloud` can start emitting `AuditEvent`-shaped JSON matching this
  document today, independent of when/whether `fornax-core` ever persists
  or transmits one itself.
- A future ticket can wire `RevocationEntry.audit_ref` to actually populate
  a well-formed `<issuer-scope>:<event_id>` string without any format
  renegotiation — the format is fixed now, adoption is separate.
- `AuditExportClass`'s fail-closed unrecognized-value handling means a
  future binary encountering an export class from an even-newer producer
  never accidentally over-shares that event's content.

## Local ledger trust boundary (FORNX-315 addendum)

FORNX-315 added `fornax-store`'s local, hash-chained persistence for
`AuditEvent` (`crates/fornax-store/src/audit_ledger.rs`,
`Store::append_audit_event`/`Store::verify_audit_chain`) — the storage/
verification machinery this ADR's own "Non-goals" section above explicitly
deferred. Its guarantee is real but narrow, and must not be
over-interpreted:

A local hash chain detects post-hoc edits by an actor who cannot recompute the whole chain forward from the point of the edit.

It does NOT attest that the endpoint recorded every event it should have — an endpoint that simply never calls `append_audit_event` for some action produces a chain that verifies as valid while being silently incomplete.

It does NOT make a compromised endpoint trustworthy — an attacker with full control of the Fornax process itself can fabricate a self-consistent chain from scratch, including events that never happened.

The chain binds this store's own rows to each other; it is not a witness to anything outside the store. See `audit_ledger.rs`'s own module doc comment for the full statement and the four-mutation-shape detection order this boundary is exercised against.
