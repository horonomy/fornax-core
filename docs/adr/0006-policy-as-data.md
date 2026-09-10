# ADR 0006: Policy-as-data domain model

Status: Accepted
Date: 2026-09-03
Jira: FORNX-116 (child of FORNX-69)

## Context

Fornax's privacy/egress/enforcement behavior today is a small set of hardcoded
env-var gates (`fornax_types::privacy::cloud_sync_allowed`,
`longitudinal_reliability_collection_allowed`) plus a per-device
`config.toml` (`sensor_config::SensorDisableConfig`). This is fine for a
single local user but has no way to express an organization's policy, no way
to target a subset of devices/projects, no immutability or tamper-evidence,
and no vocabulary for enforcement decisions at all (FORNX-121 needs one).

This ADR introduces policy as **data**: an immutable, digested,
future-signable revision of policy content, targeted at an
org/team/project/device/local-user level, resolved locally into one concrete
set of values. It does not wire any caller over to the new model — see
"Non-goals" below.

## Decision

### Placement

`crates/fornax-types/src/policy.rs` + `policy/{content,revision,target,
resolve,diagnostics,local}.rs`. No new crate — ADR-0001 D6 rejects
infrastructure without measured need, and `fornax-types` already hosts pure
domain logic (`reliability_context::aggregate_context`,
`graph::staleness_of`), not just structs. `policy/local.rs` is an addition
beyond the ticket's originally named module list, holding the
env/config.toml -> `LocalUser` layer mapping (AC5) split out for
testability — see "Deviations from the original design" below.

New dependency: `sha2 = "0.11"` (workspace + `fornax-types`), the current
latest stable line per ADR-0003. No `hex` crate — digest bytes are
hand-formatted (`format!("{b:02x}")`).

### Content is layered, not merged eagerly

Every field of `PolicyContent` (and its nested scopes) is `Option<T>`.
`None` means **this layer has no opinion about this field** — it is not a
value and must never be conflated with a concrete falsy value. This is the
single invariant the whole model depends on; see "AC5: mapping today's gates"
below for the exact place a naive `unwrap_or(false)` breaks it.

### Baseline (the concrete floor)

| Field | Baseline | Rationale |
|---|---|---|
| `collection.longitudinal_aggregation_allowed` | `false` | identical to today's env gate |
| `egress.cloud_sync_allowed` | `false` | identical to today's env gate |
| `egress.redaction_profile` | `Standard` | identical to today's `redact_json` |
| `egress.allowed_content` | `{}` | deny-by-default |
| `sensors.disabled` | `{}` | today: nothing disabled |
| `sensors.required_signals` | `{}` | no requirement asserted |
| `enforcement.rules` | `[]` -> every `(ActionClass, Verdict)` reads `ObserveOnly` | see below |
| `cache.max_age_seconds_by_risk` | `{low:86400, elevated:21600, high:3600, critical:900}` | future cache-activation ticket may tune |
| `cache.offline_grace_seconds` | `604800` (7d) | future cache-activation ticket owns |

Two default philosophies, deliberately. Collection/egress default **deny**
— mirroring today's env gates, and AC5 forbids weakening them. Enforcement
defaults **observe-only** — blocking is a *new* capability with no incumbent
behavior to preserve; silently acquiring the power to block agent actions on
upgrade is the failure mode to avoid.

### Strictness table (used for same-level conflict resolution and pin checks)

| Field | Stricter is | Meet |
|---|---|---|
| `longitudinal_aggregation_allowed` | `false` | AND |
| `cloud_sync_allowed` | `false` | AND |
| `redaction_profile` | `Strict` | max |
| `allowed_content` | smaller set | intersection |
| `sensors.disabled` | larger set | union |
| `sensors.required_signals` | larger set | union |
| `enforcement.rules` | per `ActionClass`: higher `RiskClass`, and per-verdict higher `EnforcementOutcome` independently | per-action merge; actions in only one side pass through |
| `cache.max_age_seconds_by_risk` | smaller, per risk tier independently | per-field min |
| `cache.offline_grace_seconds` | smaller | min |

### Precedence algorithm (`policy::resolve`)

1. **Select.** A binding applies if its `TargetScope` and `TargetSelector`
   both match the local `DeviceContext`. A selector value this binary
   doesn't recognize (`OsFamily::Unrecognized`/`SignalClass::Unrecognized`)
   makes the binding **match anyway**, with a `SelectorNotUnderstood`
   Warning — dropping an admin policy you can't fully narrow is the unsafe
   direction. A `requires_signals` class the device doesn't report
   `Available` **prevents** a match, with a `RequiredSignalUnavailable`
   Warning.
2. **Group** applicable bindings by `TargetLevel` (`Org < Team < Project <
   Device < LocalUser`).
3. **Within-level meet.** For each level and field: if two or more bindings
   at that level set *differing* values, emit an Error
   `ConflictingBindingsAtLevel` naming every contributing binding, and take
   the strictest value per the table above.
4. **Across-level combination**, iterating `Org -> Team -> Project -> Device
   -> LocalUser`:
   - For **override-style fields** (7 of 9: everything except
     `sensors.disabled`/`sensors.required_signals`) the most specific
     applicable level's value **replaces** all previous levels' — this is
     what makes a project/device exemption from an org-wide rule
     expressible at all (including a per-`ActionClass` exemption from an
     org's `enforcement.rules`).
   - For **accumulate-style fields** (`sensors.disabled`,
     `sensors.required_signals`) every applicable level's value is
     **union-folded** together regardless of specificity — a safety
     opt-out published anywhere can never be silently un-set by a more
     specific layer without an explicit mechanism, which does not exist
     yet.
   - Before accepting a level's value for a field with an active *pin*
     (from an earlier, less specific level's `pinned_fields`): if the
     candidate is looser than the pinned floor, emit an Error
     `PinViolation` and keep the floor's value (with its original
     provenance); otherwise accept the candidate and, if this level itself
     pins the field, raise the floor to the accepted value.
5. **Baseline.** Any field no applicable binding ever set takes
   `PolicyContent::baseline()`, provenance `Baseline`.
6. An empty or fully-non-matching `bound` slice emits an Info
   `NoApplicablePolicy` and returns baseline for everything.

The algorithm is **order-independent in the input slice**: grouping is by
level (unordered), within-level meet is commutative, and across-level
iteration always proceeds `Org -> ... -> LocalUser` regardless of input
order. `crates/fornax-types/src/policy/tests.rs::t12_*` proves this over all
24 permutations of a 4-element input (no `rand` dependency — the workspace
has none, and 4! is small enough to enumerate directly).

### `resolve()` never fails (ADR-0001 D2)

`pub fn resolve(bound: &[BoundRevision], ctx: &DeviceContext) -> (ResolvedPolicy, Vec<PolicyDiagnostic>)`
— no `Result`, and the implementation never calls `.unwrap()`/`.expect()`/
indexes a slice by a possibly-out-of-range index. A malformed *wire* revision
is rejected earlier, at `TryFrom<PolicyRevisionWire>` construction (before a
`BoundRevision` can exist); `resolve()` only ever sees already-validated
input. This is deliberate: the local critical path must not fail closed
because a remote policy layer is malformed or simply absent.

### Immutable revisions and the bytes-to-signing boundary

```
pub fn canonical_bytes(body: &PolicyRevisionBody) -> Vec<u8>;  // serde_json::to_vec, never via Value
pub fn digest_of(body: &PolicyRevisionBody) -> RevisionDigest; // "sha256:<64 lowercase hex>"
```

`canonical_bytes` is `serde_json::to_vec` on the **typed** `PolicyRevisionBody`
— never round-tripped through `serde_json::Value`. Field order is
declaration order (the default for `#[derive(Serialize)]`). Every collection
inside `PolicyContent` is a `BTreeSet`/`BTreeMap` or a
canonicalization-enforced `Vec` (see "Deviations" below) — no
`HashMap`/`HashSet` anywhere, so serialization is reproducible. The digest
is computed over the body only and is not itself a field of the body, so it
cannot hash itself. A future signing ticket signs exactly
`canonical_bytes(&body)`, verbatim.

`PublishedPolicyRevision` has private fields and only `&_` accessors
(`body()`, `digest()`, `reference()`) — no public field, no `&mut` accessor.
It is constructed only by `PolicyDraft::publish` or by
`#[serde(try_from = "PolicyRevisionWire")]`'s `TryFrom` impl, which
recomputes the digest via `digest_of` and rejects on mismatch (`DigestMismatch`)
and rejects an unsupported `schema_version` (`UnsupportedSchemaVersion`).
Without this, `#[derive(Deserialize)]` alone would let a hand-edited body
through as if it had been validated.

No `status: RevisionStatus` field exists on the body. Mutating a status to
`Revoked` would change the canonical bytes and invalidate the digest (and
any future signature over it). `supersedes` is safe because it is
forward-only — a new revision names what it replaces, never mutating the
old one. Revocation is a separate record referencing a digest, out of scope
here.

`published_at` is a parameter to `PolicyDraft::publish`, never `Utc::now()`
internally, so publishing is deterministic and canonical bytes are
reproducible in tests — this is also why `sha2` (not a UUIDv5/SHA-1
approach) was chosen: a digest a future ticket signs over and revokes by is
neither a compaction device (`reliability_context.rs`'s UUIDv5 use) nor
benchmark-dataset identity (`dataset.rs`'s precedent) — SHA-1 collision
resistance is the wrong foundation for either signing or revocation, and the
algorithm is unchangeable once digests are persisted.

### Targeting is structurally separate from content

`PolicyBinding` (a `TargetScope` + `TargetSelector` + a `PolicyRevisionRef`)
carries no policy content; `PolicyContent` carries no targeting. A future
canary/staged-rollout ticket adds state to the *binding* side without
touching a single content type.

`TargetSelector.providers`/`requires_signals` are `Vec<T>`, not
`BTreeSet<T>`: `crate::Provider` and `crate::SignalClass` derive neither
`Ord` nor `Hash` (the latter is documented as deliberate in
`reliability_context.rs`'s `capability_fingerprint`, "rather than adding
those derives to a module this ticket does not otherwise touch"). A
selector is never part of a signed revision's canonical bytes, so no
canonicalization is required — matching is a plain membership check.
`SensorScope.required_signals` has the same underlying constraint but *is*
part of the canonical body, so it is a `Vec<SignalClass>` explicitly
canonicalized (sorted by wire-tag string, deduplicated) by
`PolicyDraft::publish` before the digest is computed, so semantically-equal
sets always produce identical bytes.

### Diagnostics: two jobs, two signatures

`PolicyDraft::publish`, `BoundRevision::new`, and
`TryFrom<PolicyRevisionWire>` return `Result<_, PolicyValidationReport>` —
any Error-severity `PolicyDiagnostic` fails the whole operation.
`resolve()` returns `(ResolvedPolicy, Vec<PolicyDiagnostic>)` and never
`Err`. Every diagnostic carries a non-empty `message` (what's wrong) and
`remediation` (what to change) — enforced by
`t11_every_diagnostic_code_produces_nonempty_message_and_remediation`.

A pin naming a `PolicyFieldId::Unrecognized(_)` (a pin from a newer
publisher this binary doesn't fully understand) is **never** rejected at
publish time — rejecting it would make a newer revision unreadable by an
older binary, destroying the forward-compat story the `Unrecognized` tails
exist for. It is simply ignored for flooring at resolve time (this binary
cannot enforce a constraint it cannot identify).

A pin at `TargetLevel::LocalUser` is rejected (`PinAtLocalUserLayer`) at
`BoundRevision::new` — nothing is more specific than `LocalUser`, so a pin
there is a no-op that would only look meaningful.

`DiagnosticCode::RevisionNotMonotonic` is reserved in the enum per the
original design but is **not emitted by anything in this ticket** — checking
it requires a revision *history* to compare against, which requires a
`fornax-store` migration explicitly out of scope here (see "Non-goals").

### AC5: mapping today's gates without weakening them (`policy::local`)

**The exact place AC5 breaks.** Today's code is `unwrap_or(false)`. If the
`LocalUser` layer wrote `Some(false)` when `FORNAX_CLOUD_SYNC_ENABLED` is
*unset*, `LocalUser` — the most specific level — would become the layer that
sets the field and would permanently defeat every published policy: an org
publishing `cloud_sync_allowed = true` would never take effect for a user
who never touched the env var. `None` (no opinion) is the only value that
preserves "an org policy can turn this on."

`parse_bool_gate`/`local_user_layer_from_values` is the **pure mapping
core** — no environment or filesystem access — so the four assertions
`crate::privacy`'s own tests document (`"1"`/`"true"` enable, unset is "no
opinion", anything else is `Some(false)` + a `UnrecognizedEnvValue` Warning)
are tested directly with zero risk of the `std::env::set_var` race
`crate::privacy`'s own test module documents and consolidates around.
`local_user_layer(home: &Path)` is the thin, real-environment wrapper.

**Mid-session flip ownership.** `crate::privacy`'s doc comment commits to
the cloud-sync gate being checked before every network call, so a user can
disable sync mid-session. A cached `ResolvedPolicy` would silently break
that. Ownership is split: published layers may be cached by a future
caching ticket; the `LocalUser` layer is always re-read from the
environment on every evaluation — an env read is cheap, and this preserves
the existing guarantee without depending on that ticket shipping first.

**`sensors.disabled` mapping.** `SensorDisableConfig` gained one new public
accessor, `disabled_names() -> &HashSet<String>`, so `policy::local` can
read the full set (it previously only exposed `is_disabled(name)`).
"Absent" and "present but empty" are indistinguishable through that
accessor — this is safe specifically *because* `sensors.disabled` is an
accumulate-style field (see the precedence algorithm above): folding an
empty set into any other level's set is a no-op regardless of which case it
was, so the ambiguity has no observable effect on `resolve()`'s output.

**`redact.rs` is untouched.** `redact_json` keeps running unconditionally at
the storage boundary (ADR-0001 D3/D7). `RedactionProfile::Standard` is
documented as exactly today's `redact_json` behavior; there is no `Off`
variant to select, so the baseline floor cannot skip redaction.

**Explicit non-goal for this ticket:** `privacy::cloud_sync_allowed()`'s call
sites, the daemon, the uploader, and `fornax-store` are not rewired onto
this model. AC5 requires demonstrating the mapping is possible and
non-weakening — that is what `local_user_layer` plus the T19-T25 tests
prove. Migrating real callers over is a later ticket.

## Deviations from the original design

The design recovered from the earlier planning session got almost
everything right; three points needed correction against the current
codebase and one ambiguity needed resolving:

1. **`BTreeSet<Provider>`/`BTreeSet<SignalClass>` are compile errors.**
   `Provider` (`lib.rs`) derives no `Ord`; `SignalClass`
   (`capabilities.rs`) derives neither `Ord` nor `Hash`, documented as
   deliberate in `reliability_context.rs`. Both `TargetSelector.providers`/
   `.requires_signals` and `SensorScope.required_signals` use `Vec<T>`
   instead — see "Targeting is structurally separate from content" above
   for why each is safe without `Ord`.
2. **`local_user_layer` is split into a pure core and a thin env-reading
   wrapper**, rather than one function that reads the environment directly.
   `crate::privacy`'s own test module documents a real
   `std::env::set_var`-is-process-global race and consolidates its own tests
   around it; splitting the mapping logic out lets T19-T22 exercise it with
   zero env contact instead of inheriting that race.
3. **A pin naming an unrecognized `PolicyFieldId` is accepted, not
   rejected**, at publish time (see "Diagnostics" above) — consistent with
   the design's own "unrecognized selector value still matches" reasoning,
   applied to the pin side of forward-compatibility.
4. **Across-level combination is per-field, not uniformly "most specific
   replaces"** — see "Precedence algorithm" step 4. `sensors.disabled`/
   `sensors.required_signals` union-fold across every level;
   `enforcement.rules` and the other 6 fields use plain override. This
   resolves an internal tension in the recovered design between "more
   specific wins, full stop" (needed for project/device exemptions) and
   "meet is UNION" stated as an unconditional field property (needed for
   `sensors.disabled` to survive a `LocalUser` layer with an unrelated,
   smaller disabled list) — both readings are preserved by making the
   override-vs-accumulate choice a property of the field.

## Non-goals (explicit for this PR)

- No rewiring of `privacy::cloud_sync_allowed()`'s call sites, the daemon,
  the uploader, or `fornax-store`.
- No persistence: nothing in this ticket adds a `fornax-store` migration or
  a cache. A future caching/activation ticket owns `CacheScope` activation,
  rollback, and last-known-good behavior; this ticket only defines the
  numbers.
- No signing: a future ticket signs `canonical_bytes(&body)`; this ticket
  only defines the boundary.
- No revision-history validation (`RevisionNotMonotonic` is reserved, not
  implemented — see "Diagnostics").
- No `fornax-experiment-runner` policy migration — `GlobalExperimentPolicy`
  is a separate concept in a separate crate `fornax-types` cannot depend on.

## Test coverage

27 acceptance scenarios (T1-T27) plus two additional D2 safety tests and two
selector-matching tests, all in
`crates/fornax-types/src/policy/tests.rs`, exercising AC1 (immutability/
reproducibility), AC2 (validation diagnostics), AC3 (deterministic
precedence), AC4 (closed vocabulary, no `serde_json::Value` escape hatch),
and AC5 (non-weakening migration of today's gates), plus the FORNX-121
`VerdictOutcomes` vocabulary and the D2 "never fails" invariant. The frozen
fixture lives at `crates/fornax-types/tests/fixtures/policy_revision_v1.json`
and is regenerable via the `#[ignore]`d `generate_fixture_v1` test.
