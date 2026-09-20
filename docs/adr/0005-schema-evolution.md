# ADR 0005: Typed canonical evidence + versioned provider-extension envelope

Status: Accepted
Date: 2026-08-30
Jira: FORNX-158 (child of FORNX-138)

## Context

FORNX-155/156/157 gave core a versioned capability taxonomy, a thin
adapter boundary, and a structured sensor/provenance contract. None of them
answered a question that comes up the moment a second or third provider
adapter wants to report something genuinely provider-specific: where does
new provider-only evidence live? Two extremes were both available and both
wrong:

- Force it into a new canonical `EvidenceKind` immediately. A canonical
  field is a cross-provider commitment (core code, verifiers, and storage
  all get to assume it means the same thing regardless of provider) — that
  commitment shouldn't be made on the strength of one provider's one signal.
- Let it flow through as untyped `serde_json::Value` everywhere, with no
  version, no provider tag, no classification. This is the "generic
  schemaless event lake" this ticket's AC explicitly forbids: nothing
  distinguishes "provisional, provider-specific, low-confidence" data from
  the canonical fields core code already trusts.

This ADR defines the middle path: canonical fields stay strongly typed and
validated; new provider-specific evidence gets a versioned, classified
envelope that is explicitly a secondary, opt-in path.

## Decision

### Canonical evidence stays typed

`Evidence::payload` remains `serde_json::Value` on the wire — every producer
already builds one directly (`fornax-adapter-claude`/`fornax-adapter-codex`'s
`ExitCode` sensors) and changing that field's storage type was not necessary
to satisfy the AC. What was missing was a way to *check* that a given
`(EvidenceKind, payload)` pair actually matches its canonical shape, so
"canonical fields remain strongly typed and validated" is a checkable claim
and not just an aspiration:

```rust
pub struct ExitCodePayload { pub command: serde_json::Value, pub exit_code: i64, pub heuristic: bool }
pub struct ToolResultPayload { pub summary: String }
pub struct FileDiffPayload { pub path: String, pub diff: String }
pub struct ProcessObservationPayload { pub description: String }
pub struct TranscriptExcerptPayload { pub text: String }

pub fn validate_canonical_payload(kind: EvidenceKind, payload: &serde_json::Value) -> Result<(), String>;
```

One typed struct per `EvidenceKind` variant, all `#[serde(deny_unknown_fields)]`
— unlike the extension envelope (below), a canonical shape is *closed*: an
unrecognized field on a canonical payload is a validation failure, not
something to tolerate. Only `ExitCodePayload` has a real producer today; the
rest are typed ahead of a producer existing, mirroring FORNX-157's
`ReasoningSummarySensor` worked example (typing a shape before any provider
exposes it, so a future sensor has a target from day one).

### The extension envelope

```rust
pub struct ExtensionEnvelope {
    pub schema_version: u32,
    pub provider: Provider,
    pub adapter_version: String,
    pub content_class: ContentClass,
    pub fields: serde_json::Value,
    pub unknown: serde_json::Map<String, serde_json::Value>, // #[serde(flatten)]
}
```

Attached as `Evidence::extension: Option<ExtensionEnvelope>` — one new
optional field on the existing type, not a change to any unrelated canonical
model (AC 1). `None` is the common case.

Field choices:

- `schema_version` — see "Version compatibility" below.
- `provider` / `adapter_version` — which adapter produced this, so a
  consumer can tell "Claude Code's `adapter_version` 0.3.0" from "Codex's
  0.1.0" without depending on `content_class` alone to disambiguate.
- `content_class` — a coarse category (`ToolTelemetry`, `ProviderDiagnostic`,
  `ExperimentalSignal`, `RawProviderMetadata`, `Unrecognized(String)`
  catch-all), so a consumer can filter/route without parsing `fields`.
- `fields` — the actual provider-specific content, deliberately untyped.
  This is the *only* schemaless field anywhere in the canonical/extension
  split, and only because that is the envelope's entire purpose.
- `unknown` — see "Unknown-field tolerance" below.

### Version compatibility

```rust
pub const SUPPORTED_EXTENSION_SCHEMA_VERSIONS: &[u32] = &[1, 2];
pub const EXTENSION_SCHEMA_VERSION: u32 = 2; // current default for new envelopes
```

A plain allow-list of supported integers, not a packed major/minor scheme.
Rejected the packed-decimal alternative (`major * 1000 + minor`) because a
minor counter has no job left once unknown *fields* within a version are
already tolerated-and-preserved: "an additive change within a version" is
already exactly "same `schema_version`, extra unknown keys" (see below). A
packed scheme would only add a rollover rule to document for no expressive
gain.

**"Truly incompatible" = not a member of `SUPPORTED_EXTENSION_SCHEMA_VERSIONS`.**
Deserialization goes through `ExtensionEnvelopeWire` + a fallible
`TryFrom` (`#[serde(try_from = "ExtensionEnvelopeWire")]`, mirroring
`RuntimeCapabilitiesWire`'s pattern but fallible instead of always-succeeding)
so an incompatible version fails **loudly and specifically** — a distinct
error naming both the offending version and the supported set — before an
`ExtensionEnvelope` value is ever constructed. This is deliberate contrast
with the rest of the extension surface: an unrecognized *field* is
forward-compatible noise (see below); an unrecognized *version* means this
binary cannot vouch for the payload's own invariants, and silently accepting
it risks misinterpreting data rather than merely missing an optional detail.
A version is retired from the supported set only per the deprecation policy
below, not simply because a newer default version exists.

**Blast radius of an incompatible row (FORNX-289, resolved).** A single
`evidence` row stamped with an unsupported `schema_version` fails loudly at
the row level, per above — but it does not take down the whole session's
evidence read. `fornax-store::evidence_for_session` returns an
`EvidenceReadOutcome { evidence, failed }`: every row that deserializes
successfully still comes back in `evidence`, and each row that doesn't is
named by id in `failed` rather than silently dropped or aborting the whole
query, per ADR 0001's "observation must never break the session" invariant.
This is deliberately scoped to *this* session-wide query — a direct
single-row read or an explicit version check elsewhere still fails loudly
per the "truly incompatible" rule above; only the session-wide aggregate
read is hardened to isolate one bad row's failure from the rest.

### Unknown-field tolerance

`ExtensionEnvelope` carries `#[serde(flatten)] unknown: serde_json::Map<...>`.
Any top-level JSON key present on the wire but not named by
`schema_version`/`provider`/`adapter_version`/`content_class`/`fields` lands
in `unknown` on deserialize, and is re-emitted verbatim (via the same
`flatten`) on serialize. This is **preserve-and-ignore**, not
**delete-on-read**: a binary reading a newer envelope keeps what it doesn't
understand and can hand it back unmodified (e.g. through `fornax-cli`'s
`export-spool`, which spools `Evidence` as-is — see
`fornax-cli/src/main.rs::evidence_envelope_carries_extension_data_through_export`).
`content_class`'s own `Unrecognized(String)` catch-all follows the same
FORNX-155 precedent one level down, for the tag itself.

Reused, not reinvented: this is the same "explicit catch-all variant, carry
the original string/data forward" shape as
`SignalAvailability::Unrecognized`/`SignalClass::Unrecognized`
(`crates/fornax-types/src/capabilities.rs`) and `TrustClass::Unrecognized`
(`crates/fornax-types/src/sensor.rs`).

### Boundary with `NormalizationOutcome::Unrecognized`

`AgentAdapter::normalize`'s `NormalizationOutcome::Unrecognized` (FORNX-156)
carries only a `discriminator` type tag, never the native payload body — see
`crates/fornax-types/src/adapter.rs`'s "Unknown-event policy", which already
anticipated this ticket and explicitly deferred to it. **The extension
envelope does not change that.** An `ExtensionEnvelope` is built only for a
native shape a sensor **recognizes and deliberately chooses** to carry
provider-specifically (a real, working `EvidenceSensor` implementation
decided this data is worth keeping, just not worth a canonical field yet) —
never as a generic laundering path for a shape `normalize` didn't recognize
at all. Conflating the two would reintroduce exactly the "uncontrolled
provider-native payload leakage into domain/storage" FORNX-156 forbids.

### No dispatch on envelope content

`fields`/`unknown` are inert JSON data. Nothing in `fornax-types`,
`fornax-store`, or `fornax-daemon` executes code, loads a plugin, or branches
control flow based on their contents beyond ordinary
serialize/deserialize/persist. This satisfies the "no arbitrary code/plugin
execution" non-goal directly — there is no interpreter for `fields` to have
been given one.

### Persistence

`crates/fornax-store/migrations/0005_evidence_extension.sql` adds one
nullable `extension TEXT` column to the existing `evidence` table, following
0003/0004's additive-migration precedent exactly: no new table, `extension
IS NULL` reads back as `Evidence::extension == None`, and there is no legacy
data to reconstruct (same reasoning as 0004's `source` column).

## Promotion criteria: extension field → canonical field

A provider-extension field (identified by its `content_class` + a key under
`fields`) should be promoted to a canonical `EvidenceKind`/typed payload
struct when **all** of the following hold:

1. **Cross-provider**: at least two distinct `Provider` values have produced
   the same semantic field (same meaning, not just the same JSON key name)
   through the extension envelope. A field only one provider will ever have
   is provider-specific by nature and belongs in the envelope indefinitely.
2. **Stable shape**: the field's type and meaning have not changed across at
   least one full `schema_version` bump's worth of usage (i.e. it survived a
   version transition without needing to change shape). A field still
   changing shape between providers/versions is not ready to be frozen into
   a typed struct.
3. **Consumed by core logic**: something in `fornax-verify`/`fornax-daemon`
   (a verifier, a status computation) wants to depend on the field's
   presence/type directly, not just pass it through. If nothing downstream
   of collection ever reads `fields["x"]`, there is no pressure to type it.
4. **No canonical field already covers it**: promotion introduces a new
   `EvidenceKind` variant or a new field on an existing canonical payload
   struct, not a duplicate of something `ExitCodePayload`/etc. already
   express.

When all four hold: add the typed payload struct (or extend an existing
one) in `fornax-types`, add it to `validate_canonical_payload`, migrate
producing sensors to emit the canonical shape (in `payload`, not
`extension`), and leave `extension` empty for that data going forward.
Existing persisted rows with the data still under `extension` are **not**
backfilled — `extension: None` alongside a populated `payload` and
`extension: Some(...)` for pre-promotion rows are both valid states a
consumer must tolerate, exactly as `Evidence::source == None` already
tolerates pre-FORNX-157 rows.

## Deprecation / migration rules

- A `schema_version` is added to `SUPPORTED_EXTENSION_SCHEMA_VERSIONS` when
  a change to the envelope's shape is **not** additive-safe under the
  unknown-field-tolerance mechanism above (e.g. a field's type or meaning
  changes under the same name — pure additions never require a new
  version).
- `EXTENSION_SCHEMA_VERSION` (the default new envelopes are stamped with) is
  bumped to the new version at the same time.
- An old version is dropped from `SUPPORTED_EXTENSION_SCHEMA_VERSIONS` only
  after every producer (both adapters, and any future adapter) has been
  migrated to the new version **and** no unmigrated historical data is
  expected to still be read (in v0.0.x, with no long-term archival
  requirement yet, this means: dropped in the same release that removes the
  last producer of the old shape). Dropping a version is what actually makes
  reads of it fail with the "incompatible" error — until dropped, an old
  supported version keeps parsing successfully forever, which is the
  compatibility guarantee this ADR's required tests pin down for two such
  versions.
- Fixtures for at least two live entries in `SUPPORTED_EXTENSION_SCHEMA_VERSIONS`
  are kept in `crates/fornax-types/src/extension.rs`'s test module
  (`historical_v1_envelope_fixture_still_reads_correctly`,
  `historical_v2_envelope_fixture_reads_correctly_and_is_the_current_default`)
  for as long as both versions remain supported, so a regression that
  silently breaks an old-but-supported version's parsing is caught in CI
  rather than discovered against real persisted data.

## Non-goals (explicit, FORNX-158 AC)

- **No generic schemaless event lake.** `fields`/`unknown` are the escape
  hatch, not the default path — canonical typed payloads
  (`validate_canonical_payload`) remain how broadly-shared evidence is
  represented. A code reviewer should be able to point at any given
  `Evidence` row and say whether it went through the canonical or extension
  path, and canonical must remain the common case.
- **No arbitrary code/plugin execution.** See "No dispatch on envelope
  content" above.
