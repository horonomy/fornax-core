# Evidence sensor/source contract (FORNX-157, extended FORNX-159)

Status: living doc, describes a shipped contract (`fornax_types::sensor`).
See `crates/fornax-types/src/sensor.rs` for the authoritative, compiled
definitions and doc comments — this file is the map of *why* it looks the
way it does and *what currently implements it*, not a restatement of the
Rust doc comments.

## Why this exists

Before FORNX-157, evidence collection was ad-hoc code inline in each
adapter's `translate()`/`translate_line()` — e.g.
`fornax-adapter-claude`'s Bash exit-code heuristic. That code already did
the right thing (checked capabilities, stamped a free-text `provenance`
string), but there was no shared shape a new collector — a Git sensor, a
CI-webhook sensor, a future reasoning/logprob sensor — could implement
uniformly, and no structured "how much do we trust this" metadata separate
from the free-text provenance breadcrumb.

## The two new types

- **`EvidenceSensor`** (trait): `name()`, `required_capabilities()`
  (`&'static [SignalClass]`, reusing FORNX-155's taxonomy),
  `trust_class()`, and `collect(event: &AgentEvent, caps: &RuntimeCapabilities)
  -> SensorOutcome`. One method, no registry — mirrors `CapabilityProbe`'s
  shape (FORNX-155) deliberately: capabilities are fixed at implementation
  time, not discovered at runtime.
- **`EvidenceSource`** (struct, attached to `Evidence::source: Option<..>`):
  `sensor_name`, `trust_class`, `collected_at`, `provider`. First-class
  metadata, not a string folded into the existing `Evidence::provenance`
  field — the two are complementary: `provenance` stays the granular
  "which branch fired" breadcrumb, `source` is the structured
  identity/trust record.

`SensorOutcome` is a struct (`evidence: Vec<Evidence>`, `state:
SignalAvailability`, `detail: Option<String>`), not an enum, specifically so
a sensor can report *partial* availability (some evidence collected, then a
capability gap or failure) without lying in either direction. A
sensor-internal timeout is reported as `state: SignalAvailability::CollectionFailed`
with a `detail` naming the timeout — there is no separate error type; this
reuses FORNX-155's existing taxonomy rather than inventing a parallel one.

## Trust classes

Named exactly per FORNX-138/FORNX-157:

| Class | Meaning | Current users |
|---|---|---|
| `AgentAdjacent` | The provider's own account of what happened (not independently measured) | `ClaudeBashExitCodeSensor`, `CodexExecCommandEndSensor`, `CodexCustomToolCallOutputSensor` |
| `HostObserved` | Fornax measured it itself (e.g. an exit code Fornax's own process captured, a `git` invocation Fornax ran) | none yet — no sensor collects independently of the provider today |
| `IndependentExternal` | A system outside both agent and host (CI webhook, third-party API) | none yet |
| `HumanReviewed` | Confirmed/entered by a person | none yet |
| `ModelInternal` | The model's own internals (reasoning summary, logprobs) | `ReasoningSummarySensor` (worked example only, see below) |

## Migrated paths (no behavior loss)

Three existing, real evidence-collection code paths were migrated onto
`EvidenceSensor`. In every case the heuristic logic itself is unchanged —
only its shape (a named `EvidenceSensor` impl instead of inline code) and
the evidence it emits (now additionally carrying `source`) changed. Proof:
every pre-existing test's assertions (exact `provenance` strings, exact
payload shapes, exact message counts) were left untouched and still pass —
see the crates' test suites.

| Sensor | Crate | Migrated from |
|---|---|---|
| `ClaudeBashExitCodeSensor` | `fornax-adapter-claude` | The inline Bash `tool_response` exit-code heuristic in `translate()` |
| `CodexExecCommandEndSensor` | `fornax-adapter-codex` | The inline `exec_command_end.exit_code` literal-field extraction in `translate_line()` |
| `CodexCustomToolCallOutputSensor` | `fornax-adapter-codex` | The inline `custom_tool_call_output` "Script completed" heuristic in `translate_line()` |

No CI-signal evidence collection exists in this codebase today — a
`CiSensor` was deliberately not built (FORNX-157 non-goal: don't
speculatively design sensors for signals that don't exist yet). Git
evidence collection now does exist (FORNX-14): `ClaudeGitOutcomeSensor`
(`fornax-adapter-claude`) parses `git commit`/`git push` output from a Bash
`tool_response` into `EvidenceKind::ProcessObservation` evidence (a
`ProcessObservationDetail::VcsOperation` payload — no new `EvidenceKind`
variant, per that enum's closed-enum doc comment). Unlike the migrated paths
above, its provenance ends `#tool_response:...`, not a heuristic tag: it
parses git's own real printed output, not a `tool_input` reconstruction.

## Worked example: a future `ReasoningSummarySensor`

`crates/fornax-types/src/sensor.rs`'s test module implements a compiled,
tested `ReasoningSummarySensor`: declares `SignalClass::ReasoningSummary`,
reports `TrustClass::ModelInternal`, and — because no provider integration
exposes that signal today — always reports
`SignalAvailability::Unsupported`. Adding it required zero changes to
`EvidenceSensor`, `EvidenceSource`, `Evidence`, or `Verifier`; it is purely
an additional implementor of the already-defined trait, exactly as a real
future sensor (reasoning summaries, logprobs, or other model-internal
telemetry) would attach.

## Persistence

`fornax-store` migration `0004_evidence_source.sql` adds a single nullable
`source` column to the existing `evidence` table (additive, matching
0002/0003's precedent). A `NULL` value round-trips as `Evidence::source ==
None` — an honest "no structured provenance recorded" for legacy rows or
evidence produced by code not yet migrated onto the sensor contract, not a
fabricated value. There is no legacy bool set to reconstruct from (unlike
`RuntimeCapabilities`'s FORNX-155 migration), so the reconstruction rule is
simply "absent column means unknown."

## What `Verifier` consumes

`fornax-verify`'s `Verifier` trait already took `evidence: &[Evidence]` —
the canonical domain type, never raw provider transport — before this
ticket. FORNX-157 did not change `Verifier`'s signature or algorithm; it
only added `source` as additional metadata on the `Evidence` values a
verifier already receives. A verifier may read `Evidence::source.trust_class`
in the future, but none does today — evidence weighting/fusion by trust
class is an explicit non-goal of this ticket.

## Explicit non-goals

- No dynamic plugin loading / sensor registry / discovery mechanism. A
  sensor is a concrete Rust type an adapter constructs and calls directly,
  same as before this ticket.
- No evidence weighting or fusion by trust class.

## FORNX-159: collection method, collector version, freshness, tamper boundary

FORNX-157 gave `EvidenceSource` an identity, a trust rating, a collection
timestamp, and an optional provider. FORNX-159 adds four more fields to that
*same* struct (not a new wrapper type — see "Design: why extend
`EvidenceSource`" below):

| Field | Type | Meaning |
|---|---|---|
| `collection_method` | `CollectionMethod` | *How* a sensor observed something — a different axis from `trust_class` ("how much"). `HookCallback`, `FilePoll`, `HttpWebhook`, `ProcessObservation`, `Reconstructed`, plus `PreProvenance`/`Unrecognized` (see "Honesty on old data" below). |
| `collector_version` | `Option<String>` | The producing sensor implementation's own version. Distinct from `ExtensionEnvelope::adapter_version` — see the type's doc comment for why these don't collapse into one field. |
| `freshness` | `Freshness { clock_source, caveat }` | Which clock a timestamp came from: `HostClock`, `ProviderReported`, `Reconstructed`, or `PreProvenance`, plus a free-text `caveat` for clock disagreement. |
| `tamper_boundary` | `TamperBoundary { description, detail }` | A human/UI-readable explanation of the trust boundary crossed, e.g. "captured via Claude Code's PostToolUse hook, running in-process with the agent, not independently verifiable." `description` comes from a small canned set keyed by `(TrustClass, CollectionMethod)` (`TamperBoundary::for_trust_class`), not freeform text a sensor author writes ad hoc. |

### Worked proof that collection method is a distinct axis from trust class

`ClaudeBashExitCodeSensor` and Codex's `CodexExecCommandEndSensor`/
`CodexCustomToolCallOutputSensor` are all `TrustClass::AgentAdjacent` — none
is independently verified, all report the provider's own account of what
happened. But Claude Code's sensor is `CollectionMethod::HookCallback` (an
in-process `PostToolUse` callback) and Codex's sensors are
`CollectionMethod::FilePoll` (tailing the always-on rollout JSONL file).
Trust class alone cannot tell those apart; `sensor.rs`'s
`hook_callback_and_file_poll_are_distinct_collection_methods_for_the_same_trust_class`
test proves the two axes vary independently and produce distinct canned
`tamper_boundary` text.

### Design: why extend `EvidenceSource`, not `ExtensionEnvelope`

FORNX-159's AC requires *every* evidence record to carry enough provenance
to explain who/what observed it. `ExtensionEnvelope` (FORNX-158) is `None`
in the common case by design — an opt-in escape hatch for provider-specific
data, not a place for metadata every record needs. `EvidenceSource` is
already the canonical "what produced this" home, so these fields extend it
directly.

### Design: no new `fornax-store` column

All of `EvidenceSource` — old fields and these new ones — persists as one
JSON blob in the `evidence.source` column added by `0004_evidence_source.sql`.
Adding named fields to a struct that already round-trips through one TEXT
column needs no new column: this is exactly the "additive change within a
version is the same shape, extra keys" reasoning `0005-schema-evolution.md`
already established for `ExtensionEnvelope`'s unknown-field tolerance. A new
column would duplicate data already inside the existing blob.

### Honesty on old data (FORNX-159 AC: "existing evidence is migrated with honest defaults/unknowns where history lacks detail")

`Evidence::source == None` (a pre-FORNX-157 record, or code never migrated
onto the sensor contract) is unaffected — still reads back as `None`, same
as before.

The new case FORNX-159 introduces: a record where `source` is *not* `None`
— trust class, sensor name, etc. are genuinely known (written by
FORNX-157-era code) — but the FORNX-159 fields didn't exist yet when it was
written. Each new field's `#[serde(default)]` produces an explicit,
distinctly-named unknown value on deserialize, never a fabricated
specific-sounding guess:

- `collection_method` defaults to `CollectionMethod::PreProvenance` — a
  *domain* fact ("no sensor declared a method when this record was
  written"), kept deliberately distinct from `Unrecognized` (a *parse-time*
  fact: "this binary doesn't know what this tag means"), mirroring
  `SignalAvailability::Unknown` vs. `Unrecognized`'s existing precedent
  (`crates/fornax-types/src/capabilities.rs`).
- `freshness.clock_source` defaults to `ClockSource::PreProvenance` the same
  way.
- `tamper_boundary` defaults to the literal description `"unknown (record
  predates tamper-boundary tracking)"` — not reconstructed from
  `trust_class`/`collection_method` even when those happen to be known,
  since a plausible-looking reconstruction is exactly what this AC forbids.
- `collector_version` defaults to `None`, which needed no special sentinel:
  an absent version has no fabricated-looking value to be confused with.

`fornax-store`'s
`pre_migration_evidence_source_reads_back_new_fields_as_honest_unknown` test
hand-inserts a genuine FORNX-157-shaped `source` JSON blob (no FORNX-159 keys
at all) and proves the full store round trip reads the old fields as known
and the new fields as the explicit pre-provenance markers above — not a
query error, not a fabricated value.

### Cloud-safe projection and replay

`fornax-cli`'s `evidence_envelope_carries_source_metadata_through_export`
test was extended to assert `collection_method`/`collector_version`/
`freshness`/`tamper_boundary` survive the same spool-export projection
boundary as the original FORNX-157 fields (evidence spools as-is — see the
FORNX-158 section above). `fornax-verify`'s
`evidence_source_provenance_is_unchanged_by_verification_and_stable_under_replay`
test proves a `Verifier` neither mutates nor drops this metadata while
computing a finding, across a first run and a replayed run.

### UI-distinguishability status

Neither `fornax-cli`'s `detail` command nor the daemon's `/dashboard` render
`Evidence` directly today — both operate on `Finding` rows joined to
`Claim`s (`fornax-daemon/src/main.rs::dashboard`,
`fornax-cli/src/main.rs`'s `Commands::Detail` -> `/api/findings/recent`).
There is currently no rendering surface where `trust_class`/
`collection_method` would even appear, so "UI can distinguish independent
external evidence from agent-adjacent evidence" has no code path to wire
today. The data model exposes everything a future renderer needs
(`Evidence::source.trust_class`, `.collection_method`,
`.tamper_boundary.description`, all preserved end to end per the sections
above). Follow-up (not in this ticket's scope): once evidence itself is
rendered anywhere (a future finding-detail or evidence-list view), route
`trust_class`/`tamper_boundary.description` into that view rather than
inventing a new evidence-rendering surface just for this ticket.
