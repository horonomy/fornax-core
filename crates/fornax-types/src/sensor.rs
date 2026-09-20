//! Sensor/source contract for evidence collection (FORNX-157, parent epic
//! FORNX-138).
//!
//! Today, evidence is produced by ad-hoc code inline in each adapter's
//! `translate()` (e.g. `fornax-adapter-claude`'s Bash exit-code heuristic).
//! That code already does the right thing — it checks
//! [`crate::RuntimeCapabilities`] before claiming a signal, and it stamps a
//! human-readable `provenance` string on every [`crate::Evidence`] it
//! produces. What it does not do is expose that shape as a *contract* other
//! collectors (a Git sensor, a CI-webhook sensor, a future
//! reasoning/logprob sensor) can implement uniformly, or attach *structured*
//! provenance/trust metadata that survives a join-free read.
//!
//! This module formalizes that as two things:
//!
//! - [`EvidenceSource`]: a structured "what produced this, and how much do
//!   we trust it" record, attached to [`crate::Evidence::source`]. Replaces
//!   ad-hoc free-text provenance strings as far as trust/collector identity
//!   is concerned — `Evidence::provenance` (the existing field) stays as the
//!   more granular "handler/branch that fired" breadcrumb (e.g.
//!   `"claude_code:PostToolUse:Bash#heuristic:stderr_empty"`); the two are
//!   complementary, not a replacement of one by the other.
//! - [`EvidenceSensor`]: the trait a collector implements. Deliberately one
//!   method (`collect`) plus two capability-declaration accessors, mirroring
//!   [`crate::CapabilityProbe`]'s "one method, no registry, no dynamic
//!   negotiation" shape (FORNX-155) for the same reason: a sensor's declared
//!   capabilities are fixed at implementation time, not discovered at
//!   runtime. This is deliberate — see the module's non-goals below.
//!
//! # Extended provenance (FORNX-159, parent epic FORNX-138)
//!
//! FORNX-157 gave `EvidenceSource` an identity (`sensor_name`), a trust
//! rating (`trust_class`), a collection timestamp, and an optional owning
//! `provider`. It deliberately left four things out, which this ticket adds
//! as more fields on the *same* struct (not a new wrapper — see the ticket's
//! design note below):
//!
//! - [`CollectionMethod`]: *how* a sensor observed something, independent of
//!   *how much it's trusted*. `ClaudeBashExitCodeSensor` and Codex's rollout
//!   sensors are both [`TrustClass::AgentAdjacent`] (neither is independently
//!   verified — both report the provider's own account of what happened),
//!   but one is a [`CollectionMethod::HookCallback`] (an in-process
//!   PostToolUse hook invocation) and the other is
//!   [`CollectionMethod::FilePoll`] (tailing the always-on rollout JSONL
//!   file). Trust class alone cannot tell those apart; a real future
//!   CI-webhook sensor would need [`CollectionMethod::HttpWebhook`] on top of
//!   its own (likely higher) trust class. Two independent axes, not one
//!   collapsed into the other.
//! - `collector_version`: the *sensor's own* implementation version.
//!   Distinct from [`crate::ExtensionEnvelope::adapter_version`] (which
//!   version of the *provider adapter crate* produced a provider-specific
//!   extension payload) — an adapter crate can ship multiple sensors that
//!   version independently in principle, and `EvidenceSource` is the
//!   canonical provenance home attached to *every* evidence record, while
//!   `extension` is `None` in the common case (see `extension.rs`'s "escape
//!   hatch, not the default path"). Reusing `adapter_version` here would tie
//!   canonical provenance to an optional field that most evidence never
//!   carries.
//! - [`Freshness`]: which clock a `collected_at`-style timestamp actually
//!   came from (`ClockSource::HostClock` — Fornax's own wall clock,
//!   `ClockSource::ProviderReported` — the provider stamped its own
//!   timestamp on the underlying event, `ClockSource::Reconstructed` —
//!   derived after the fact from other data), plus a free-text caveat for
//!   the case clocks disagree (e.g. a provider timestamp observed to be
//!   skewed from the host clock it was compared against).
//! - [`TamperBoundary`]: a UI/human-readable explanation of the trust
//!   boundary a piece of evidence crossed, e.g. "captured via Claude Code's
//!   PostToolUse hook, running in-process with the agent, not independently
//!   verifiable" — not just the [`TrustClass`] tag. Deliberately a small
//!   canned set keyed by `(TrustClass, CollectionMethod)`
//!   ([`TamperBoundary::for_trust_class`]) plus room for a sensor-supplied
//!   `detail` string, not freeform text a sensor author invents each time —
//!   see the type's own doc comment.
//!
//! ## Design note: extend `EvidenceSource`, not a new envelope
//!
//! FORNX-159's AC requires *every* evidence record to carry enough
//! provenance to explain who/what observed it. [`ExtensionEnvelope`]
//! (`crate::extension`, FORNX-158) is `None` in the common case by design —
//! it is an opt-in escape hatch for provider-specific data that doesn't
//! warrant a canonical field, not a place to put metadata every record
//! needs. `EvidenceSource` is already the canonical "what produced this"
//! home attached to `Evidence::source`, so these fields extend it directly.
//!
//! ## Design note: no new `fornax-store` column
//!
//! `EvidenceSource` (all of it, old fields and these new ones) persists as
//! one JSON blob in the `evidence.source` column added by
//! `migrations/0004_evidence_source.sql`. Per `docs/adr/0005-schema-evolution.md`'s
//! own framing (adopted here for the same struct-serialization reason,
//! adapted from the extension envelope's `schema_version`/unknown-field
//! discussion): "an additive change within a version is exactly the same
//! shape, extra keys." Adding named fields to a struct that already
//! round-trips through one TEXT column needs no new column — a new column
//! would duplicate data that is already inside the existing JSON blob and
//! contradict that precedent. What *is* required, and is added below, is
//! the honesty guarantee for old data: every new field defaults — via
//! `#[serde(default)]` — to an explicit, distinctly-tagged
//! "pre-provenance"/unknown value on deserialize, never to a
//! plausible-looking guess. See `fornax-store`'s
//! `pre_migration_evidence_source_reads_back_new_fields_as_honest_unknown`
//! test for the proof this isn't just a doc claim.
//!
//! # Non-goals (explicit, FORNX-157 AC)
//!
//! - **No dynamic plugin loading.** A sensor is a concrete Rust type an
//!   adapter or the daemon constructs and calls directly, the same way
//!   `translate()` already calls its heuristic functions directly. There is
//!   no sensor registry, no `Box<dyn EvidenceSensor>` dispatch table, no
//!   discovery mechanism.
//! - **No evidence weighting/fusion.** A sensor either collects evidence or
//!   explains why it didn't ([`SensorOutcome`]); nothing here scores,
//!   ranks, or merges evidence from multiple sensors. That stays entirely
//!   out of scope, same as it is for [`crate::Verifier`]-adjacent code today
//!   (verifiers consume already-collected `Evidence`, they don't produce
//!   or arbitrate it).
//!
//! # Worked example: a future `ReasoningSummarySensor`
//!
//! FORNX-157 AC requires showing how a not-yet-built signal (a provider's
//! reasoning/chain-of-thought summary, logprobs, or other model-internal
//! telemetry) would attach to this contract without a core rewrite. The
//! `sensor_tests` module below implements exactly this, compiled and
//! tested: a `ReasoningSummarySensor` that declares
//! [`crate::SignalClass::ReasoningSummary`], reports
//! [`TrustClass::ModelInternal`], and — because no provider integration
//! exposes that signal yet — always returns
//! [`crate::SignalAvailability::Unsupported`] from `collect`. No change to
//! `EvidenceSensor`, `EvidenceSource`, `Evidence`, or `Verifier` was needed
//! to add it; it exists purely as an additional implementor of the trait
//! already defined here, exactly as a real future sensor would.

use serde::{Deserialize, Serialize};

use crate::{AgentEvent, Evidence, Provider, RuntimeCapabilities, SignalAvailability, SignalClass};

/// How much a piece of evidence's *origin* should be trusted, independent of
/// its content. Named exactly per FORNX-138/FORNX-157's taxonomy — do not
/// rename variants without updating the ticket-referenced vocabulary.
///
/// Attached to [`EvidenceSource`], not [`Evidence`] directly, so it always
/// travels with the rest of "what produced this" rather than living as a
/// second, easily-desynced tag on `Evidence` itself.
///
/// Carries the same `#[serde(untagged)] Unrecognized(String)` forward-compat
/// tail as [`SignalClass`]/[`SignalAvailability`] (FORNX-155 precedent) — a
/// persisted `EvidenceSource` is exactly as durable a payload as a persisted
/// `RuntimeCapabilities`, and must tolerate a future variant the same way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// Reported by the coding agent's own provider integration (e.g. Claude
    /// Code's `tool_response`, Codex's rollout JSONL) — the provider's own
    /// account of what happened, not independently measured by Fornax.
    AgentAdjacent,
    /// Measured directly by Fornax's own local tooling (a literal process
    /// exit code Fornax captured itself, a `git` invocation Fornax ran) —
    /// independent of what the provider claims happened.
    HostObserved,
    /// From a system outside both the agent and the local host — a CI
    /// webhook, a third-party API result.
    IndependentExternal,
    /// Confirmed or entered by a person, not inferred from any automated
    /// signal.
    HumanReviewed,
    /// From the model's own internals (reasoning summaries, logprobs,
    /// other provider-internal telemetry) — see [`crate::SignalClass::ReasoningSummary`]
    /// / [`crate::SignalClass::RawReasoning`] / [`crate::SignalClass::TokenLogprobs`].
    ModelInternal,
    /// Forward-compatibility catch-all, matching
    /// [`crate::SignalAvailability::Unrecognized`]'s round-trip guarantee.
    /// Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// *How* a sensor observed something, independent of *how much it's
/// trusted* ([`TrustClass`]) — see the module docs' worked example
/// (`ClaudeBashExitCodeSensor` vs. Codex's rollout sensors: both
/// `AgentAdjacent`, different methods).
///
/// Carries the same explicit-`Unknown`-vs-`Unrecognized` split as
/// [`crate::SignalAvailability`] (`crates/fornax-types/src/capabilities.rs`),
/// for the same reason spelled out there: `PreProvenance` is a *domain*
/// fact ("no sensor declared a method when this record was written, because
/// the field didn't exist yet"), `Unrecognized` is a *parse-time* fact
/// ("this binary doesn't know what this tag means"). Conflating them would
/// make it impossible to tell a FORNX-157-era record apart from a stale
/// binary reading a genuinely newer tag.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMethod {
    /// An in-process callback invoked synchronously by the provider around
    /// an action (e.g. Claude Code's `PostToolUse` hook).
    HookCallback,
    /// Tailing or periodically reading a file the provider writes on its
    /// own schedule (e.g. Codex's always-on rollout JSONL transcript).
    FilePoll,
    /// Received via an inbound HTTP request from an external system (e.g. a
    /// future CI webhook sensor). Not implemented by any sensor yet — typed
    /// ahead of a producer, same as `SignalClass::ReasoningSummary`.
    HttpWebhook,
    /// Fornax's own host-side process invocation (e.g. a literal `git`
    /// command Fornax ran itself), as opposed to reading something a
    /// provider produced.
    ProcessObservation,
    /// Derived after the fact from other already-collected data, rather
    /// than observed directly at collection time.
    Reconstructed,
    /// The honest default for a record that predates this field entirely
    /// (deserializing a FORNX-157-era `EvidenceSource` JSON blob that never
    /// had a `collection_method` key) — never a guessed real method. See
    /// the module docs' "no new `fornax-store` column" design note. Also the
    /// `#[serde(default)]` value for a missing `collection_method` key.
    #[serde(rename = "pre_provenance")]
    #[default]
    PreProvenance,
    /// Forward-compatibility catch-all, matching [`TrustClass::Unrecognized`]'s
    /// round-trip guarantee. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// Which clock a timestamp attached to a piece of evidence actually came
/// from. Distinct axis from [`CollectionMethod`]/[`TrustClass`] — a
/// hook-callback sensor can still report a provider-stamped timestamp if the
/// provider's own payload carries one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockSource {
    /// Fornax's own wall clock at collection time (e.g. `chrono::Utc::now()`
    /// in [`EvidenceSource::now`]).
    HostClock,
    /// The provider's own timestamp, taken from its payload verbatim.
    ProviderReported,
    /// Derived after the fact (e.g. inferred from surrounding events) rather
    /// than read directly from either clock at collection time.
    Reconstructed,
    /// Honest default for a record predating this field — see
    /// [`CollectionMethod::PreProvenance`] for the identical reasoning. Also
    /// the `#[serde(default)]` value for a missing `clock_source` key.
    #[serde(rename = "pre_provenance")]
    #[default]
    PreProvenance,
    /// Forward-compatibility catch-all. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// Timestamp provenance for one [`EvidenceSource`]: which clock produced
/// `collected_at`, plus an optional caveat when clocks disagree (e.g. a
/// provider-reported timestamp observed skewed against the host clock it
/// was compared to). A struct rather than bare `ClockSource` so a sensor can
/// attach a caveat without a second top-level `EvidenceSource` field.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Freshness {
    #[serde(default)]
    pub clock_source: ClockSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caveat: Option<String>,
}

/// Human/UI-readable explanation of the trust boundary a piece of evidence
/// crossed — richer than the bare [`TrustClass`] tag, e.g. "captured via
/// Claude Code's PostToolUse hook, running in-process with the agent, not
/// independently verifiable". Deliberately a small canned set keyed by
/// `(TrustClass, CollectionMethod)` via [`TamperBoundary::for_trust_class`],
/// not freeform text a sensor author writes ad hoc each time — freeform text
/// would let the same trust class read wildly differently across sensors
/// for no reason a UI or a future fusion algorithm could rely on. `detail`
/// is the intentional escape hatch for sensor-specific specifics the canned
/// `description` doesn't capture (e.g. a literal file path polled).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperBoundary {
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Default for TamperBoundary {
    /// Honest default for a record predating this field: says plainly that
    /// no boundary description was recorded, rather than guessing one from
    /// whatever `trust_class`/`collection_method` happen to deserialize to
    /// (both of which may *themselves* be `PreProvenance` on the same
    /// record, but are not guaranteed to be — this default does not attempt
    /// to cross-reference them).
    fn default() -> Self {
        Self {
            description: "unknown (record predates tamper-boundary tracking)".to_string(),
            detail: None,
        }
    }
}

impl TamperBoundary {
    /// The canned description for a given `(trust_class, collection_method)`
    /// pair. Every real named `TrustClass` variant has a canned sentence;
    /// `Unrecognized`/`PreProvenance`-style inputs fall back to a generic but
    /// still honest description rather than panicking or fabricating
    /// specifics. `detail` starts empty — callers append sensor-specific
    /// detail via the returned value's `detail` field.
    pub fn for_trust_class(trust_class: &TrustClass, collection_method: &CollectionMethod) -> Self {
        let description = match (trust_class, collection_method) {
            // Checked first, regardless of trust_class: a `PreProvenance`/
            // `Unrecognized` collection method means this binary cannot
            // vouch for *how* the evidence was collected, so it must not
            // synthesize a confident boundary sentence from trust_class
            // alone — that would fabricate exactly the specific-sounding
            // description the FORNX-159 AC forbids for a record whose
            // collection method genuinely is not known.
            (_, CollectionMethod::PreProvenance) => {
                "unknown (record predates collection-method tracking)"
            }
            (_, CollectionMethod::Unrecognized(_)) => {
                "collection method not recognized by this binary — boundary unknown, see \
                 the raw collection_method tag"
            }
            (TrustClass::AgentAdjacent, CollectionMethod::HookCallback) => {
                "captured via an in-process hook callback invoked by the coding agent \
                 itself — the agent's own account of what happened, running in-process \
                 with it, not independently verifiable"
            }
            (TrustClass::AgentAdjacent, CollectionMethod::FilePoll) => {
                "captured by tailing a transcript/log file the coding agent writes on \
                 its own schedule — the agent's own account of what happened, not \
                 independently verifiable, though observed out-of-process from a file \
                 rather than via an in-process callback"
            }
            (TrustClass::AgentAdjacent, _) => {
                "the coding agent's own account of what happened, not independently \
                 verified by Fornax"
            }
            (TrustClass::HostObserved, _) => {
                "measured directly by Fornax's own local tooling (e.g. a process exit \
                 code or command Fornax ran itself), independent of what the agent \
                 claims happened"
            }
            (TrustClass::IndependentExternal, _) => {
                "reported by a system outside both the coding agent and the local host \
                 (e.g. a CI webhook or third-party API) — independent of both the agent \
                 and Fornax's own host observation"
            }
            (TrustClass::HumanReviewed, _) => {
                "confirmed or entered by a person, not inferred from any automated signal"
            }
            (TrustClass::ModelInternal, _) => {
                "derived from the model's own internal telemetry (reasoning summary, \
                 logprobs, or similar provider-internal signal), not externally verified"
            }
            (TrustClass::Unrecognized(_), _) => {
                "trust class not recognized by this binary — boundary unknown, see the \
                 raw trust_class tag"
            }
        };
        Self {
            description: description.to_string(),
            detail: None,
        }
    }

    /// Attach a sensor-specific detail string (e.g. a polled file path) to
    /// an existing canned boundary.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Structured identity/provenance for one piece of [`Evidence`]: which
/// sensor produced it, when, from which adapter/provider connection, how
/// much its origin should be trusted, how it was collected, which clock its
/// timestamp came from, and a human-readable description of the trust
/// boundary it crossed. First-class metadata (a struct), not a string tag
/// folded into `Evidence::provenance`.
///
/// `None` on [`Evidence::source`] means exactly what it says: this evidence
/// predates the sensor contract (FORNX-157) or was constructed by code that
/// has not been migrated onto it yet — not "trust unknown" in some deeper
/// sense. See `fornax-store`'s migration for the on-disk equivalent.
///
/// `collection_method`, `freshness`, and `tamper_boundary` were added by
/// FORNX-159 on top of FORNX-157's original four fields — see the module
/// docs' "Extended provenance" section. Each defaults, via
/// `#[serde(default)]`, to an explicit "pre-provenance" value on
/// deserialize, so a `Some(EvidenceSource { .. })` written before FORNX-159
/// (trust class *is* known — this is not the `Evidence::source == None`
/// case) still reads back honestly: known fields stay known, new fields
/// read as explicit unknowns, never fabricated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSource {
    /// The producing sensor's stable name (mirrors [`crate::Verifier::name`]
    /// — a `&'static str` identity, stored as an owned `String` here because
    /// it crosses serialization, unlike a verifier's in-process-only name).
    pub sensor_name: String,
    pub trust_class: TrustClass,
    /// RFC3339 timestamp the sensor collected this evidence. Distinct from
    /// `Evidence::observed_at`, which is when the underlying event was
    /// observed — a sensor may run its collection step after the event it
    /// reads from was already recorded.
    pub collected_at: String,
    /// Which adapter/provider connection this sensor was running under, if
    /// applicable. `None` for a sensor with no single owning provider (e.g.
    /// a future host-level Git sensor that isn't tied to any one adapter
    /// connection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
    /// How this sensor observed its input (FORNX-159) — see
    /// [`CollectionMethod`].
    #[serde(default)]
    pub collection_method: CollectionMethod,
    /// The producing sensor implementation's own version, independent of
    /// `crate::ExtensionEnvelope::adapter_version` — see the module docs'
    /// "Extended provenance" section for why these are two distinct fields.
    /// `None` means no version was recorded (a pre-FORNX-159 record, or a
    /// sensor that doesn't track one) — this is already an honest "we don't
    /// have that" and needs no separate sentinel, unlike the enum fields
    /// above (there is no plausible-looking fabricated version string this
    /// could be confused with).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collector_version: Option<String>,
    /// Which clock `collected_at` (and any other timestamp this evidence
    /// carries) actually came from, plus a caveat if clocks disagreed
    /// (FORNX-159) — see [`Freshness`].
    #[serde(default)]
    pub freshness: Freshness,
    /// Human/UI-readable trust-boundary explanation (FORNX-159) — see
    /// [`TamperBoundary`].
    #[serde(default)]
    pub tamper_boundary: TamperBoundary,
}

impl EvidenceSource {
    /// Convenience constructor stamping `collected_at` as now (host clock —
    /// the common case for a sensor producing evidence synchronously from
    /// live input) and deriving a canned `tamper_boundary` from
    /// `trust_class`/`collection_method`.
    pub fn now(
        sensor_name: &'static str,
        trust_class: TrustClass,
        provider: Option<Provider>,
        collection_method: CollectionMethod,
        collector_version: Option<String>,
    ) -> Self {
        let tamper_boundary = TamperBoundary::for_trust_class(&trust_class, &collection_method);
        Self {
            sensor_name: sensor_name.to_string(),
            trust_class,
            collected_at: chrono::Utc::now().to_rfc3339(),
            provider,
            collection_method,
            collector_version,
            freshness: Freshness {
                clock_source: ClockSource::HostClock,
                caveat: None,
            },
            tamper_boundary,
        }
    }
}

/// Result of one [`EvidenceSensor::collect`] call. A struct rather than an
/// enum with `Collected`/`Unavailable`/`Failed` variants because a sensor
/// must be able to report *partial* availability honestly: e.g. a
/// hypothetical multi-file diff sensor that produced evidence for two of
/// three changed files before hitting a permission error on the third must
/// not be forced to choose between silently dropping the two it got or
/// lying about the one it didn't.
///
/// Reading the four combinations:
/// - `state: Available`, `evidence` non-empty — normal success.
/// - `state: Available`, `evidence` empty — the sensor ran, its required
///   capabilities are observable, but there was nothing evidentiary to
///   report this call (e.g. a Bash call with no recognizable exit-code
///   shape at all — see `fornax-adapter-claude`'s heuristic fallback).
/// - `state` not `Available`, `evidence` non-empty — partial collection:
///   some evidence was produced before/alongside a failure or capability
///   gap. Callers must not discard the evidence just because `state` isn't
///   clean.
/// - `state` not `Available`, `evidence` empty — clean non-collection: the
///   sensor could not observe anything at all, `state` says why
///   ([`SignalAvailability::Unsupported`]/`Unavailable`/`Redacted`/
///   `CollectionFailed`/`Unknown`).
///
/// A sensor-internal timeout is reported as `state: CollectionFailed` with
/// `detail` naming the timeout — there is no separate `SensorError` type.
/// This reuses [`SignalAvailability`]'s existing "we tried and it errored"
/// variant rather than inventing a parallel failure taxonomy (FORNX-157 AC:
/// unavailability/failure returns use `SignalAvailability`).
#[derive(Debug, Clone)]
pub struct SensorOutcome {
    pub evidence: Vec<Evidence>,
    pub state: SignalAvailability,
    pub detail: Option<String>,
}

impl SensorOutcome {
    /// Normal success: one or more evidence items, capability confirmed
    /// available.
    pub fn collected(evidence: Vec<Evidence>) -> Self {
        Self {
            evidence,
            state: SignalAvailability::Available,
            detail: None,
        }
    }

    /// Capability confirmed available, but nothing evidentiary to report
    /// this call.
    pub fn nothing_to_report() -> Self {
        Self {
            evidence: vec![],
            state: SignalAvailability::Available,
            detail: None,
        }
    }

    /// Clean non-collection: no evidence, `state` explains why (must not be
    /// `Available` — use `collected`/`nothing_to_report` for that).
    pub fn not_collected(state: SignalAvailability, detail: impl Into<Option<String>>) -> Self {
        Self {
            evidence: vec![],
            state,
            detail: detail.into(),
        }
    }

    /// True only when at least one evidence item was produced, regardless
    /// of `state` (partial collection still counts).
    pub fn has_evidence(&self) -> bool {
        !self.evidence.is_empty()
    }
}

/// Contract for a component that observes something and turns it into
/// canonical [`Evidence`], the observation-collection side of the
/// "immutable observation before interpretation" invariant
/// (`docs/adr/0001-architecture-invariants.md`). A sensor must never
/// interpret/verify — that's [`crate::Verifier`]'s job, downstream of
/// already-collected evidence.
///
/// Implementors live in the adapter/collector crate that owns the raw input
/// a sensor reads (e.g. `fornax-adapter-claude` owns `ClaudeBashExitCodeSensor`
/// because it owns the Claude Code `tool_response` shape), not in
/// `fornax-types` itself — this trait is the shared contract, not a place to
/// centralize collection logic (adapters stay thin, D5, but the *shape* they
/// implement is now uniform).
pub trait EvidenceSensor {
    /// Stable identity, stamped onto every [`EvidenceSource::sensor_name`]
    /// this sensor produces.
    fn name(&self) -> &'static str;

    /// The [`SignalClass`]es this sensor needs `Available` to collect
    /// anything at all. A sensor may still choose to check `caps` itself
    /// inside `collect` for finer-grained partial-availability behavior;
    /// this is the coarse declaration a caller can use to skip calling
    /// `collect` entirely when nothing is observable.
    fn required_capabilities(&self) -> &'static [SignalClass];

    /// How much this sensor's output should be trusted, attached to every
    /// [`EvidenceSource`] it stamps.
    fn trust_class(&self) -> TrustClass;

    /// How this sensor observes its input (FORNX-159), attached to every
    /// [`EvidenceSource`] it stamps — a fixed property of the sensor
    /// *implementation* (a hook-callback sensor doesn't become a file-poll
    /// sensor mid-session), same as `trust_class` above. See
    /// [`CollectionMethod`]'s doc for why this is a separate axis from trust.
    fn collection_method(&self) -> CollectionMethod;

    /// This sensor implementation's own version, if it tracks one. Default
    /// `None` — most sensors so far are versioned only via their owning
    /// adapter crate's `CARGO_PKG_VERSION`; a sensor that wants to expose
    /// that should override this.
    fn collector_version(&self) -> Option<String> {
        None
    }

    /// Attempt to collect evidence from `event`, given what `caps` says is
    /// currently observable. Must not block indefinitely — a sensor backed
    /// by a genuinely slow/remote source (a future CI-webhook sensor) is
    /// responsible for enforcing its own budget and reporting
    /// `SignalAvailability::CollectionFailed` with a `detail` naming the
    /// timeout, rather than this trait imposing an OS-level deadline no
    /// sensor implemented so far actually needs.
    fn collect(&self, event: &AgentEvent, caps: &RuntimeCapabilities) -> SensorOutcome;

    /// Convenience: true only if every required capability is confirmed
    /// `Available`. Sensors with partial-availability behavior should not
    /// rely on this alone inside `collect` — see the trait doc.
    fn is_ready(&self, caps: &RuntimeCapabilities) -> bool {
        self.required_capabilities()
            .iter()
            .all(|c| caps.is_observable(c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilitySignal, EventKind, EvidenceKind};
    use uuid::Uuid;

    fn caps_with(signals: Vec<CapabilitySignal>) -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: crate::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals,
            notes: Default::default(),
        }
    }

    fn dummy_event() -> AgentEvent {
        AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: None,
            tool_response: None,
            raw: serde_json::json!({}),
        }
    }

    // --- TrustClass round-trip (FORNX-155 precedent) --------------------

    #[test]
    fn unrecognized_trust_class_tag_round_trips_the_original_string() {
        let json = r#""quantum_verified""#;
        let v: TrustClass = serde_json::from_str(json).unwrap();
        assert_eq!(v, TrustClass::Unrecognized("quantum_verified".to_string()));
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn every_canonical_trust_class_tag_round_trips_to_its_named_variant() {
        let cases = [
            ("\"agent_adjacent\"", TrustClass::AgentAdjacent),
            ("\"host_observed\"", TrustClass::HostObserved),
            ("\"independent_external\"", TrustClass::IndependentExternal),
            ("\"human_reviewed\"", TrustClass::HumanReviewed),
            ("\"model_internal\"", TrustClass::ModelInternal),
        ];
        for (json, expected) in cases {
            let v: TrustClass = serde_json::from_str(json).unwrap();
            assert_eq!(v, expected, "tag {json} did not parse to its named variant");
        }
    }

    // --- EvidenceSource round-trip ---------------------------------------

    #[test]
    fn evidence_source_serializes_and_round_trips() {
        let src = EvidenceSource::now(
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
            Some(Provider::ClaudeCode),
            CollectionMethod::HookCallback,
            Some("claude-adapter-0.3.0".to_string()),
        );
        let json = serde_json::to_string(&src).unwrap();
        let back: EvidenceSource = serde_json::from_str(&json).unwrap();
        assert_eq!(src, back);
    }

    // --- FORNX-159: extended provenance fields ----------------------------

    #[test]
    fn collection_method_and_clock_source_default_to_pre_provenance_when_missing() {
        // A FORNX-157-era EvidenceSource JSON blob: trust_class *is* known,
        // but none of the FORNX-159 fields were ever written.
        let json = r#"{
            "sensor_name": "claude_bash_exit_code_sensor_v1",
            "trust_class": "agent_adjacent",
            "collected_at": "2026-01-01T00:00:00Z",
            "provider": "claude_code"
        }"#;
        let src: EvidenceSource = serde_json::from_str(json).unwrap();
        assert_eq!(
            src.trust_class,
            TrustClass::AgentAdjacent,
            "known field stays known"
        );
        assert_eq!(
            src.collection_method,
            CollectionMethod::PreProvenance,
            "missing field must read as an explicit pre-provenance marker, not a guessed method"
        );
        assert_eq!(src.collector_version, None);
        assert_eq!(src.freshness.clock_source, ClockSource::PreProvenance);
        assert_eq!(src.freshness.caveat, None);
        assert_eq!(
            src.tamper_boundary.description,
            "unknown (record predates tamper-boundary tracking)"
        );
    }

    #[test]
    fn unrecognized_collection_method_tag_round_trips_the_original_string() {
        let json = r#""quantum_intercept""#;
        let v: CollectionMethod = serde_json::from_str(json).unwrap();
        assert_eq!(
            v,
            CollectionMethod::Unrecognized("quantum_intercept".to_string())
        );
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn every_canonical_collection_method_tag_round_trips_to_its_named_variant() {
        let cases = [
            ("\"hook_callback\"", CollectionMethod::HookCallback),
            ("\"file_poll\"", CollectionMethod::FilePoll),
            ("\"http_webhook\"", CollectionMethod::HttpWebhook),
            (
                "\"process_observation\"",
                CollectionMethod::ProcessObservation,
            ),
            ("\"reconstructed\"", CollectionMethod::Reconstructed),
            ("\"pre_provenance\"", CollectionMethod::PreProvenance),
        ];
        for (json, expected) in cases {
            let v: CollectionMethod = serde_json::from_str(json).unwrap();
            assert_eq!(v, expected, "tag {json} did not parse to its named variant");
        }
    }

    #[test]
    fn unrecognized_clock_source_tag_round_trips_the_original_string() {
        let json = r#""atomic_clock""#;
        let v: ClockSource = serde_json::from_str(json).unwrap();
        assert_eq!(v, ClockSource::Unrecognized("atomic_clock".to_string()));
        let back = serde_json::to_string(&v).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn hook_callback_and_file_poll_are_distinct_collection_methods_for_the_same_trust_class() {
        // The module docs' worked example: two sensors, same trust class,
        // different collection method — proves the two are independent axes.
        let hook = EvidenceSource::now(
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
            Some(Provider::ClaudeCode),
            CollectionMethod::HookCallback,
            None,
        );
        let poll = EvidenceSource::now(
            "codex_exec_command_end_sensor_v1",
            TrustClass::AgentAdjacent,
            Some(Provider::Codex),
            CollectionMethod::FilePoll,
            None,
        );
        assert_eq!(hook.trust_class, poll.trust_class);
        assert_ne!(hook.collection_method, poll.collection_method);
        assert_ne!(
            hook.tamper_boundary.description, poll.tamper_boundary.description,
            "distinct collection methods must produce distinct canned tamper-boundary text"
        );
    }

    #[test]
    fn tamper_boundary_detail_is_appended_without_losing_the_canned_description() {
        let boundary = TamperBoundary::for_trust_class(
            &TrustClass::HostObserved,
            &CollectionMethod::ProcessObservation,
        )
        .with_detail("git status --porcelain");
        assert!(boundary.description.contains("measured directly"));
        assert_eq!(boundary.detail.as_deref(), Some("git status --porcelain"));
    }

    #[test]
    fn for_trust_class_reports_honest_unknown_when_collection_method_is_not_known() {
        // A known, high-confidence trust_class must not make `for_trust_class`
        // synthesize a confident boundary sentence when the collection
        // method itself is unknown — that would fabricate specifics this
        // binary cannot actually vouch for (the exact failure mode FORNX-159's
        // AC forbids).
        let pre_provenance = TamperBoundary::for_trust_class(
            &TrustClass::AgentAdjacent,
            &CollectionMethod::PreProvenance,
        );
        assert_eq!(
            pre_provenance.description,
            "unknown (record predates collection-method tracking)"
        );

        let unrecognized = TamperBoundary::for_trust_class(
            &TrustClass::HostObserved,
            &CollectionMethod::Unrecognized("quantum_intercept".to_string()),
        );
        assert!(unrecognized.description.contains("not recognized"));
    }

    #[test]
    fn pre_provenance_tag_serializes_to_itself_not_unrecognized() {
        // Guards against the exact asymmetry `SignalAvailability::from_tag`'s
        // doc warns about: `Unrecognized("pre_provenance")` round-trips fine,
        // but the named `PreProvenance` variant must itself serialize back
        // to the `"pre_provenance"` tag, not something that would re-parse
        // as the catch-all.
        let json = serde_json::to_string(&CollectionMethod::PreProvenance).unwrap();
        assert_eq!(json, "\"pre_provenance\"");
        let back: CollectionMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CollectionMethod::PreProvenance);

        let json = serde_json::to_string(&ClockSource::PreProvenance).unwrap();
        assert_eq!(json, "\"pre_provenance\"");
        let back: ClockSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ClockSource::PreProvenance);
    }

    // --- SensorOutcome partial-availability combinations ------------------

    #[test]
    fn sensor_outcome_supports_partial_availability_with_evidence_and_a_non_available_state() {
        let ev = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test:partial".into(),
            source: None,
            extension: None,
        };
        let outcome = SensorOutcome {
            evidence: vec![ev.clone()],
            state: SignalAvailability::CollectionFailed,
            detail: Some("collected one of two expected items before erroring".to_string()),
        };
        assert!(outcome.has_evidence());
        assert_ne!(outcome.state, SignalAvailability::Available);
    }

    #[test]
    fn not_collected_is_clean_when_no_evidence_and_non_available_state() {
        let outcome = SensorOutcome::not_collected(
            SignalAvailability::Unsupported,
            Some("runtime cannot expose this signal".to_string()),
        );
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unsupported);
    }

    // --- Worked example: a future ReasoningSummarySensor ------------------
    // FORNX-157 AC: docs must show how a future reasoning/logprob/internal
    // signal sensor would attach without core rewrites. This is that
    // example, compiled and exercised — no provider integration exposes
    // this signal today, so `collect` always reports `Unsupported`.

    struct ReasoningSummarySensor;

    impl EvidenceSensor for ReasoningSummarySensor {
        fn name(&self) -> &'static str {
            "reasoning_summary_sensor_v1"
        }

        fn required_capabilities(&self) -> &'static [SignalClass] {
            &[SignalClass::ReasoningSummary]
        }

        fn trust_class(&self) -> TrustClass {
            TrustClass::ModelInternal
        }

        fn collection_method(&self) -> CollectionMethod {
            // A future real implementation would extract this from the
            // model's own response stream in-process, same shape as a hook
            // callback — no provider exposes it yet, so this is illustrative.
            CollectionMethod::HookCallback
        }

        fn collect(&self, _event: &AgentEvent, caps: &RuntimeCapabilities) -> SensorOutcome {
            if !self.is_ready(caps) {
                return SensorOutcome::not_collected(
                    SignalAvailability::Unsupported,
                    Some(
                        "no provider integration exposes reasoning-summary content yet".to_string(),
                    ),
                );
            }
            // Unreachable today (no provider ever declares this class
            // Available), but a real implementation would extract the
            // summary from `event.raw` here and return
            // `SensorOutcome::collected(vec![...])`.
            SensorOutcome::nothing_to_report()
        }
    }

    #[test]
    fn future_reasoning_summary_sensor_attaches_via_the_existing_trait_with_no_core_changes() {
        let sensor = ReasoningSummarySensor;
        assert_eq!(sensor.name(), "reasoning_summary_sensor_v1");
        assert_eq!(sensor.trust_class(), TrustClass::ModelInternal);

        // No provider declares ReasoningSummary Available today.
        let caps = caps_with(vec![]);
        assert!(!sensor.is_ready(&caps));
        let outcome = sensor.collect(&dummy_event(), &caps);
        assert!(!outcome.has_evidence());
        assert_eq!(outcome.state, SignalAvailability::Unsupported);

        // If a future provider *did* declare it available, the same sensor
        // (unmodified) would be ready.
        let future_caps = caps_with(vec![CapabilitySignal {
            class: SignalClass::ReasoningSummary,
            state: SignalAvailability::Available,
            detail: None,
        }]);
        assert!(sensor.is_ready(&future_caps));
    }
}
