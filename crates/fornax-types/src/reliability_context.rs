//! Reliability context keys and privacy-safe aggregation (FORNX-103, parent
//! epic FORNX-20 / discovery thesis HVDL-15).
//!
//! # Why this module exists
//!
//! FORNX-104/105/106 will build longitudinal reliability statistics, a UI,
//! and retention enforcement on top of *some* notion of "comparable
//! historical behavior." Left undefined, that notion collapses to "group by
//! provider name" — exactly the outcome the FORNX-66/67 epic guardrail
//! forbids: **"Historical reliability is never a global 'Claude = 93%
//! trustworthy' score."** A Claude Code session running `pytest` in a public
//! OSS repo with no CI signal is not comparable to a Claude Code session
//! running a deploy script in a private monorepo with full CI/verifier
//! coverage — collapsing both into "Claude" would launder that difference
//! into a single misleading number.
//!
//! This module defines the structured context a reliability observation must
//! be keyed by ([`ReliabilityContextKey`]), a pseudonymous, aggregation-safe
//! cohort handle over that context ([`CohortIdentity`]), a gate that refuses
//! to produce a confident-looking read from a sparse cohort
//! ([`SampleSupport`]), a real function that turns a potentially-identifying
//! raw context into a privacy-safe key ([`aggregate_context`]), and the
//! dataset-lineage tag a future retention/deletion mechanism (FORNX-106) will
//! act on ([`DatasetLineageTag`]).
//!
//! **This ticket does not compute reliability statistics (FORNX-104), does
//! not build a UI (FORNX-105), and does not implement retention/deletion
//! enforcement (FORNX-106).** It defines the schema and a working
//! aggregation function those tickets build on.
//!
//! # AC 1: keyed by explicit context, never provider name alone
//!
//! [`ReliabilityContextKey`] has no `Default` impl, no `#[serde(default)]` on
//! any field (deliberately unlike `RuntimeCapabilities`/`EvidenceSource`'s
//! backward-compatibility defaults — there is no legacy data for a brand-new
//! type, so tolerance here would buy nothing except reopening exactly the
//! "provider name alone" construction path this AC forbids), and no
//! convenience constructor that takes fewer than all dimensions. The only way
//! to produce one is [`aggregate_context`], which requires every dimension as
//! an argument. See this module's tests for the structural proof (a JSON
//! blob naming only `provider` fails to deserialize).
//!
//! # AC 2: context dimensions, their cardinality, and privacy considerations
//!
//! | Dimension | Type | Cardinality | Privacy risk | Mitigation |
//! |---|---|---|---|---|
//! | Coding-agent provider | [`crate::Provider`] | Low (4 variants today) | None — no identifying content. | Closed enum, already used elsewhere. |
//! | Model family | [`ModelFamily`] | Low, grows slowly | None. | Closed enum + `Unrecognized` escape hatch. |
//! | Model version | `String` | Medium — providers mint new version strings often | Low, but a version string is a plausible smuggling channel for pasted-in free text. | Passed through [`redact_text`] and length-capped ([`MAX_VERSION_STRING_LEN`]) by [`aggregate_context`]. |
//! | Adapter version | `String` | Medium — one per adapter release | Same as model version. | Same mitigation. |
//! | Task/claim class | [`TaskClass`] | Low, closed set | None. | Closed enum + escape hatch. |
//! | Toolset | `Vec<`[`ToolClass`]`>` | Medium — combinatorial in principle, but drawn from a small closed vocabulary | Low; sorted+deduped so two callers reporting the same tools in different orders produce the same key. | Closed enum, canonical sort order. |
//! | Repository/environment class | [`RepositoryClass`] | Low (coarse buckets only) | **High if this were a literal repo path/name** — a repo identifier can itself identify a customer or a private codebase. | The raw identifier is never a field on the output key at all — [`RawRepositoryContext`] (the aggregation *input*) carries it and does not even derive `Serialize`/`Deserialize` (cannot be persisted or transmitted through this type), and [`aggregate_context`] drops it on the floor, keeping only the caller-classified coarse [`RepositoryClass`] tag. This is a structural guarantee, not a redaction pass: `redact_text` alone would **not** catch an ordinary-looking repo path (it is not high-entropy and is not an env-assignment shape), which is exactly why generalization, not text-scrubbing, is the primary guard here. |
//! | Policy/verifier/fusion version | `String` (×3) | Medium — one per release | Same as model version. | Same mitigation (`redact_text` + length cap). |
//! | Capability state | fingerprint derived from [`crate::RuntimeCapabilities`] | Medium — grows with `SignalClass` variants | Low; `RuntimeCapabilities::notes` (a free-text `HashMap`) is deliberately **excluded** from the fingerprint — it can carry session ids or other operator-written text unrelated to what capabilities were actually available. | [`capability_fingerprint`] extracts only `(class, state)` pairs plus `schema_version`, sorted and deduped; `notes` is never read. |
//!
//! # AC 3: sparse contexts represent uncertainty, never a numeric-looking guess
//!
//! [`SampleSupport::InsufficientSupport`] carries only the observed count and
//! the threshold it fell short of — no `f64`, no interval, nothing a caller
//! could mistake for an estimate. See [`evaluate_sample_support`].
//!
//! # AC 4: dataset deletion/retention can honor tenant/user policy
//!
//! At this ticket's scope, "honor policy" means the types carry enough
//! information for a future enforcement mechanism (FORNX-106) to find and
//! act on a tenant's records — not that this ticket deletes anything.
//! [`DatasetLineageTag`] carries an explicit [`TenantRef`], a [`RetentionClass`],
//! and the source record ids a given derived record traces back to. It is
//! deliberately a separate type from [`ReliabilityContextKey`]/[`CohortIdentity`]:
//! a cohort key is meant to be aggregation-safe and must never carry a
//! retrievable tenant identifier, while a lineage tag's whole job is to be
//! retrievable by tenant. Mixing the two would either make cohorts
//! re-identifiable or make deletion propagation unable to find what to
//! delete — see `crate::privacy::cloud_sync_allowed` for this codebase's
//! existing "local policy must explicitly approve before X happens"
//! precedent, which this module follows in spirit (structural gate, not an
//! ad hoc check).
//!
//! # AC 5: historical records stay attributable to the versions used at the time
//!
//! `policy_version`/`verifier_version`/`fusion_version` are owned fields
//! captured into [`ReliabilityContextKey`] at aggregation time — snapshots,
//! never resolved later from "whatever the current version is." A
//! [`ReliabilityContextKey`] serialized last year continues to name the
//! versions that were live when it was built, exactly as
//! `EvidenceSource::collector_version` does for evidence provenance.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::redact::redact_text;
use crate::{Provider, RuntimeCapabilities};

/// Version of the [`ReliabilityContextKey`]/[`CohortIdentity`]/[`DatasetLineageTag`]
/// shapes. Bumped whenever a structural change would change the canonical
/// serialization `cohort_id_for` hashes over, or would change which fields a
/// consumer can rely on being present — mirrors
/// `crate::CAPABILITY_SCHEMA_VERSION` / `crate::EXTENSION_SCHEMA_VERSION`.
pub const RELIABILITY_CONTEXT_SCHEMA_VERSION: u32 = 1;

/// Version strings (model/adapter/policy/verifier/fusion) are free text
/// originating outside this binary's control. Capped so a pathological input
/// cannot make a context key unboundedly large.
pub const MAX_VERSION_STRING_LEN: usize = 128;

/// A cohort is treated as having enough support for a confident reliability
/// read only at or above this many observations. Deliberately conservative
/// and arbitrary — chosen as "large enough that a handful of unlucky runs
/// can't swing a verdict, small enough that a real cohort accumulates it in
/// days, not months." FORNX-104 may revisit this once real data exists; until
/// then it is a named constant, not a number buried in a comparison.
pub const MINIMUM_COHORT_SAMPLE_SUPPORT: u32 = 30;

/// Cap and redact a free-text version-ish string before it enters a
/// [`ReliabilityContextKey`]. `redact_text` catches high-entropy/secret-shaped
/// substrings (see `crate::redact`'s own documented gaps — it does **not**
/// catch an ordinary path or name); the length cap bounds pathological input.
fn sanitize_version_string(raw: &str) -> String {
    let redacted = redact_text(raw);
    redacted.chars().take(MAX_VERSION_STRING_LEN).collect()
}

/// Normalize a value of one of this module's `Unrecognized(String)`-tailed
/// enums (or a collection of them) to its canonical Rust representation by
/// round-tripping through its wire form.
///
/// Every enum in this module follows `capabilities.rs`'s
/// `SignalAvailability`/`TrustClass` pattern: `Unrecognized("public_oss")` and
/// `PublicOss` are *not* equal under `PartialEq` (different Rust values) but
/// serialize to the *same* JSON string (`"public_oss"`) — the exact asymmetry
/// `SignalAvailability::from_tag`'s doc comment warns about. Left
/// unnormalized, that asymmetry would let two `ReliabilityContextKey` values
/// that are `!=` under `PartialEq` collapse to the same `cohort_id` (which
/// hashes the *wire* bytes), silently misgrouping cohorts. `aggregate_context`
/// is the single chokepoint that produces a `ReliabilityContextKey`, so this
/// is called there for every dimension a caller could plausibly construct as
/// `Unrecognized` — reparsing a value already in canonical form is a no-op.
fn normalize_enum<T>(value: T) -> T
where
    T: Serialize + for<'de> Deserialize<'de>,
{
    let wire = serde_json::to_value(&value).expect("module enums always serialize");
    serde_json::from_value(wire).expect("re-parsing a value's own wire form always succeeds")
}

/// Which underlying model family produced a session's output. Deliberately
/// coarser than a literal model version string (kept separately, and
/// redacted/capped — see [`ReliabilityContextKey::model_version`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFamily {
    Claude,
    Gpt,
    Gemini,
    Llama,
    Other,
    /// Forward-compatibility catch-all, matching the `Unrecognized(String)`
    /// pattern used throughout `capabilities.rs`/`sensor.rs`. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// Coarse category of what a session/claim was actually trying to
/// accomplish. Task class matters because "test execution" and "deployment"
/// sessions have structurally different reliability profiles even from the
/// same provider/model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskClass {
    TestExecution,
    CodeReview,
    BuildOrCompile,
    Documentation,
    Deployment,
    VersionControlOperation,
    GeneralAgentic,
    /// Forward-compatibility catch-all. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// One category of tool a session had access to. A [`ReliabilityContextKey`]
/// carries a sorted, deduped set of these (see [`aggregate_context`]) rather
/// than literal tool names, which would be effectively unbounded cardinality
/// (every adapter/MCP server can name its own tools).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolClass {
    Shell,
    FileEdit,
    VersionControl,
    HttpNetwork,
    Search,
    TestRunner,
    Other,
    /// Forward-compatibility catch-all. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// Coarse repository/environment classification. **Never** a literal repo
/// name, path, or URL — see this module's AC-2 table for why a repo
/// identifier is treated as high privacy risk and structurally excluded from
/// ever reaching a [`ReliabilityContextKey`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryClass {
    PublicOss,
    PrivateMonorepo,
    PrivateSingleRepo,
    /// No classification was supplied. Distinct from `Unrecognized` the same
    /// way `SignalAvailability::Unknown` is distinct from
    /// `SignalAvailability::Unrecognized` in `capabilities.rs`: this is a
    /// domain fact ("nobody classified this"), not a parse-time fact ("this
    /// binary doesn't know this tag").
    Unknown,
    /// Forward-compatibility catch-all. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// Raw, potentially-identifying repository context — the *input* to
/// [`aggregate_context`], never itself part of a [`ReliabilityContextKey`].
/// `identifying_hint` exists only so a caller can pass through whatever raw
/// value it had (a path, a slug, a URL) for local debugging/logging on the
/// caller's own side; [`aggregate_context`] never reads it into the output
/// key — it is dropped, not redacted, because a repo path does not reliably
/// trip `redact_text`'s secret-shape detectors (see this module's AC-2
/// table). Neither this type nor [`RawReliabilityContext`] derives
/// `Serialize`/`Deserialize` — the raw identifier cannot be persisted or sent
/// over the wire through this type at all, a stronger guarantee than
/// "dropped during aggregation."
#[derive(Debug, Clone)]
pub struct RawRepositoryContext {
    pub identifying_hint: Option<String>,
    /// The caller-supplied coarse classification. Aggregation trusts this
    /// value verbatim — classifying a repo as public vs. private is a policy
    /// decision made by whatever code owns the repo/environment metadata,
    /// not something this module infers from a path.
    pub class: RepositoryClass,
}

/// The raw, not-yet-aggregated context for one reliability observation.
/// Every field a real caller would already have on hand; [`aggregate_context`]
/// is the only way to turn this into a [`ReliabilityContextKey`], so
/// constructing a key always requires supplying every dimension (AC 1).
#[derive(Debug, Clone)]
pub struct RawReliabilityContext {
    pub provider: Provider,
    pub model_family: ModelFamily,
    pub model_version: String,
    pub adapter_version: String,
    pub task_class: TaskClass,
    pub toolset: Vec<ToolClass>,
    pub repository: RawRepositoryContext,
    pub policy_version: String,
    pub verifier_version: String,
    pub fusion_version: String,
    pub capabilities: RuntimeCapabilities,
}

/// A structured, versioned composite key identifying "comparable historical
/// behavior" (FORNX-103 AC 1). Reliability observations must be grouped by
/// this key, never by [`Provider`] alone — see the module docs' worked
/// example of why that collapse is misleading.
///
/// No `Default` impl and no `#[serde(default)]` field: every dimension is
/// mandatory, and the only constructor is [`aggregate_context`]. This is
/// deliberate — see this module's docs, AC 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReliabilityContextKey {
    pub schema_version: u32,
    pub provider: Provider,
    pub model_family: ModelFamily,
    pub model_version: String,
    pub adapter_version: String,
    pub task_class: TaskClass,
    pub toolset: Vec<ToolClass>,
    pub repository_class: RepositoryClass,
    pub policy_version: String,
    pub verifier_version: String,
    pub fusion_version: String,
    /// `RuntimeCapabilities::schema_version` at aggregation time — carried
    /// separately from `capability_fingerprint` so a future consumer can
    /// tell "no signals were declared" apart from "an old capability schema
    /// produced this fingerprint."
    pub capability_schema_version: u32,
    /// Canonical, sorted `(SignalClass, SignalAvailability)` tag-string pairs
    /// derived from a [`RuntimeCapabilities`] snapshot — see
    /// [`capability_fingerprint`]. Deliberately excludes
    /// `RuntimeCapabilities::notes` (see this module's AC-2 table).
    pub capability_fingerprint: Vec<(String, String)>,
}

/// Extract a canonical, order-independent fingerprint of a capability
/// snapshot's `(class, state)` declarations. `SignalClass`/`SignalAvailability`
/// derive neither `Ord` nor `Hash` (see `capabilities.rs`), so this sorts by
/// their serde wire representation (a plain JSON string for every variant,
/// tagged or `Unrecognized`) rather than adding those derives to a module
/// this ticket does not otherwise touch.
pub fn capability_fingerprint(caps: &RuntimeCapabilities) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = caps
        .signals
        .iter()
        .map(|s| {
            let class = serde_json::to_value(&s.class)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            let state = serde_json::to_value(&s.state)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            (class, state)
        })
        .collect();
    pairs.sort();
    pairs.dedup();
    pairs
}

/// Turn a [`RawReliabilityContext`] into a privacy-safe [`ReliabilityContextKey`]
/// (FORNX-103's "privacy-safe aggregation rules", concretely implemented —
/// not just documented). Two independent guards run here:
///
/// - **Generalization**: `raw.repository.identifying_hint` (a literal path,
///   slug, or URL) is never read into the output at all — only
///   `raw.repository.class` (already a coarse enum) survives.
/// - **Redaction + length cap**: every free-text version string is passed
///   through [`redact_text`] and truncated to [`MAX_VERSION_STRING_LEN`],
///   catching a secret accidentally pasted into a version field.
pub fn aggregate_context(raw: RawReliabilityContext) -> ReliabilityContextKey {
    // Normalize each tool class to its canonical wire-equivalent form before
    // sorting/deduping — otherwise a caller-supplied `Unrecognized("shell")`
    // would sort/dedupe against `ToolClass::Shell` by Rust `PartialEq`
    // (unequal) rather than by wire identity (equal), leaving both in the set.
    let mut toolset: Vec<ToolClass> = raw.toolset.into_iter().map(normalize_enum).collect();
    toolset.sort();
    toolset.dedup();

    ReliabilityContextKey {
        schema_version: RELIABILITY_CONTEXT_SCHEMA_VERSION,
        provider: raw.provider,
        model_family: normalize_enum(raw.model_family),
        model_version: sanitize_version_string(&raw.model_version),
        adapter_version: sanitize_version_string(&raw.adapter_version),
        task_class: normalize_enum(raw.task_class),
        toolset,
        repository_class: normalize_enum(raw.repository.class),
        policy_version: sanitize_version_string(&raw.policy_version),
        verifier_version: sanitize_version_string(&raw.verifier_version),
        fusion_version: sanitize_version_string(&raw.fusion_version),
        capability_schema_version: raw.capabilities.schema_version,
        capability_fingerprint: capability_fingerprint(&raw.capabilities),
    }
}

/// Fixed namespace UUID for deriving cohort ids via `Uuid::new_v5`. Any fixed
/// value works — what matters is that it never changes, so the same
/// `ReliabilityContextKey` always hashes to the same `cohort_id`. Generated
/// once (a random v4 UUID) and frozen here; it carries no meaning beyond
/// "the namespace this module uses."
const COHORT_ID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x5c, 0x6a, 0x1e, 0x2d, 0x9b, 0x4f, 0x4a, 0x8e, 0xb1, 0x02, 0x7f, 0x3a, 0x91, 0xd4, 0x6c, 0x77,
]);

/// Derive a stable, pseudonymous cohort id from a [`ReliabilityContextKey`].
///
/// This is a **compaction device, not an anonymization device**: `Uuid::new_v5`
/// is unkeyed SHA-1 over a small, already-generalized input space (closed
/// enums plus capped version strings), so it is brute-forceable by
/// enumeration if an attacker already knows the space of possible contexts.
/// It provides a stable, opaque handle to group observations under without
/// repeating the full key everywhere — the actual privacy guarantee is
/// upstream, in [`aggregate_context`] never letting identifying content
/// (a repo path, a customer name) into the key in the first place.
pub fn cohort_id_for(key: &ReliabilityContextKey) -> Uuid {
    let canonical =
        serde_json::to_vec(key).expect("ReliabilityContextKey always serializes to JSON");
    Uuid::new_v5(&COHORT_ID_NAMESPACE, &canonical)
}

/// A [`ReliabilityContextKey`] plus its derived pseudonymous cohort handle.
/// Deliberately carries no tenant/user identifier — see [`DatasetLineageTag`]
/// for where that lives instead, and this module's AC-4 docs for why the two
/// are kept apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortIdentity {
    pub context_key: ReliabilityContextKey,
    pub cohort_id: Uuid,
}

impl CohortIdentity {
    /// The only constructor — `cohort_id` is always derived from
    /// `context_key`, never supplied independently, so the two can never
    /// silently disagree.
    pub fn new(context_key: ReliabilityContextKey) -> Self {
        let cohort_id = cohort_id_for(&context_key);
        Self {
            context_key,
            cohort_id,
        }
    }
}

/// Whether a cohort has accumulated enough observations to support a
/// confident reliability read (FORNX-103 AC 3). **Never** carries a numeric
/// estimate in the insufficient case — only the observed count and the
/// threshold it fell short of. FORNX-104 is the only place an actual
/// reliability statistic gets computed, and only once this gate reports
/// `Confident`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SampleSupport {
    Confident {
        sample_count: u32,
    },
    InsufficientSupport {
        sample_count: u32,
        minimum_required: u32,
    },
}

/// Gate a raw sample count into a [`SampleSupport`] verdict against
/// [`MINIMUM_COHORT_SAMPLE_SUPPORT`]. The gate never *produces* a numeric
/// estimate below the threshold — `InsufficientSupport`'s `sample_count`
/// field stays visible (deliberately, e.g. to display "3 of 30 observed")
/// but is never packaged as, or substituted for, a reliability statistic.
pub fn evaluate_sample_support(sample_count: u32) -> SampleSupport {
    if sample_count >= MINIMUM_COHORT_SAMPLE_SUPPORT {
        SampleSupport::Confident { sample_count }
    } else {
        SampleSupport::InsufficientSupport {
            sample_count,
            minimum_required: MINIMUM_COHORT_SAMPLE_SUPPORT,
        }
    }
}

/// Which retention bucket a stored reliability-related record belongs to.
/// Matches FORNX-106's own scope bullet ("separate retention classes") — this
/// type is the schema FORNX-106's enforcement mechanism attaches to, not the
/// enforcement itself.
///
/// Carries the `Unrecognized(String)` forward-compat tail like
/// `capabilities.rs`'s taxonomy, **not** closed like `EvidenceKind` — this
/// type is local-only (no `fornax-cloud` mirror to keep in lockstep with), so
/// the reason `EvidenceKind` stays closed does not apply here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    /// Raw, unaggregated local observation data.
    RawLocal,
    /// A sanitized fixture derived from raw data for replay/testing, with
    /// identifying content already stripped.
    SanitizedReplayFixture,
    /// A computed aggregate feature (e.g. a per-cohort statistic) — no longer
    /// traceable to a single session without following `source_record_ids`.
    AggregatedFeature,
    /// A derived finding/verdict produced from aggregated features.
    DerivedFinding,
    /// Forward-compatibility catch-all. Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

/// An opaque reference to whichever tenant/user a record belongs to, for
/// deletion-propagation purposes (FORNX-103 AC 4). Deliberately just a
/// `String` wrapper — this module does not define identity/auth; it only
/// guarantees a retrievable field exists for a future deletion mechanism to
/// filter on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRef(pub String);

/// The dataset-lineage tag a stored reliability-related record carries, so a
/// future deletion/retention enforcement mechanism (FORNX-106) has something
/// concrete to act on. This ticket defines the shape only — no cron job, no
/// actual deletion, no consent UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatasetLineageTag {
    pub schema_version: u32,
    pub retention_class: RetentionClass,
    pub tenant_ref: TenantRef,
    /// Ids of the source record(s) this record was derived from, empty for a
    /// directly-observed `RawLocal` record. Mirrors
    /// `EvidenceSource::derived_from`'s shape/intent (`sensor.rs`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_record_ids: Vec<Uuid>,
    /// RFC3339 timestamp this record was written.
    pub recorded_at: String,
    /// RFC3339 timestamp a deletion request was recorded against this
    /// record's tenant, if any. `None` is the ordinary case; a future
    /// enforcement mechanism sets this and later actually deletes the row —
    /// this field only records that the request happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletion_requested_at: Option<String>,
}

impl DatasetLineageTag {
    pub fn new(retention_class: RetentionClass, tenant_ref: TenantRef) -> Self {
        Self {
            schema_version: RELIABILITY_CONTEXT_SCHEMA_VERSION,
            retention_class,
            tenant_ref,
            source_record_ids: Vec::new(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
            deletion_requested_at: None,
        }
    }

    pub fn derived_from(mut self, source_record_ids: Vec<Uuid>) -> Self {
        self.source_record_ids = source_record_ids;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{CapabilitySignal, RuntimeCapabilities};
    use crate::{SignalAvailability, SignalClass};
    use std::collections::HashMap;

    fn caps_with(signals: Vec<CapabilitySignal>) -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: crate::CAPABILITY_SCHEMA_VERSION,
            provider: Provider::ClaudeCode,
            signals,
            notes: HashMap::new(),
        }
    }

    fn sample_raw(repository: RawRepositoryContext) -> RawReliabilityContext {
        RawReliabilityContext {
            provider: Provider::ClaudeCode,
            model_family: ModelFamily::Claude,
            model_version: "claude-sonnet-5".to_string(),
            adapter_version: "0.0.4".to_string(),
            task_class: TaskClass::TestExecution,
            toolset: vec![ToolClass::Shell, ToolClass::FileEdit],
            repository,
            policy_version: "policy-v3".to_string(),
            verifier_version: "verifier-v2".to_string(),
            fusion_version: "fusion-v1".to_string(),
            capabilities: caps_with(vec![CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }]),
        }
    }

    // --- AC 1: no provider-name-alone construction path -------------------

    #[test]
    fn context_key_cannot_be_constructed_from_provider_alone_via_deserialization() {
        let json = r#"{"provider": "claude_code"}"#;
        let err = serde_json::from_str::<ReliabilityContextKey>(json);
        assert!(
            err.is_err(),
            "a ReliabilityContextKey naming only `provider` must not deserialize \
             — every dimension is mandatory (AC 1)"
        );
    }

    #[test]
    fn context_key_requires_every_dimension_to_deserialize() {
        let key = aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::PublicOss,
        }));
        let json = serde_json::to_string(&key).unwrap();
        // Sanity: the full, well-formed key round-trips.
        let back: ReliabilityContextKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);

        // Removing any one required field breaks deserialization.
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("task_class");
        assert!(serde_json::from_value::<ReliabilityContextKey>(value).is_err());
    }

    // --- Privacy-safe aggregation ------------------------------------------

    #[test]
    fn aggregation_drops_a_raw_repository_identifier_entirely() {
        let key = aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: Some("/Users/alice/super-secret-customer-repo".to_string()),
            class: RepositoryClass::PrivateSingleRepo,
        }));
        let serialized = serde_json::to_string(&key).unwrap();
        assert!(!serialized.contains("alice"));
        assert!(!serialized.contains("super-secret-customer-repo"));
        assert_eq!(key.repository_class, RepositoryClass::PrivateSingleRepo);
    }

    #[test]
    fn aggregation_redacts_a_secret_shaped_string_pasted_into_a_version_field() {
        let mut raw = sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::Unknown,
        });
        raw.policy_version =
            "policy-v3 GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz".to_string();
        let key = aggregate_context(raw);
        assert!(!key.policy_version.contains("ghp_"));
        assert!(key.policy_version.contains("[REDACTED"));
    }

    #[test]
    fn aggregation_caps_an_overlong_version_string() {
        let mut raw = sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::Unknown,
        });
        raw.model_version = "v".repeat(10_000);
        let key = aggregate_context(raw);
        assert!(key.model_version.chars().count() <= MAX_VERSION_STRING_LEN);
    }

    #[test]
    fn aggregation_sorts_and_dedupes_toolset() {
        let mut raw = sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::Unknown,
        });
        raw.toolset = vec![
            ToolClass::FileEdit,
            ToolClass::Shell,
            ToolClass::Shell,
            ToolClass::FileEdit,
        ];
        let key = aggregate_context(raw);
        assert_eq!(key.toolset, vec![ToolClass::Shell, ToolClass::FileEdit]);
    }

    #[test]
    fn capability_fingerprint_excludes_notes() {
        let mut caps = caps_with(vec![CapabilitySignal {
            class: SignalClass::ToolTrace,
            state: SignalAvailability::Available,
            detail: None,
        }]);
        caps.notes.insert(
            "session_id".to_string(),
            "sensitive-session-abc".to_string(),
        );
        let fp = capability_fingerprint(&caps);
        for (class, state) in &fp {
            assert!(!class.contains("sensitive-session-abc"));
            assert!(!state.contains("sensitive-session-abc"));
        }
    }

    // --- AC 3: sparse contexts represent uncertainty, never a number ------

    #[test]
    fn below_threshold_sample_is_insufficient_support_not_a_numeric_estimate() {
        let result = evaluate_sample_support(MINIMUM_COHORT_SAMPLE_SUPPORT - 1);
        match result {
            SampleSupport::InsufficientSupport {
                sample_count,
                minimum_required,
            } => {
                assert_eq!(sample_count, MINIMUM_COHORT_SAMPLE_SUPPORT - 1);
                assert_eq!(minimum_required, MINIMUM_COHORT_SAMPLE_SUPPORT);
            }
            SampleSupport::Confident { .. } => panic!("must not be confident below threshold"),
        }
        let json = serde_json::to_value(result).unwrap();
        let variant = json.get("insufficient_support").unwrap();
        assert!(variant.get("sample_count").is_some());
        // No numeric estimate field should exist alongside the counts.
        assert!(variant.get("estimate").is_none());
        assert!(variant.get("confidence_interval").is_none());
    }

    #[test]
    fn at_or_above_threshold_sample_is_confident() {
        let result = evaluate_sample_support(MINIMUM_COHORT_SAMPLE_SUPPORT);
        assert!(matches!(result, SampleSupport::Confident { .. }));
    }

    // --- Cohort identity: deterministic, and carries no tenant field ------

    #[test]
    fn same_context_key_produces_the_same_cohort_id() {
        let raw = || {
            sample_raw(RawRepositoryContext {
                identifying_hint: None,
                class: RepositoryClass::PublicOss,
            })
        };
        let a = CohortIdentity::new(aggregate_context(raw()));
        let b = CohortIdentity::new(aggregate_context(raw()));
        assert_eq!(a.cohort_id, b.cohort_id);
    }

    #[test]
    fn a_different_context_key_produces_a_different_cohort_id() {
        let a = CohortIdentity::new(aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::PublicOss,
        })));
        let b = CohortIdentity::new(aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::PrivateMonorepo,
        })));
        assert_ne!(a.cohort_id, b.cohort_id);
    }

    /// Pins `cohort_id_for`'s output for a fully-specified key. `cohort_id`
    /// hashes the key's canonical JSON serialization, which depends on
    /// `ReliabilityContextKey`'s *field declaration order* — a future no-op
    /// field reorder would silently repartition every historical cohort with
    /// no other test catching it (AC 5: historical attribution must not
    /// silently drift). If this test ever needs updating, that is itself the
    /// signal to double check nothing downstream assumed cohort ids were
    /// stable across the change.
    #[test]
    fn cohort_id_is_pinned_for_a_known_context_key() {
        let key = aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::PublicOss,
        }));
        assert_eq!(
            cohort_id_for(&key).to_string(),
            "25032472-861c-5e2f-9ad8-9704b1269722"
        );
    }

    /// `Unrecognized("public_oss")` and `RepositoryClass::PublicOss` are
    /// unequal Rust values (matching `SignalAvailability`'s documented
    /// asymmetry) but must serialize identically — and `aggregate_context`
    /// must normalize the former to the latter, so two keys that mean the
    /// same thing on the wire always compare equal and hash to the same
    /// cohort id.
    #[test]
    fn aggregation_normalizes_an_unrecognized_tag_matching_a_known_variant() {
        let canonical = RepositoryClass::PublicOss;
        let unrecognized = RepositoryClass::Unrecognized("public_oss".to_string());
        assert_ne!(
            canonical, unrecognized,
            "sanity: these are distinct Rust values"
        );
        assert_eq!(
            serde_json::to_value(&canonical).unwrap(),
            serde_json::to_value(&unrecognized).unwrap(),
            "sanity: but identical on the wire"
        );

        let key_a = aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: canonical,
        }));
        let key_b = aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: unrecognized,
        }));
        assert_eq!(
            key_a, key_b,
            "aggregate_context must normalize Unrecognized(\"public_oss\") to PublicOss"
        );
        assert_eq!(cohort_id_for(&key_a), cohort_id_for(&key_b));
    }

    #[test]
    fn cohort_identity_has_no_tenant_or_user_field() {
        let identity = CohortIdentity::new(aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::PublicOss,
        })));
        let json = serde_json::to_value(&identity).unwrap();
        assert!(json.get("tenant_ref").is_none());
        assert!(json.get("tenant_id").is_none());
        assert!(json.get("user_id").is_none());
    }

    // --- Round-trip serialization with schema_version ----------------------

    #[test]
    fn context_key_round_trips_and_carries_schema_version() {
        let key = aggregate_context(sample_raw(RawRepositoryContext {
            identifying_hint: None,
            class: RepositoryClass::PublicOss,
        }));
        assert_eq!(key.schema_version, RELIABILITY_CONTEXT_SCHEMA_VERSION);
        let json = serde_json::to_string(&key).unwrap();
        let back: ReliabilityContextKey = serde_json::from_str(&json).unwrap();
        assert_eq!(key, back);
    }

    #[test]
    fn dataset_lineage_tag_round_trips_and_carries_schema_version() {
        let tag = DatasetLineageTag::new(
            RetentionClass::AggregatedFeature,
            TenantRef("tenant-123".to_string()),
        )
        .derived_from(vec![Uuid::new_v4(), Uuid::new_v4()]);
        assert_eq!(tag.schema_version, RELIABILITY_CONTEXT_SCHEMA_VERSION);
        let json = serde_json::to_string(&tag).unwrap();
        let back: DatasetLineageTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag, back);
    }

    #[test]
    fn dataset_lineage_tag_carries_tenant_ref_for_deletion_propagation() {
        let tag = DatasetLineageTag::new(
            RetentionClass::RawLocal,
            TenantRef("tenant-abc".to_string()),
        );
        assert_eq!(tag.tenant_ref, TenantRef("tenant-abc".to_string()));
        assert!(tag.deletion_requested_at.is_none());
    }

    // --- Unrecognized forward-compat tail round-trips (matches capabilities.rs) --

    #[test]
    fn unrecognized_repository_class_round_trips() {
        let json = serde_json::json!("air_gapped_lab_environment");
        let class: RepositoryClass = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            class,
            RepositoryClass::Unrecognized("air_gapped_lab_environment".to_string())
        );
        let back = serde_json::to_value(&class).unwrap();
        assert_eq!(back, json);
    }

    #[test]
    fn unrecognized_retention_class_round_trips() {
        let json = serde_json::json!("quarantined_pending_review");
        let class: RetentionClass = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(
            class,
            RetentionClass::Unrecognized("quarantined_pending_review".to_string())
        );
        let back = serde_json::to_value(&class).unwrap();
        assert_eq!(back, json);
    }
}
