//! Policy content vocabulary and scopes (FORNX-116, epic FORNX-69).
//!
//! Every [`PolicyContent`] field is `Option<T>`. `None` means **this layer
//! does not speak to this field** — it is not a value, and must never be
//! conflated with a concrete falsy value (e.g. `Some(false)`). This is the
//! single most important invariant in the model: see
//! `crate::policy::local::local_user_layer`'s doc comment for the exact
//! place a naive `unwrap_or(false)` migration would silently break it, and
//! `crate::policy::resolve` for how layers combine.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{SignalClass, Verdict};

pub const POLICY_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_POLICY_SCHEMA_VERSIONS: &[u32] = &[1];

/// What the agent is doing that policy has an opinion about. Carries the
/// `Unrecognized` forward-compat tail (see `capabilities.rs`'s
/// `SignalAvailability`/`SignalClass` precedent) because `fornax-cloud`'s
/// FORNX-117 authoring UI mirrors this in Python and the two repos deploy
/// independently.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    CodeEdit,
    ShellCommand,
    VersionControlWrite,
    NetworkFetch,
    PackageInstall,
    CredentialAccess,
    InfrastructureMutation,
    DataEgress,
    /// Forward-compatibility catch-all. Must stay last — `#[serde(untagged)]`
    /// makes it the fallback the tagged variants above are tried before.
    #[serde(untagged)]
    Unrecognized(String),
}

/// Closed on purpose — no `Unrecognized`. This is an ordered lattice used
/// for cache-expiry meet; an unknown tier cannot be ordered, so it cannot
/// exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    Low,
    Elevated,
    High,
    Critical,
}

/// Strictness order: `Allow < ObserveOnly < Warn < Block` (derive order ==
/// meet order — `Ord`'s `max` is the strictness meet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOutcome {
    /// Policy affirmatively permits this. There is nothing being suppressed.
    Allow,
    /// Policy's opinion is Warn-or-Block, but enforcement is suppressed. The
    /// would-be outcome is recorded. This is NOT "permit without recording"
    /// — ADR-0001 D3 means Fornax records regardless; the distinction from
    /// `Allow` is whether an opinion is being held back.
    ObserveOnly,
    Warn,
    Block,
}

/// The D4 coordination point: enforcement is keyed on the five-state
/// verdict, never on a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictOutcomes {
    pub verified: EnforcementOutcome,
    pub unverified: EnforcementOutcome,
    pub contradicted: EnforcementOutcome,
    pub review: EnforcementOutcome,
    pub unavailable: EnforcementOutcome,
}

impl VerdictOutcomes {
    pub fn uniform(o: EnforcementOutcome) -> Self {
        Self {
            verified: o,
            unverified: o,
            contradicted: o,
            review: o,
            unavailable: o,
        }
    }

    /// Exhaustive match, no wildcard arm — adding a `Verdict` variant fails
    /// to compile rather than silently mapping to a default (D4).
    pub fn for_verdict(&self, v: Verdict) -> EnforcementOutcome {
        match v {
            Verdict::Verified => self.verified,
            Verdict::Unverified => self.unverified,
            Verdict::Contradicted => self.contradicted,
            Verdict::Review => self.review,
            Verdict::Unavailable => self.unavailable,
        }
    }

    /// Per-verdict stricter-wins meet (FORNX-121: never a single global
    /// fail-open/fail-closed toggle — each verdict is merged independently).
    pub(crate) fn meet(a: Self, b: Self) -> Self {
        Self {
            verified: a.verified.max(b.verified),
            unverified: a.unverified.max(b.unverified),
            contradicted: a.contradicted.max(b.contradicted),
            review: a.review.max(b.review),
            unavailable: a.unavailable.max(b.unavailable),
        }
    }
}

/// Every field `Option<T>`. `None` means "this layer does not speak to this
/// field" — see module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyContent {
    pub collection: CollectionScope,
    pub egress: EgressScope,
    pub sensors: SensorScope,
    pub enforcement: EnforcementScope,
    pub cache: CacheScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CollectionScope {
    /// Maps 1:1 to today's `privacy::longitudinal_reliability_collection_allowed()`.
    pub longitudinal_aggregation_allowed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EgressScope {
    /// Maps 1:1 to today's `privacy::cloud_sync_allowed()`.
    pub cloud_sync_allowed: Option<bool>,
    pub redaction_profile: Option<RedactionProfile>,
    /// Meet is INTERSECTION (smaller set = stricter).
    pub allowed_content: Option<BTreeSet<EgressContentClass>>,
}

/// No `Off`/`None` variant exists. The schema cannot express "do not
/// redact"; `Standard` is exactly today's `redact::redact_json` behavior and
/// is the floor. Strictness order: `Standard < Strict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionProfile {
    Standard,
    Strict,
}

/// No raw-payload / raw-prompt / source-code variant exists, by construction
/// (ADR-0001 D7). Egress of raw content is not a policy setting that happens
/// to default off — it is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressContentClass {
    FindingVerdicts,
    ClaimText,
    EvidenceMetadata,
    RedactedEvidencePayload,
    CapabilityDeclarations,
    #[serde(untagged)]
    Unrecognized(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SensorScope {
    /// By `EvidenceSensor::name`. Meet is UNION (more disabled = stricter).
    /// Maps to today's `SensorDisableConfig`.
    pub disabled: Option<BTreeSet<String>>,
    /// Meet is UNION. A required signal the device reports as `Unsupported`
    /// produces a resolve-time Warning, never a silent pass.
    ///
    /// `Vec`, not `BTreeSet`: `crate::SignalClass` derives neither `Ord` nor
    /// `Hash` (see `reliability_context.rs`'s `capability_fingerprint` doc,
    /// which states this deliberately, "rather than adding those derives to
    /// a module this ticket does not otherwise touch"). Canonicalized
    /// (sorted by wire tag, deduplicated) by `PolicyDraft::publish` so
    /// semantically-equal sets always produce identical canonical bytes —
    /// see `revision::canonical_bytes`.
    pub required_signals: Option<Vec<SignalClass>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EnforcementScope {
    /// Sorted by `action_class`, no duplicates — both enforced at publish
    /// time. A `Vec`, not a `BTreeMap<ActionClass, _>`: an enum with an
    /// untagged newtype variant as a JSON map key is fragile, and a sorted
    /// Vec gives deterministic canonical bytes for free.
    pub rules: Option<Vec<EnforcementRule>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementRule {
    pub action_class: ActionClass,
    pub risk_class: RiskClass,
    pub outcomes: VerdictOutcomes,
}

/// Declarative values FORNX-119's cache state machine consumes. This ticket
/// defines the numbers; FORNX-119 owns activation/rollback/last-known-good.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CacheScope {
    pub max_age_seconds_by_risk: Option<RiskClassSeconds>,
    pub offline_grace_seconds: Option<u32>,
}

/// Four named fields, same trick as [`VerdictOutcomes`] — closed,
/// exhaustive, no enum-as-map-key problem. Smaller = stricter, per field
/// independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskClassSeconds {
    pub low: u32,
    pub elevated: u32,
    pub high: u32,
    pub critical: u32,
}

impl RiskClassSeconds {
    pub(crate) fn meet(a: Self, b: Self) -> Self {
        Self {
            low: a.low.min(b.low),
            elevated: a.elevated.min(b.elevated),
            high: a.high.min(b.high),
            critical: a.critical.min(b.critical),
        }
    }
}

/// All-concrete mirror of [`PolicyContent`] — the output of `resolve()`.
/// Every field here is what a consumer (e.g. `privacy::cloud_sync_allowed`'s
/// eventual replacement) actually reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedValues {
    pub longitudinal_aggregation_allowed: bool,
    pub cloud_sync_allowed: bool,
    pub redaction_profile: RedactionProfile,
    pub allowed_content: BTreeSet<EgressContentClass>,
    pub sensors_disabled: BTreeSet<String>,
    pub sensors_required_signals: Vec<SignalClass>,
    pub enforcement_rules: Vec<EnforcementRule>,
    pub cache_max_age_seconds_by_risk: RiskClassSeconds,
    pub cache_offline_grace_seconds: u32,
}

/// Canonical wire-tag string for a `SignalClass`, used only to sort/dedup —
/// `SignalClass` has no `Ord`/`Hash` of its own (see [`SensorScope`]'s
/// `required_signals` doc). Falls back to a debug-format string for a value
/// that (unexpectedly) fails to serialize, which never happens for this
/// enum in practice.
pub(crate) fn signal_class_sort_key(class: &SignalClass) -> String {
    serde_json::to_string(class).unwrap_or_else(|_| format!("{class:?}"))
}

/// Sorts and deduplicates a `Vec<SignalClass>` by its wire-tag string, so
/// semantically-equal sets always canonicalize to the same bytes regardless
/// of publish-time construction order.
pub(crate) fn normalize_signal_classes(classes: &mut Vec<SignalClass>) {
    classes.sort_by_key(signal_class_sort_key);
    classes.dedup_by(|a, b| a == b);
}

/// Union of two `SignalClass` collections (larger = stricter), normalized.
pub(crate) fn union_signal_classes(
    mut a: Vec<SignalClass>,
    b: Vec<SignalClass>,
) -> Vec<SignalClass> {
    a.extend(b);
    normalize_signal_classes(&mut a);
    a
}

impl PolicyContent {
    /// The concrete floor every field falls back to when nothing sets it.
    ///
    /// Two default philosophies, deliberately. Collection/egress default
    /// **deny** — mirroring today's env gates and `SideEffectAllowList`, and
    /// AC5 forbids weakening them. Enforcement defaults **observe-only** —
    /// blocking is a *new* capability with no incumbent behavior to
    /// preserve, and silently acquiring the power to block agent actions on
    /// upgrade is the failure mode to avoid. Do not "harmonize" these into
    /// one rule.
    pub fn baseline() -> ResolvedValues {
        ResolvedValues {
            longitudinal_aggregation_allowed: false,
            cloud_sync_allowed: false,
            redaction_profile: RedactionProfile::Standard,
            allowed_content: BTreeSet::new(),
            sensors_disabled: BTreeSet::new(),
            sensors_required_signals: Vec::new(),
            enforcement_rules: Vec::new(),
            cache_max_age_seconds_by_risk: RiskClassSeconds {
                low: 86_400,
                elevated: 21_600,
                high: 3_600,
                critical: 900,
            },
            cache_offline_grace_seconds: 604_800,
        }
    }
}

impl ResolvedValues {
    /// The enforcement outcome for one `(action_class, verdict)` pair. Each
    /// `action_class` has at most one rule (uniqueness enforced by
    /// `PolicyDraft::publish`); an `action_class` with no matching rule
    /// reads `ObserveOnly` — see [`PolicyContent::baseline`]: nothing blocks
    /// on upgrade merely because no rule was ever published for it.
    pub fn enforcement_outcome_for(
        &self,
        action_class: &ActionClass,
        verdict: Verdict,
    ) -> EnforcementOutcome {
        self.enforcement_rules
            .iter()
            .find(|r| &r.action_class == action_class)
            .map(|r| r.outcomes.for_verdict(verdict))
            .unwrap_or(EnforcementOutcome::ObserveOnly)
    }
}
