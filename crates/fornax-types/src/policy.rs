//! Policy-as-data domain model (FORNX-116, epic FORNX-69).
//!
//! Fornax's privacy/egress/enforcement rules stop being hardcoded env-var
//! gates (`crate::privacy`) and start being data: an immutable, digested,
//! signable [`revision::PublishedPolicyRevision`] targeted at an
//! organization/team/project/device/local-user level via
//! [`target::PolicyBinding`], resolved against a local
//! [`target::DeviceContext`] into one concrete [`resolve::ResolvedPolicy`].
//!
//! See `docs/adr/0006-policy-as-data.md` for the full precedence table,
//! strictness table, baseline table, and the canonical-bytes-for-signing
//! boundary. In short:
//!
//! - **Content** ([`content::PolicyContent`]): every field is
//!   `Option<T>` — `None` means "this layer has no opinion," never a
//!   concrete falsy value. [`content::PolicyContent::baseline`] is the
//!   all-concrete floor every field falls back to.
//! - **Revisions** ([`revision::PublishedPolicyRevision`]) are immutable
//!   once published; [`revision::canonical_bytes`] defines exactly what a
//!   future signing ticket signs.
//! - **Targeting** ([`target::PolicyBinding`]/[`target::TargetScope`]) is
//!   kept structurally separate from content.
//! - **Resolution** ([`resolve::resolve`]) never fails and never panics —
//!   ADR-0001 D2's local critical path must not depend on a well-formed
//!   remote policy.
//! - **Diagnostics** ([`diagnostics::PolicyDiagnostic`]) are actionable:
//!   every one carries a non-empty `message` and `remediation`.

mod action_classification;
mod bundle;
pub mod cache;
mod content;
mod diagnostics;
mod local;
mod resolve;
mod revision;
mod revocation;
mod target;
pub mod trust_store;

pub use action_classification::classify_action_class;
pub use bundle::{
    verify_bundle, BundlePayload, BundleProvenance, BundleRejection, BundleSignature, KeyId,
    PayloadDigest, SignatureAlgorithm, SignedPolicyBundle, TrustStoreError, TrustedKey,
    TrustedVerificationKeys, VerifiedPolicyBundle, BUNDLE_SCHEMA_VERSION, BUNDLE_SIGNING_DOMAIN,
    CLOCK_SKEW_TOLERANCE_SECONDS, MAX_PAYLOAD_BYTES, MAX_SIGNATURES,
    SUPPORTED_BUNDLE_SCHEMA_VERSIONS,
};
pub use cache::{
    compute_posture, effective_outcome, evaluate_activation, evaluate_revocation_ingest, freshness,
    member_freshness, staleness_floor, ActivationDecision, ActivationOutcome, ActivationRejection,
    CacheGeneration, CacheSlotKind, CachedBundleRef, EffectivePolicy, FreshnessTier,
    MemberFreshness, PolicyCacheState, PolicyDegradationReason, PolicyFreshness, PolicyPosture,
    RevocationHit, RevocationHitMeta, RevocationIngestDecision, RevocationIngestRejection,
    RevocationSet, RiskClassTiers, SequenceHighWater, POLICY_CACHE_SCHEMA_VERSION,
};
pub use content::{
    ActionClass, CacheScope, CollectionScope, EgressContentClass, EgressScope, EnforcementOutcome,
    EnforcementRule, EnforcementScope, PolicyContent, RedactionProfile, ResolvedValues, RiskClass,
    RiskClassSeconds, SensorScope, VerdictOutcomes, POLICY_SCHEMA_VERSION,
    SUPPORTED_POLICY_SCHEMA_VERSIONS,
};
pub use diagnostics::{
    DiagnosticCode, DiagnosticSeverity, PolicyDiagnostic, PolicyValidationReport,
};
pub use local::{local_user_layer, local_user_layer_from_values};
pub use resolve::{resolve, FieldProvenance, PolicyFieldId, ResolvedPolicy};
pub use revision::{
    canonical_bytes, digest_of, PolicyDraft, PolicyId, PolicyRevisionBody, PolicyRevisionRef,
    PublishedPolicyRevision, RevisionDigest,
};
pub use revocation::{
    verify_revocation_list, RevocationEntry, RevocationPayload, RevocationRejection,
    RevocationTarget, SignedRevocationList, VerifiedRevocationList, MAX_REVOCATION_ENTRIES,
    REVOCATION_SCHEMA_VERSION, REVOCATION_SIGNING_DOMAIN, SUPPORTED_REVOCATION_SCHEMA_VERSIONS,
};
pub use target::{
    BoundRevision, DeviceContext, OsFamily, PolicyBinding, TargetLevel, TargetScope, TargetSelector,
};
pub use trust_store::resolve_trust_store;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cache_tests;

#[cfg(test)]
mod revocation_tests;
