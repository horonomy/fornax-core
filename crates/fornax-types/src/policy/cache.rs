//! Local policy cache: activation, rollback defense, and staleness floors
//! (FORNX-119, epic FORNX-69).
//!
//! Everything in this module is pure — no I/O, no clock reads (`now` is
//! always a parameter). [`evaluate_activation`] is the sole decision point
//! for whether a [`super::bundle::VerifiedPolicyBundle`] may become the
//! active generation; `fornax-store`'s `policy_cache` module is the sole
//! executor of that decision against real SQLite state. See
//! `docs/adr/0008-local-policy-cache-and-activation.md` for the full design
//! rationale (generations-as-sets, the `(issuer, policy_id)` high-water
//! mark, the freshness/floor tables, and the two residual risks inherited
//! from ADR-0007).
//!
//! **Cache unit.** A "generation" ([`CacheGeneration`]) is an immutable SET
//! of verified bundle references, at most one per `policy_id` lineage.
//! Slots ([`CacheSlotKind`]) are pointers to generations, not to single
//! revisions — `resolve()` needs multiple lineages layered together (e.g.
//! an org policy and a device policy), which a single-revision slot cannot
//! express.
//!
//! **Rollback defense.** [`SequenceHighWater`] is keyed on `(issuer,
//! policy_id)`, persisted independently of the active/pending/last-known-good
//! slots, and never lowered — not even by a rollback to last-known-good.
//!
//! **Expiry never discards content.** A cached bundle that goes stale or
//! expires is never deleted. Instead, [`staleness_floor`]/[`effective_outcome`]
//! ratchet a compiled-in, per-[`RiskClass`] enforcement floor:
//! `effective = max(resolved, floor)`, using [`EnforcementOutcome`]'s
//! existing strictness `Ord`.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::bundle::{BundleRejection, KeyId, PayloadDigest, VerifiedPolicyBundle};
use super::content::{ActionClass, EnforcementOutcome, RiskClass, RiskClassSeconds};
use super::diagnostics::PolicyValidationReport;
use super::resolve::ResolvedPolicy;
use super::revision::{PolicyId, RevisionDigest};
use super::revocation::{RevocationEntry, RevocationTarget, VerifiedRevocationList};
use crate::Verdict;

pub const POLICY_CACHE_SCHEMA_VERSION: u32 = 1;

/// Every field here is safe to surface on a local status endpoint
/// (`GET /api/policy`) — no display names, no content, no envelope bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedBundleRef {
    pub bundle_id: Uuid,
    pub issuer: String,
    pub sequence: u64,
    pub policy_id: PolicyId,
    pub revision: u32,
    pub revision_digest: RevisionDigest,
    pub payload_digest: PayloadDigest,
    pub verified_by: KeyId,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub first_activated_at: DateTime<Utc>,
    /// The freshness clock. Advanced by `Confirm` (a re-submission of the
    /// same sequence/bytes), NOT by re-activation alone.
    pub confirmed_at: DateTime<Utc>,
}

/// Immutable, atomically-written set. At most one member per `policy_id`,
/// sorted by `policy_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheGeneration {
    pub generation: u64,
    pub members: Vec<CachedBundleRef>,
    pub written_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheSlotKind {
    Active,
    Pending,
    LastKnownGood,
}

/// Anti-rollback memory, persisted independently of the slots, never
/// lowered — not even by `rollback_policy_to_last_known_good`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceHighWater {
    pub issuer: String,
    pub policy_id: PolicyId,
    pub max_sequence: u64,
    pub last_bundle_id: Uuid,
    pub last_payload_digest: PayloadDigest,
    pub last_seen_at: DateTime<Utc>,
}

/// What matched, for diagnostic/error attribution -- returned by
/// [`RevocationSet::hit`]. Deliberately small: only what a diagnostic or
/// [`ActivationRejection::Revoked`] needs to say *why*, never the raw
/// [`RevocationEntry`] (which may carry an `audit_ref` not meant for every
/// surface this hit is threaded through).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationHit {
    pub target: RevocationTarget,
    pub reason: String,
    pub revoked_at: String,
}

/// Metadata stored per revoked digest -- deviation from the design sketch's
/// bare `BTreeSet<Digest>`: `hit()` must return `reason`/`revoked_at`
/// attribution, which a bare set cannot hold. See ADR-0009.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationHitMeta {
    pub reason: String,
    pub revoked_at: String,
}

/// The local, sticky, union-only set of revoked digests (FORNX-123).
/// **Issuer-agnostic on the device**: an entry from ANY trusted issuer
/// revokes any digest -- cross-tenant isolation is enforced by the cloud's
/// authorization at publish time, not device-verifiable, so this type does
/// not attempt to fake it. See `docs/adr/0009-policy-revocation-and-emergency-control.md`.
///
/// Deviation from the design sketch: `revision_digests`/`payload_digests`
/// are `BTreeMap<_, RevocationHitMeta>`, not bare `BTreeSet<_>` -- `hit()`
/// must return attribution (`target`/`reason`/`revoked_at`), which a bare
/// set cannot carry. Field names are unchanged from the sketch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RevocationSet {
    pub revision_digests: BTreeMap<RevisionDigest, RevocationHitMeta>,
    pub payload_digests: BTreeMap<PayloadDigest, RevocationHitMeta>,
    pub max_sequence_by_issuer: BTreeMap<String, u64>,
    pub unrecognized_entry_count: u64,
}

impl RevocationSet {
    /// Checks both digest kinds -- a re-wrapped bundle (same content,
    /// different `bundle_id`/envelope, therefore different `payload_digest`
    /// but the SAME `revision_digest`) is caught by the revision-digest
    /// entry; an issuer revoking by `payload_digest` alone still catches an
    /// exact-envelope resubmission. Revision-digest is checked first (no
    /// significance to the order beyond determinism -- a digest is never
    /// revoked under both kinds with different attribution in this design).
    pub fn hit(&self, rev: &RevisionDigest, payload: &PayloadDigest) -> Option<RevocationHit> {
        if let Some(meta) = self.revision_digests.get(rev) {
            return Some(RevocationHit {
                target: RevocationTarget::RevisionDigest {
                    digest: rev.clone(),
                },
                reason: meta.reason.clone(),
                revoked_at: meta.revoked_at.clone(),
            });
        }
        if let Some(meta) = self.payload_digests.get(payload) {
            return Some(RevocationHit {
                target: RevocationTarget::PayloadDigest {
                    digest: payload.clone(),
                },
                reason: meta.reason.clone(),
                revoked_at: meta.revoked_at.clone(),
            });
        }
        None
    }
}

/// Exhaustive, no panics.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RevocationIngestRejection {
    #[error(
        "sequence {candidate} for issuer {issuer:?} did not advance past high-water {high_water}"
    )]
    SequenceNotAdvanced {
        issuer: String,
        candidate: u64,
        high_water: u64,
    },
    #[error("persistence failure: {detail}")]
    Persistence { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationIngestDecision {
    Apply {
        issuer: String,
        sequence: u64,
        new_entries: Vec<RevocationEntry>,
        superseded_sequence: Option<u64>,
    },
    AlreadyCurrent {
        issuer: String,
        sequence: u64,
    },
}

/// PURE -- no I/O, `now` unused today (kept as a parameter for symmetry with
/// [`evaluate_activation`] and because a future check, e.g. per-issuer rate
/// limiting, may need it) but the decision itself has no time dimension:
/// revocation entries carry no expiry (see `super::revocation`'s module
/// docs), so nothing here consults a clock.
///
/// `sequence < high_water` -> reject (`SequenceNotAdvanced`). `sequence ==
/// high_water` -> `AlreadyCurrent` (idempotent re-import, no duplicate
/// rows). `sequence > high_water` -> `Apply` with `new_entries` computed as
/// the set difference against every digest already recorded in
/// `state.revocations` -- entries are NEVER removed by a newer list that
/// omits them; only genuinely new entries are returned for the caller to
/// persist (existing rows are left untouched).
pub fn evaluate_revocation_ingest(
    candidate: &VerifiedRevocationList,
    state: &PolicyCacheState,
    _now: DateTime<Utc>,
) -> Result<RevocationIngestDecision, RevocationIngestRejection> {
    let issuer = candidate.issuer().to_string();
    let candidate_sequence = candidate.sequence();

    let existing_high_water = state
        .revocations
        .max_sequence_by_issuer
        .get(&issuer)
        .copied();

    if let Some(hw) = existing_high_water {
        if candidate_sequence < hw {
            return Err(RevocationIngestRejection::SequenceNotAdvanced {
                issuer,
                candidate: candidate_sequence,
                high_water: hw,
            });
        }
        if candidate_sequence == hw {
            return Ok(RevocationIngestDecision::AlreadyCurrent {
                issuer,
                sequence: candidate_sequence,
            });
        }
    }

    let new_entries: Vec<RevocationEntry> = candidate
        .entries()
        .iter()
        .filter(|entry| match &entry.target {
            RevocationTarget::RevisionDigest { digest } => {
                !state.revocations.revision_digests.contains_key(digest)
            }
            RevocationTarget::PayloadDigest { digest } => {
                !state.revocations.payload_digests.contains_key(digest)
            }
            RevocationTarget::Unrecognized => true,
        })
        .cloned()
        .collect();

    Ok(RevocationIngestDecision::Apply {
        issuer,
        sequence: candidate_sequence,
        new_entries,
        superseded_sequence: existing_high_water,
    })
}

/// Converts today's silent fail-open (a wholly unusable generation quietly
/// resolving to baseline's `ObserveOnly`-for-everything, see this module's
/// top doc comment) into a loud, queryable signal. Deliberately thin: NO
/// new enforcement semantics live here, and NO default per-action-class
/// risk assumption is invented to "fix" the gap -- that would contradict
/// `docs/adr/0006-policy-as-data.md` and `action_classification.rs`'s
/// explicit "never a silently invented risk assumption" discipline. Wiring
/// this into an actual enforcement decision is out of this ticket's scope
/// (a future enforcement-wiring ticket's job) -- this only computes and
/// surfaces the posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPosture {
    Normal,
    Degraded { reason: PolicyDegradationReason },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDegradationReason {
    Revoked,
    Unverifiable,
    TrustStoreUnavailable,
    NoUsableGeneration,
}

/// Pins an explicit precedence for the (fairly common) case where multiple
/// diagnostic codes are present at once -- e.g. a generation that fell back
/// to last-known-good because of revocation also triggers the pre-existing
/// FORNX-119 "nothing usable" diagnostic once LKG is *also* unusable. The
/// most-specific cause wins: `Revoked` > `Unverifiable` >
/// `TrustStoreUnavailable` > `NoUsableGeneration`. A fresh install that has
/// never had a bundle imported (`ever_configured == false`) is `Normal`,
/// not `Degraded` -- mirroring [`freshness`]'s own `Unconfigured` tier: no
/// floor/posture penalty is invented merely because nothing has ever been
/// configured.
pub fn compute_posture(
    ever_configured: bool,
    usable_is_empty: bool,
    diagnostics: &[super::diagnostics::PolicyDiagnostic],
) -> PolicyPosture {
    use super::diagnostics::DiagnosticCode;

    if !usable_is_empty || !ever_configured {
        return PolicyPosture::Normal;
    }
    if diagnostics
        .iter()
        .any(|d| d.code == DiagnosticCode::PolicyCacheRevoked)
    {
        return PolicyPosture::Degraded {
            reason: PolicyDegradationReason::Revoked,
        };
    }
    if diagnostics
        .iter()
        .any(|d| d.code == DiagnosticCode::PolicyCacheUnverifiable)
    {
        return PolicyPosture::Degraded {
            reason: PolicyDegradationReason::Unverifiable,
        };
    }
    if diagnostics
        .iter()
        .any(|d| d.code == DiagnosticCode::TrustStoreUnavailable)
    {
        return PolicyPosture::Degraded {
            reason: PolicyDegradationReason::TrustStoreUnavailable,
        };
    }
    PolicyPosture::Degraded {
        reason: PolicyDegradationReason::NoUsableGeneration,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCacheState {
    pub schema_version: u32,
    pub active: Option<CacheGeneration>,
    /// ALWAYS `None` in v0.6.0 — modelled, never populated, no API can set
    /// it. No caller exists yet for staging; see this ticket's deviations.
    pub pending: Option<CacheGeneration>,
    pub last_known_good: Option<CacheGeneration>,
    pub high_water: BTreeMap<(String, PolicyId), SequenceHighWater>,
    /// Sticky: once `true`, never `false` again.
    pub ever_configured: bool,
    /// FORNX-123: the local, sticky, union-only set of revoked digests.
    /// Never populated by anything in `verify_bundle`/`verify_revocation_list`
    /// themselves — only by [`evaluate_revocation_ingest`]'s persisted
    /// decision.
    pub revocations: RevocationSet,
}

/// Derive order == strictness order; `meet` is per-field max, mirroring
/// [`EnforcementOutcome`]/[`RiskClassSeconds`]'s own strictness conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessTier {
    Unconfigured,
    Fresh,
    Stale,
    GraceExpired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskClassTiers {
    pub low: FreshnessTier,
    pub elevated: FreshnessTier,
    pub high: FreshnessTier,
    pub critical: FreshnessTier,
}

impl RiskClassTiers {
    pub fn uniform(t: FreshnessTier) -> Self {
        Self {
            low: t,
            elevated: t,
            high: t,
            critical: t,
        }
    }

    /// Exhaustive match, no wildcard arm (D4 discipline — see
    /// [`super::content::VerdictOutcomes::for_verdict`]'s precedent).
    pub fn for_risk(&self, r: RiskClass) -> FreshnessTier {
        match r {
            RiskClass::Low => self.low,
            RiskClass::Elevated => self.elevated,
            RiskClass::High => self.high,
            RiskClass::Critical => self.critical,
        }
    }

    pub(crate) fn meet(a: Self, b: Self) -> Self {
        Self {
            low: a.low.max(b.low),
            elevated: a.elevated.max(b.elevated),
            high: a.high.max(b.high),
            critical: a.critical.max(b.critical),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberFreshness {
    pub bundle_id: Uuid,
    pub policy_id: PolicyId,
    pub confirmed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub age_seconds: u64,
    pub tier_by_risk: RiskClassTiers,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFreshness {
    pub tier_by_risk: RiskClassTiers,
    pub members: Vec<MemberFreshness>,
    pub evaluated_at: DateTime<Utc>,
}

/// `tier(member, R) = GraceExpired` if `now > confirmed_at + max_age(R) +
/// grace`; `Stale` if `now > confirmed_at + max_age(R)` OR `now >
/// expires_at`; `Fresh` otherwise. `now` is always a parameter, never
/// `Utc::now()` internally.
fn tier_for_risk(
    confirmed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    max_age_seconds: u32,
    offline_grace_seconds: u32,
    now: DateTime<Utc>,
) -> FreshnessTier {
    let stale_at = confirmed_at + Duration::seconds(max_age_seconds as i64);
    let grace_expired_at = stale_at + Duration::seconds(offline_grace_seconds as i64);
    if now > grace_expired_at {
        FreshnessTier::GraceExpired
    } else if now > stale_at || now > expires_at {
        FreshnessTier::Stale
    } else {
        FreshnessTier::Fresh
    }
}

pub fn member_freshness(
    m: &CachedBundleRef,
    max_age: RiskClassSeconds,
    offline_grace_seconds: u32,
    now: DateTime<Utc>,
) -> MemberFreshness {
    let tier_by_risk = RiskClassTiers {
        low: tier_for_risk(
            m.confirmed_at,
            m.expires_at,
            max_age.low,
            offline_grace_seconds,
            now,
        ),
        elevated: tier_for_risk(
            m.confirmed_at,
            m.expires_at,
            max_age.elevated,
            offline_grace_seconds,
            now,
        ),
        high: tier_for_risk(
            m.confirmed_at,
            m.expires_at,
            max_age.high,
            offline_grace_seconds,
            now,
        ),
        critical: tier_for_risk(
            m.confirmed_at,
            m.expires_at,
            max_age.critical,
            offline_grace_seconds,
            now,
        ),
    };
    let age_seconds = (now - m.confirmed_at).num_seconds().max(0) as u64;
    MemberFreshness {
        bundle_id: m.bundle_id,
        policy_id: m.policy_id,
        confirmed_at: m.confirmed_at,
        expires_at: m.expires_at,
        age_seconds,
        tier_by_risk,
    }
}

/// Generation tier per risk class = strictest across members
/// ([`RiskClassTiers::meet`]). No members + `ever_configured` ->
/// `GraceExpired` for every class (floors apply on baseline values). No
/// members + never configured -> `Unconfigured` (no floors — a fresh
/// install must not silently gain blocking power).
pub fn freshness(
    members: &[CachedBundleRef],
    ever_configured: bool,
    max_age: RiskClassSeconds,
    offline_grace_seconds: u32,
    now: DateTime<Utc>,
) -> PolicyFreshness {
    if members.is_empty() {
        let tier = if ever_configured {
            RiskClassTiers::uniform(FreshnessTier::GraceExpired)
        } else {
            RiskClassTiers::uniform(FreshnessTier::Unconfigured)
        };
        return PolicyFreshness {
            tier_by_risk: tier,
            members: Vec::new(),
            evaluated_at: now,
        };
    }

    let member_freshnesses: Vec<MemberFreshness> = members
        .iter()
        .map(|m| member_freshness(m, max_age, offline_grace_seconds, now))
        .collect();

    let mut tier_by_risk = member_freshnesses[0].tier_by_risk;
    for mf in member_freshnesses.iter().skip(1) {
        tier_by_risk = RiskClassTiers::meet(tier_by_risk, mf.tier_by_risk);
    }

    PolicyFreshness {
        tier_by_risk,
        members: member_freshnesses,
        evaluated_at: now,
    }
}

/// Compiled-in per-[`RiskClass`] enforcement floor, NOT policy-authored — a
/// stale policy must never be able to lower its own floor.
///
/// | RiskClass | Fresh/Unconfigured | Stale | GraceExpired |
/// |---|---|---|---|
/// | Low       | -   | -    | -    |
/// | Elevated  | -   | -    | Warn |
/// | High      | -   | Warn | Warn |
/// | Critical  | -   | Warn | Block |
pub fn staleness_floor(risk: RiskClass, tier: FreshnessTier) -> Option<EnforcementOutcome> {
    match (risk, tier) {
        (RiskClass::Low, FreshnessTier::Unconfigured) => None,
        (RiskClass::Low, FreshnessTier::Fresh) => None,
        (RiskClass::Low, FreshnessTier::Stale) => None,
        (RiskClass::Low, FreshnessTier::GraceExpired) => None,
        (RiskClass::Elevated, FreshnessTier::Unconfigured) => None,
        (RiskClass::Elevated, FreshnessTier::Fresh) => None,
        (RiskClass::Elevated, FreshnessTier::Stale) => None,
        (RiskClass::Elevated, FreshnessTier::GraceExpired) => Some(EnforcementOutcome::Warn),
        (RiskClass::High, FreshnessTier::Unconfigured) => None,
        (RiskClass::High, FreshnessTier::Fresh) => None,
        (RiskClass::High, FreshnessTier::Stale) => Some(EnforcementOutcome::Warn),
        (RiskClass::High, FreshnessTier::GraceExpired) => Some(EnforcementOutcome::Warn),
        (RiskClass::Critical, FreshnessTier::Unconfigured) => None,
        (RiskClass::Critical, FreshnessTier::Fresh) => None,
        (RiskClass::Critical, FreshnessTier::Stale) => Some(EnforcementOutcome::Warn),
        (RiskClass::Critical, FreshnessTier::GraceExpired) => Some(EnforcementOutcome::Block),
    }
}

/// `max(resolved, floor)` — monotone, staleness only ever tightens.
pub fn effective_outcome(
    resolved: EnforcementOutcome,
    risk: RiskClass,
    tier: FreshnessTier,
) -> EnforcementOutcome {
    match staleness_floor(risk, tier) {
        Some(floor) => resolved.max(floor),
        None => resolved,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectivePolicy {
    pub resolved: ResolvedPolicy,
    pub freshness: PolicyFreshness,
}

impl EffectivePolicy {
    /// The rule's own `risk_class` selects the tier. No matching rule ->
    /// `ObserveOnly`, unaffected by staleness — an action class nobody ever
    /// governed does not acquire a floor because some other class went
    /// stale.
    pub fn enforcement_outcome_for(&self, ac: &ActionClass, v: Verdict) -> EnforcementOutcome {
        let Some(rule) = self
            .resolved
            .values
            .enforcement_rules
            .iter()
            .find(|r| &r.action_class == ac)
        else {
            return EnforcementOutcome::ObserveOnly;
        };
        let base = rule.outcomes.for_verdict(v);
        let tier = self.freshness.tier_by_risk.for_risk(rule.risk_class);
        effective_outcome(base, rule.risk_class, tier)
    }
}

/// Exhaustive, no panics anywhere in this module.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ActivationRejection {
    #[error("candidate bundle failed verification: {0}")]
    NotVerified(#[source] BundleRejection),
    #[error(
        "sequence {candidate} for issuer {issuer:?} policy_id {policy_id:?} did not advance past high-water {high_water}"
    )]
    SequenceNotAdvanced {
        issuer: String,
        policy_id: PolicyId,
        candidate: u64,
        high_water: u64,
    },
    #[error(
        "sequence {sequence} for policy_id {policy_id:?} was already seen as a different bundle ({recorded_bundle_id})"
    )]
    SequenceReused {
        policy_id: PolicyId,
        sequence: u64,
        recorded_bundle_id: Uuid,
    },
    #[error(
        "policy_id {policy_id:?} is already bound to issuer {bound_issuer:?}, candidate names issuer {candidate_issuer:?}"
    )]
    IssuerMismatchForLineage {
        policy_id: PolicyId,
        bound_issuer: String,
        candidate_issuer: String,
    },
    #[error("candidate bundle's bindings are unusable: {0}")]
    BindingsUnusable(#[source] PolicyValidationReport),
    #[error("persistence failure: {detail}")]
    Persistence { detail: String },
    /// FORNX-123: the candidate's `revision_digest`/`payload_digest` is on
    /// the local revocation list. Checked FIRST in [`evaluate_activation`],
    /// before lineage/sequence -- "must never be trusted again" outranks
    /// every other rejection reason. A revoked bundle's signature is still
    /// perfectly valid (`verify_bundle` never sees the revocation list at
    /// all); this is the one place that fact is caught.
    #[error("policy_id {policy_id:?} candidate is revoked: {reason} (revoked_at={revoked_at})")]
    Revoked {
        policy_id: PolicyId,
        target: RevocationTarget,
        reason: String,
        revoked_at: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivationDecision {
    Activate {
        members: Vec<CachedBundleRef>,
        replaced: Option<PolicyId>,
    },
    Confirm {
        policy_id: PolicyId,
        bundle_id: Uuid,
        payload_digest: PayloadDigest,
    },
}

/// No `PartialEq`/`Eq` — `Rejected` carries [`ActivationRejection`], which
/// wraps `BundleRejection`/`PolicyValidationReport` (neither implements
/// `PartialEq`). Tests assert on this with `matches!`, not `assert_eq!`.
#[derive(Debug, Clone)]
pub enum ActivationOutcome {
    Activated {
        generation: u64,
        superseded: Option<u64>,
        replaced_member: Option<PolicyId>,
    },
    /// A real committed write, not a no-op.
    Confirmed {
        generation: u64,
        policy_id: PolicyId,
        confirmed_at: DateTime<Utc>,
    },
    Rejected {
        rejection: ActivationRejection,
        active_generation: Option<u64>,
    },
}

/// PURE — no I/O, no clock read internally (`now` is a parameter).
/// `fornax-store::policy_cache::Store::submit_policy_bundle` is the sole
/// executor of the [`ActivationDecision`] this returns.
///
/// `candidate` must already be a [`VerifiedPolicyBundle`] — signature
/// verification (`verify_bundle`) happens before this function is ever
/// called, outside any transaction, so an invalid bundle never replaces
/// last-known-good.
pub fn evaluate_activation(
    candidate: &VerifiedPolicyBundle,
    state: &PolicyCacheState,
    now: DateTime<Utc>,
) -> Result<ActivationDecision, ActivationRejection> {
    let issuer = candidate.payload().provenance.issuer.clone();
    let policy_id = candidate.revision().body().policy_id;

    // FORNX-123: revocation is checked FIRST, before lineage/sequence --
    // "must never be trusted again" outranks every other rejection reason.
    // A revoked bundle's signature is still perfectly valid (`verify_bundle`
    // never consults the revocation list), so this is the one place that
    // fact is caught.
    if let Some(hit) = state
        .revocations
        .hit(candidate.revision().digest(), candidate.payload_digest())
    {
        return Err(ActivationRejection::Revoked {
            policy_id,
            target: hit.target,
            reason: hit.reason,
            revoked_at: hit.revoked_at,
        });
    }

    // Lineage/issuer binding: scoped per-lineage, not global. Any
    // high-water row ever recorded for this policy_id under a different
    // issuer means this lineage is already bound elsewhere.
    for (hw_issuer, hw_policy_id) in state.high_water.keys() {
        if *hw_policy_id == policy_id && hw_issuer != &issuer {
            return Err(ActivationRejection::IssuerMismatchForLineage {
                policy_id,
                bound_issuer: hw_issuer.clone(),
                candidate_issuer: issuer,
            });
        }
    }

    let candidate_sequence = candidate.payload().sequence;
    let candidate_bundle_id = candidate.payload().bundle_id;
    let candidate_payload_digest = candidate.payload_digest().clone();

    if let Some(hw) = state.high_water.get(&(issuer.clone(), policy_id)) {
        if candidate_sequence < hw.max_sequence {
            return Err(ActivationRejection::SequenceNotAdvanced {
                issuer,
                policy_id,
                candidate: candidate_sequence,
                high_water: hw.max_sequence,
            });
        }
        if candidate_sequence == hw.max_sequence {
            if hw.last_bundle_id == candidate_bundle_id
                && hw.last_payload_digest == candidate_payload_digest
            {
                return Ok(ActivationDecision::Confirm {
                    policy_id,
                    bundle_id: candidate_bundle_id,
                    payload_digest: candidate_payload_digest,
                });
            }
            return Err(ActivationRejection::SequenceReused {
                policy_id,
                sequence: candidate_sequence,
                recorded_bundle_id: hw.last_bundle_id,
            });
        }
        // candidate_sequence > hw.max_sequence -> fall through to Activate.
    }

    // Bind: covers PinAtLocalUserLayer, the one case verify_bundle itself
    // doesn't check.
    if let Err(report) = candidate.clone().into_bound_revisions() {
        return Err(ActivationRejection::BindingsUnusable(report));
    }

    let not_before: DateTime<Utc> = candidate
        .payload()
        .not_before
        .parse()
        .map_err(|_| ActivationRejection::Persistence {
            detail: format!(
                "candidate not_before {:?} failed to parse after verify_bundle already validated it",
                candidate.payload().not_before
            ),
        })?;
    let expires_at: DateTime<Utc> = candidate
        .payload()
        .expires_at
        .parse()
        .map_err(|_| ActivationRejection::Persistence {
            detail: format!(
                "candidate expires_at {:?} failed to parse after verify_bundle already validated it",
                candidate.payload().expires_at
            ),
        })?;

    let new_member = CachedBundleRef {
        bundle_id: candidate_bundle_id,
        issuer: issuer.clone(),
        sequence: candidate_sequence,
        policy_id,
        revision: candidate.revision().body().revision,
        revision_digest: candidate.revision().digest().clone(),
        payload_digest: candidate_payload_digest,
        verified_by: candidate.verified_by().clone(),
        not_before,
        expires_at,
        first_activated_at: now,
        confirmed_at: now,
    };

    let mut members: Vec<CachedBundleRef> = state
        .active
        .as_ref()
        .map(|g| g.members.clone())
        .unwrap_or_default();
    let replaced = if members.iter().any(|m| m.policy_id == policy_id) {
        Some(policy_id)
    } else {
        None
    };
    members.retain(|m| m.policy_id != policy_id);
    members.push(new_member);
    members.sort_by_key(|m| m.policy_id);

    Ok(ActivationDecision::Activate { members, replaced })
}
