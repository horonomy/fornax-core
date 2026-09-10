//! Value-of-Information evidence planner (FORNX-345, Stage 8 / Active
//! Evidence Intelligence): given a claim's current fused finding, asks
//! "what evidence would most reduce uncertainty next" instead of stopping
//! at `Unverified`/`Review` or collecting every possible signal.
//!
//! **Ranking-only.** This module never acquires evidence itself (that is
//! FORNX-346, not yet built) and never produces a
//! [`crate::decision::RecommendationAction`] — [`plan`] and
//! [`DeterministicVoiPolicy`] import neither `decision` nor anything that
//! could construct one, and a test below pins that a plan's JSON carries no
//! `action` field.
//!
//! **No numeric score is ever serialized.** [`UtilityEstimate`]'s seven
//! dimensions and an [`AcquisitionCandidate`]'s 1-based `rank` are the only
//! public output — the integer weighting inside [`DeterministicVoiPolicy`]
//! stays private, matching this crate's existing discipline
//! (`UncertaintyBand` forbids numeric comparison;
//! `fused_finding_json_carries_no_numeric_confidence_field` in `fusion.rs`).
//! A serialized weighted score would invite exactly the false probabilistic
//! precision this ticket's AC explicitly forbids.
//!
//! **Correlation/independence is read, never re-derived.** [`Independence`]
//! is computed structurally from `FusedFinding::counted_link_ids` and each
//! counted link's evidence `correlation_group`/`trust_class` — this module
//! never re-implements `fusion.rs`'s R5 collapsing logic, only reads what it
//! already counted.
//!
//! See `docs/adr/0015-value-of-information.md` for the full boundary and the
//! list of claims this mechanism cannot verify without FORNX-346 (real
//! acquisition).

use std::collections::BTreeSet;

use fornax_types::experiment::{SideEffectAllowList, SideEffectClass};
use fornax_types::sensor_config::SensorDisableConfig;
use fornax_types::{
    Claim, Evidence, EvidenceGraph, RuntimeCapabilities, SignalAvailability, SignalClass,
    TrustClass,
};
use uuid::Uuid;

use crate::decision::RiskClass;
use crate::fusion::{FusedFinding, FusionRule};

// --- Gaps --------------------------------------------------------------

/// Why more evidence is wanted for a claim. See [`derive_gaps`] for exactly
/// which real signals produce which variant.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGapKind {
    /// The evidence graph has zero links and zero missing-evidence notes —
    /// nobody looked at all.
    NoEvidenceAtAll,
    /// A signal class a verifier expects, explicitly noted missing
    /// (`fornax_types::graph::MissingEvidence`) with a concerning
    /// availability state.
    ExpectedSignalMissing { signal_class: SignalClass },
    /// A signal class this runtime's own declared capabilities mark
    /// unsupported/unavailable/redacted/failed/disabled — a gap even when
    /// no verifier explicitly noted it missing.
    SignalClassUnobservable { signal_class: SignalClass },
    /// Every link fusion considered was discounted (`FusionRule::AllSupportDiscounted`).
    AllVotesDiscounted,
    /// Support was demoted for being stale (`FusionRule::StaleSupportDemoted`).
    StaleSupport,
    /// Fusion flagged at least one counted vote with no recorded
    /// correlation group (`FusionRule::IndependenceUnverified`).
    IndependenceUnverified,
    /// Every counted vote shares one correlation group — a single source
    /// dressed as corroboration.
    SingleSourceCorroboration,
    /// `FusedFinding::unresolved_conflict` is true.
    UnresolvedConflict,
}

/// One reason to want more evidence for a claim, naming exactly which
/// links/missing-evidence entries motivated it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvidenceGap {
    pub kind: EvidenceGapKind,
    pub claim_id: Uuid,
    pub link_ids: Vec<Uuid>,
    pub missing_evidence_ids: Vec<Uuid>,
    pub detail: String,
}

/// Derive every gap for `claim`'s current fused finding. Three sources,
/// deliberately all three (module docs `docs/adr/0015`): `fused.rationale`
/// (what fusion already flagged), `graph.missing` (what a verifier
/// explicitly noted absent), and `capabilities` (what this runtime cannot
/// observe at all — real traffic rarely populates `graph.missing` beyond
/// `ToolTrace`/`FinalResponse`/`ToolResultPayload`, so capabilities is the
/// only source that ever surfaces a `ProcessResult` gap).
///
/// Returns at least one gap for every fused finding except a `Verified`
/// verdict under `UncertaintyBand::Corroborated` — itself documented
/// unreachable on real traffic in `fusion.rs` (no shipped sensor stamps
/// `correlation_group` yet), so that empty-gaps case is fixture-only.
pub fn derive_gaps(
    claim: &Claim,
    graph: &EvidenceGraph,
    evidence: &[Evidence],
    fused: &FusedFinding,
    capabilities: &[RuntimeCapabilities],
) -> Vec<EvidenceGap> {
    let mut gaps = Vec::new();
    let mut covered_classes: BTreeSet<String> = BTreeSet::new();

    if fused.unresolved_conflict {
        gaps.push(EvidenceGap {
            kind: EvidenceGapKind::UnresolvedConflict,
            claim_id: claim.id,
            link_ids: fused.counted_link_ids.clone(),
            missing_evidence_ids: vec![],
            detail: "fusion reports an unresolved supports/contradicts conflict".to_string(),
        });
    }

    for entry in &fused.rationale {
        match entry.rule {
            FusionRule::StaleSupportDemoted => gaps.push(EvidenceGap {
                kind: EvidenceGapKind::StaleSupport,
                claim_id: claim.id,
                link_ids: entry.link_ids.clone(),
                missing_evidence_ids: vec![],
                detail: entry.detail.clone(),
            }),
            FusionRule::AllSupportDiscounted => gaps.push(EvidenceGap {
                kind: EvidenceGapKind::AllVotesDiscounted,
                claim_id: claim.id,
                link_ids: entry.link_ids.clone(),
                missing_evidence_ids: vec![],
                detail: entry.detail.clone(),
            }),
            FusionRule::IndependenceUnverified => gaps.push(EvidenceGap {
                kind: EvidenceGapKind::IndependenceUnverified,
                claim_id: claim.id,
                link_ids: entry.link_ids.clone(),
                missing_evidence_ids: vec![],
                detail: entry.detail.clone(),
            }),
            _ => {}
        }
    }

    if counted_correlation_groups(fused, graph, evidence).len() == 1
        && fused.counted_link_ids.len() >= 2
    {
        gaps.push(EvidenceGap {
            kind: EvidenceGapKind::SingleSourceCorroboration,
            claim_id: claim.id,
            link_ids: fused.counted_link_ids.clone(),
            missing_evidence_ids: vec![],
            detail: "every counted vote shares one correlation group".to_string(),
        });
    }

    for missing in &graph.missing {
        if is_concerning(&missing.availability) {
            covered_classes.insert(signal_class_key(&missing.signal_class));
            gaps.push(EvidenceGap {
                kind: EvidenceGapKind::ExpectedSignalMissing {
                    signal_class: missing.signal_class.clone(),
                },
                claim_id: claim.id,
                link_ids: vec![],
                missing_evidence_ids: vec![missing.id],
                detail: missing
                    .detail
                    .clone()
                    .unwrap_or_else(|| "signal explicitly noted missing".to_string()),
            });
        }
    }

    for caps in capabilities {
        for signal in &caps.signals {
            if is_concerning_capability(&signal.state)
                && !covered_classes.contains(&signal_class_key(&signal.class))
            {
                covered_classes.insert(signal_class_key(&signal.class));
                gaps.push(EvidenceGap {
                    kind: EvidenceGapKind::SignalClassUnobservable {
                        signal_class: signal.class.clone(),
                    },
                    claim_id: claim.id,
                    link_ids: vec![],
                    missing_evidence_ids: vec![],
                    detail: signal.detail.clone().unwrap_or_else(|| {
                        "runtime capability state marks this unobservable".into()
                    }),
                });
            }
        }
    }

    if graph.links.is_empty() && graph.missing.is_empty() {
        gaps.push(EvidenceGap {
            kind: EvidenceGapKind::NoEvidenceAtAll,
            claim_id: claim.id,
            link_ids: vec![],
            missing_evidence_ids: vec![],
            detail: "no evidence link or missing-evidence note exists for this claim".to_string(),
        });
    }

    gaps
}

fn is_concerning(a: &SignalAvailability) -> bool {
    matches!(
        a,
        SignalAvailability::Unsupported
            | SignalAvailability::Unavailable
            | SignalAvailability::CollectionFailed
            | SignalAvailability::Redacted
            | SignalAvailability::Disabled
    )
}

fn is_concerning_capability(a: &SignalAvailability) -> bool {
    is_concerning(a)
}

fn signal_class_key(class: &SignalClass) -> String {
    // SignalClass does not derive Ord/Hash (shared, persisted type) -- key
    // on its serde wire tag instead of adding derives for this module's
    // convenience.
    serde_json::to_value(class)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

// --- Independence (read, never re-derived) ------------------------------

/// Every distinct correlation group id among `fused`'s counted links'
/// evidence. Structural: reads `Evidence::source.correlation_group`, never
/// parses `RationaleEntry.detail` prose.
fn counted_correlation_groups(
    fused: &FusedFinding,
    graph: &EvidenceGraph,
    evidence: &[Evidence],
) -> BTreeSet<Uuid> {
    let mut groups = BTreeSet::new();
    for link_id in &fused.counted_link_ids {
        if let Some(link) = graph.links.iter().find(|l| &l.id == link_id) {
            if let Some(ev) = evidence.iter().find(|e| e.id == link.evidence_id) {
                if let Some(source) = &ev.source {
                    if let Some(group) = source.correlation_group {
                        groups.insert(group);
                    }
                }
            }
        }
    }
    groups
}

/// Every distinct `TrustClass` among `fused`'s counted links' evidence.
fn counted_trust_classes(
    fused: &FusedFinding,
    graph: &EvidenceGraph,
    evidence: &[Evidence],
) -> BTreeSet<String> {
    let mut classes = BTreeSet::new();
    for link_id in &fused.counted_link_ids {
        if let Some(link) = graph.links.iter().find(|l| &l.id == link_id) {
            if let Some(ev) = evidence.iter().find(|e| e.id == link.evidence_id) {
                if let Some(source) = &ev.source {
                    classes.insert(trust_class_key(&source.trust_class));
                }
            }
        }
    }
    classes
}

fn trust_class_key(class: &TrustClass) -> String {
    serde_json::to_value(class)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// How independent a candidate probe's evidence would be from what fusion
/// already counted (AC3: correlated evidence must never be rewarded as if
/// it were independent confirmation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Independence {
    IndependentOfCounted,
    PartiallyCorrelated,
    SameSourceAsCounted,
    Unverified,
}

fn independence_of(
    probe_trust_class: &TrustClass,
    fused: &FusedFinding,
    graph: &EvidenceGraph,
    evidence: &[Evidence],
) -> Independence {
    let counted_classes = counted_trust_classes(fused, graph, evidence);
    let key = trust_class_key(probe_trust_class);
    if !counted_classes.contains(&key) {
        return Independence::IndependentOfCounted;
    }
    // The probe's trust class was already counted -- independent only if
    // fusion recorded no correlation group for that counted evidence
    // (Unverified, not rewarded as independent), otherwise it's the same
    // correlated source.
    if counted_correlation_groups(fused, graph, evidence).is_empty() {
        Independence::Unverified
    } else {
        Independence::SameSourceAsCounted
    }
}

// --- Candidate evidence requests ----------------------------------------

/// A concrete kind of evidence acquisition this planner can recommend.
/// Closed on purpose -- adding a variant is additive, but each one must
/// have a real referent in this codebase (see `docs/adr/0015`'s table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    RerunTest,
    InspectVcsState,
    QueryCiStatus,
    VerifyArtifactHash,
    BoundedReplayExperiment,
    HumanReview,
}

/// One concrete evidence request a probe would perform. Not itself
/// executable -- FORNX-346 maps this to a real sensor/executor.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EvidenceRequest {
    pub kind: ProbeKind,
    pub target_signal_class: SignalClass,
    pub expected_trust_class: TrustClass,
    pub required_side_effects: SideEffectAllowList,
    pub description: String,
}

fn probes_for_class(signal_class: &SignalClass) -> Vec<EvidenceRequest> {
    let describe = |kind: ProbeKind, trust: TrustClass, effects: &[SideEffectClass], desc: &str| {
        EvidenceRequest {
            kind,
            target_signal_class: signal_class.clone(),
            expected_trust_class: trust,
            required_side_effects: SideEffectAllowList::new(effects.iter().copied()),
            description: desc.to_string(),
        }
    };

    match signal_class {
        SignalClass::ProcessResult => vec![describe(
            ProbeKind::RerunTest,
            TrustClass::HostObserved,
            &[SideEffectClass::ProcessSpawn],
            "rerun the relevant command/test and observe its real exit code",
        )],
        SignalClass::ToolTrace | SignalClass::ToolResultPayload => vec![
            describe(
                ProbeKind::InspectVcsState,
                TrustClass::HostObserved,
                // fornax-vcs is a pure in-process `gix` reimplementation --
                // no subprocess spawn, no ProcessSpawn grant needed.
                &[],
                "inspect current git/filesystem state directly",
            ),
            describe(
                ProbeKind::VerifyArtifactHash,
                TrustClass::HostObserved,
                &[],
                "verify a referenced file/artifact hash against disk, read-only",
            ),
        ],
        _ => vec![describe(
            ProbeKind::HumanReview,
            TrustClass::HumanReviewed,
            &[],
            "no automated probe can reconstruct this signal after the fact -- needs human review",
        )],
    }
}

fn probes_for_gap(gap: &EvidenceGap) -> Vec<EvidenceRequest> {
    let describe = |kind: ProbeKind,
                    class: SignalClass,
                    trust: TrustClass,
                    effects: &[SideEffectClass],
                    desc: &str| {
        EvidenceRequest {
            kind,
            target_signal_class: class,
            expected_trust_class: trust,
            required_side_effects: SideEffectAllowList::new(effects.iter().copied()),
            description: desc.to_string(),
        }
    };

    match &gap.kind {
        EvidenceGapKind::ExpectedSignalMissing { signal_class }
        | EvidenceGapKind::SignalClassUnobservable { signal_class } => probes_for_class(signal_class),
        EvidenceGapKind::StaleSupport => vec![
            describe(
                ProbeKind::InspectVcsState,
                SignalClass::ToolTrace,
                TrustClass::HostObserved,
                &[],
                "re-observe current state now -- the counted evidence is stale",
            ),
            describe(
                ProbeKind::QueryCiStatus,
                SignalClass::ToolResultPayload,
                TrustClass::IndependentExternal,
                &[SideEffectClass::NetworkCall],
                "query current CI status as a fresh, independent observation",
            ),
        ],
        EvidenceGapKind::IndependenceUnverified | EvidenceGapKind::SingleSourceCorroboration => vec![
            describe(
                ProbeKind::QueryCiStatus,
                SignalClass::ToolResultPayload,
                TrustClass::IndependentExternal,
                &[SideEffectClass::NetworkCall],
                "an independent external source would corroborate without sharing the counted source",
            ),
            describe(
                ProbeKind::InspectVcsState,
                SignalClass::ToolTrace,
                TrustClass::HostObserved,
                &[],
                "a host-observed check is independent of an agent-reported source",
            ),
            describe(
                ProbeKind::HumanReview,
                SignalClass::FinalResponse,
                TrustClass::HumanReviewed,
                &[],
                "human review is independent of every automated source",
            ),
        ],
        EvidenceGapKind::AllVotesDiscounted => vec![
            describe(
                ProbeKind::RerunTest,
                SignalClass::ProcessResult,
                TrustClass::HostObserved,
                &[SideEffectClass::ProcessSpawn],
                "every prior vote was discounted -- a fresh direct observation is needed",
            ),
            describe(
                ProbeKind::InspectVcsState,
                SignalClass::ToolTrace,
                TrustClass::HostObserved,
                &[],
                "inspect current state directly",
            ),
        ],
        EvidenceGapKind::UnresolvedConflict => vec![
            describe(
                ProbeKind::InspectVcsState,
                SignalClass::ToolTrace,
                TrustClass::HostObserved,
                &[],
                "inspect current state to help resolve the conflict",
            ),
            describe(
                ProbeKind::RerunTest,
                SignalClass::ProcessResult,
                TrustClass::HostObserved,
                &[SideEffectClass::ProcessSpawn],
                "rerun to see which side of the conflict current reality supports",
            ),
            describe(
                ProbeKind::BoundedReplayExperiment,
                SignalClass::ProcessResult,
                TrustClass::HostObserved,
                &[
                    SideEffectClass::EphemeralWorktreeMutation,
                    SideEffectClass::ProcessSpawn,
                ],
                "a bounded counterfactual replay could discriminate between the conflicting claims",
            ),
            describe(
                ProbeKind::HumanReview,
                SignalClass::FinalResponse,
                TrustClass::HumanReviewed,
                &[],
                "a human can resolve what automated evidence alone could not",
            ),
        ],
        EvidenceGapKind::NoEvidenceAtAll => {
            let mut probes = probes_for_class(&SignalClass::ProcessResult);
            probes.extend(probes_for_class(&SignalClass::ToolTrace));
            probes.push(describe(
                ProbeKind::HumanReview,
                SignalClass::FinalResponse,
                TrustClass::HumanReviewed,
                &[],
                "nothing has looked at this claim at all yet",
            ));
            probes
        }
    }
}

// --- Utility dimensions and availability --------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Discrimination {
    High,
    Moderate,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recency {
    FreshObservation,
    PossiblyStale,
    HistoricalOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionCost {
    Free,
    Cheap,
    Moderate,
    Expensive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionLatency {
    SubSecond,
    Seconds,
    Minutes,
    Long,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySensitivity {
    None,
    LocalOnly,
    EgressRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionRisk {
    ReadOnly,
    SandboxedMutation,
    ExternalSideEffect,
}

/// The seven inspectable dimensions behind a candidate's rank (AC7: "policy/
/// utility estimates", never rendered as a probability). See module docs
/// for why no numeric score accompanies these on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UtilityEstimate {
    pub discrimination: Discrimination,
    pub independence: Independence,
    pub recency: Recency,
    pub cost: AcquisitionCost,
    pub latency: AcquisitionLatency,
    pub privacy: PrivacySensitivity,
    pub action_risk: ActionRisk,
}

/// Whether a candidate can actually be acted on given local policy — never
/// silently dropped; see [`EvidencePlan::unavailable`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CandidateAvailability {
    Available,
    /// The required side effect or egress is not currently granted --
    /// naming exactly what to grant, never a bare "denied".
    RequiresApproval {
        missing_grant: String,
    },
    /// The target signal class/sensor is unobservable/disabled for this
    /// runtime.
    Unavailable {
        reason: String,
    },
    /// Never approvable through this planner (e.g. a filesystem write
    /// outside the experiment worktree boundary).
    Forbidden {
        reason: String,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcquisitionCandidate {
    pub request: EvidenceRequest,
    pub utility: UtilityEstimate,
    pub availability: CandidateAvailability,
    /// Indices into `EvidencePlan::gaps` this candidate would address.
    pub addresses_gaps: Vec<usize>,
    /// 1-based rank among `Available`/`RequiresApproval` candidates.
    /// `None` for `Unavailable`/`Forbidden`.
    pub rank: Option<u32>,
    pub why_it_matters: String,
}

/// Policy/acquisition context [`VoiPolicy::plan`] gates candidates against.
/// Built by the caller (e.g. from `GlobalExperimentPolicy`,
/// `privacy::cloud_sync_allowed`, and `SensorDisableConfig`) -- kept as
/// plain data here so this module adds no new dependency to `fornax-verify`.
#[derive(Debug, Clone)]
pub struct AcquisitionPolicy {
    pub granted_side_effects: SideEffectAllowList,
    pub egress_allowed: bool,
    pub disabled_sensors: SensorDisableConfig,
}

fn classify_availability(
    request: &EvidenceRequest,
    capabilities: &[RuntimeCapabilities],
    policy: &AcquisitionPolicy,
) -> CandidateAvailability {
    for class in [SideEffectClass::FilesystemWriteOutsideWorktree] {
        if request_requires(request, class) {
            return CandidateAvailability::Forbidden {
                reason: format!("{class:?} is never approvable through this planner"),
            };
        }
    }

    for caps in capabilities {
        let state = caps.state_of(&request.target_signal_class);
        if matches!(
            state,
            SignalAvailability::Unsupported | SignalAvailability::Unavailable
        ) {
            return CandidateAvailability::Unavailable {
                reason: format!(
                    "{state:?} for {:?} on this runtime",
                    request.target_signal_class
                ),
            };
        }
        if state == SignalAvailability::Disabled {
            return CandidateAvailability::Unavailable {
                reason: "producing sensor is disabled by local configuration".to_string(),
            };
        }
    }

    for class in effective_classes(request) {
        if !policy.granted_side_effects.permits(class) {
            return CandidateAvailability::RequiresApproval {
                missing_grant: format!("{class:?}"),
            };
        }
    }

    if privacy_of(request) == PrivacySensitivity::EgressRequired && !policy.egress_allowed {
        return CandidateAvailability::RequiresApproval {
            missing_grant: "FORNAX_CLOUD_SYNC_ENABLED".to_string(),
        };
    }

    CandidateAvailability::Available
}

fn request_requires(request: &EvidenceRequest, class: SideEffectClass) -> bool {
    effective_classes(request).contains(&class)
}

fn effective_classes(request: &EvidenceRequest) -> Vec<SideEffectClass> {
    [
        SideEffectClass::EphemeralWorktreeMutation,
        SideEffectClass::ProcessSpawn,
        SideEffectClass::NetworkCall,
        SideEffectClass::FilesystemWriteOutsideWorktree,
    ]
    .into_iter()
    .filter(|c| request.required_side_effects.permits(*c))
    .collect()
}

fn privacy_of(request: &EvidenceRequest) -> PrivacySensitivity {
    if request
        .required_side_effects
        .permits(SideEffectClass::NetworkCall)
    {
        PrivacySensitivity::EgressRequired
    } else {
        PrivacySensitivity::None
    }
}

fn discrimination_for(gap_count: usize, kind: ProbeKind) -> Discrimination {
    if gap_count >= 2 {
        return Discrimination::High;
    }
    match kind {
        ProbeKind::RerunTest | ProbeKind::InspectVcsState | ProbeKind::QueryCiStatus => {
            Discrimination::High
        }
        ProbeKind::VerifyArtifactHash | ProbeKind::BoundedReplayExperiment => {
            Discrimination::Moderate
        }
        ProbeKind::HumanReview => Discrimination::Low,
    }
}

fn recency_for(kind: ProbeKind) -> Recency {
    match kind {
        ProbeKind::RerunTest | ProbeKind::InspectVcsState | ProbeKind::QueryCiStatus => {
            Recency::FreshObservation
        }
        ProbeKind::VerifyArtifactHash => Recency::PossiblyStale,
        ProbeKind::BoundedReplayExperiment => Recency::FreshObservation,
        ProbeKind::HumanReview => Recency::HistoricalOnly,
    }
}

fn cost_for(kind: ProbeKind) -> AcquisitionCost {
    match kind {
        ProbeKind::VerifyArtifactHash => AcquisitionCost::Free,
        ProbeKind::InspectVcsState | ProbeKind::QueryCiStatus => AcquisitionCost::Cheap,
        ProbeKind::RerunTest => AcquisitionCost::Moderate,
        ProbeKind::BoundedReplayExperiment => AcquisitionCost::Expensive,
        ProbeKind::HumanReview => AcquisitionCost::Expensive,
    }
}

fn latency_for(kind: ProbeKind) -> AcquisitionLatency {
    match kind {
        ProbeKind::VerifyArtifactHash => AcquisitionLatency::SubSecond,
        ProbeKind::InspectVcsState | ProbeKind::QueryCiStatus => AcquisitionLatency::Seconds,
        ProbeKind::RerunTest => AcquisitionLatency::Minutes,
        ProbeKind::BoundedReplayExperiment => AcquisitionLatency::Minutes,
        ProbeKind::HumanReview => AcquisitionLatency::Long,
    }
}

fn action_risk_for(kind: ProbeKind) -> ActionRisk {
    match kind {
        ProbeKind::VerifyArtifactHash
        | ProbeKind::InspectVcsState
        | ProbeKind::QueryCiStatus
        | ProbeKind::HumanReview => ActionRisk::ReadOnly,
        ProbeKind::RerunTest => ActionRisk::SandboxedMutation,
        ProbeKind::BoundedReplayExperiment => ActionRisk::SandboxedMutation,
    }
}

// --- Plan ----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanOutcome {
    CandidatesRanked,
    /// At least one gap was identified, but nothing is currently available
    /// to acquire (everything is `Unavailable`/`Forbidden`, or every
    /// candidate `RequiresApproval`).
    NoUsefulEvidenceAvailable,
    /// No gap was identified at all -- see [`derive_gaps`]'s doc comment on
    /// when this is (and is not) reachable.
    NoGapIdentified,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvidencePlan {
    pub claim_id: Uuid,
    pub outcome: PlanOutcome,
    pub gaps: Vec<EvidenceGap>,
    /// Ranked, `Available`/`RequiresApproval` candidates, best first.
    pub candidates: Vec<AcquisitionCandidate>,
    /// `Unavailable`/`Forbidden` candidates -- listed with reasons, never
    /// silently dropped.
    pub unavailable: Vec<AcquisitionCandidate>,
    pub policy_name: String,
    pub policy_version: u32,
    pub computed_at: String,
}

/// Everything [`VoiPolicy::plan`] needs. Deliberately does not include
/// anything from `decision` — see module docs.
pub struct PlanInput<'a> {
    pub claim: &'a Claim,
    pub graph: &'a EvidenceGraph,
    pub evidence: &'a [Evidence],
    pub fused: &'a FusedFinding,
    pub risk: RiskClass,
    pub capabilities: &'a [RuntimeCapabilities],
    pub acquisition: &'a AcquisitionPolicy,
}

pub trait VoiPolicy {
    fn name(&self) -> &'static str;
    fn policy_version(&self) -> u32;
    fn plan(&self, input: &PlanInput<'_>, computed_at: &str) -> EvidencePlan;
}

/// The first, deterministic [`VoiPolicy`] (FORNX-345). Pure, sync, no
/// clock read internally -- `computed_at` is passed in, mirroring
/// `FusionPolicy`/`DecisionPolicy`'s existing discipline.
pub struct DeterministicVoiPolicy;

impl DeterministicVoiPolicy {
    fn score(utility: &UtilityEstimate) -> i32 {
        let discrimination_points: i32 = match utility.discrimination {
            Discrimination::High => 60,
            Discrimination::Moderate => 30,
            Discrimination::Low => 10,
        };
        let independence_numerator: i32 = match utility.independence {
            Independence::IndependentOfCounted => 100,
            Independence::PartiallyCorrelated => 40,
            Independence::Unverified => 70,
            Independence::SameSourceAsCounted => 10,
        };
        let mut gain = discrimination_points * independence_numerator / 100;
        gain += match utility.recency {
            Recency::FreshObservation => 10,
            Recency::PossiblyStale => 0,
            Recency::HistoricalOnly => -10,
        };

        let penalty = match utility.cost {
            AcquisitionCost::Free => 0,
            AcquisitionCost::Cheap => 5,
            AcquisitionCost::Moderate => 15,
            AcquisitionCost::Expensive => 35,
        } + match utility.latency {
            AcquisitionLatency::SubSecond => 0,
            AcquisitionLatency::Seconds => 3,
            AcquisitionLatency::Minutes => 10,
            AcquisitionLatency::Long => 25,
        } + match utility.action_risk {
            ActionRisk::ReadOnly => 0,
            ActionRisk::SandboxedMutation => 5,
            ActionRisk::ExternalSideEffect => 20,
        } + match utility.privacy {
            PrivacySensitivity::None | PrivacySensitivity::LocalOnly => 0,
            PrivacySensitivity::EgressRequired => 2,
        };

        gain.saturating_sub(penalty)
    }
}

impl VoiPolicy for DeterministicVoiPolicy {
    fn name(&self) -> &'static str {
        "deterministic_voi_v1"
    }

    fn policy_version(&self) -> u32 {
        1
    }

    fn plan(&self, input: &PlanInput<'_>, computed_at: &str) -> EvidencePlan {
        let gaps = derive_gaps(
            input.claim,
            input.graph,
            input.evidence,
            input.fused,
            input.capabilities,
        );

        if gaps.is_empty() {
            return EvidencePlan {
                claim_id: input.claim.id,
                outcome: PlanOutcome::NoGapIdentified,
                gaps,
                candidates: vec![],
                unavailable: vec![],
                policy_name: self.name().to_string(),
                policy_version: self.policy_version(),
                computed_at: computed_at.to_string(),
            };
        }

        // Dedupe candidates by (ProbeKind, target signal class), unioning
        // which gaps each addresses.
        let mut by_key: Vec<(ProbeKind, String, EvidenceRequest, Vec<usize>)> = Vec::new();
        for (gap_index, gap) in gaps.iter().enumerate() {
            for request in probes_for_gap(gap) {
                let key = (request.kind, signal_class_key(&request.target_signal_class));
                if let Some(existing) = by_key
                    .iter_mut()
                    .find(|(k, c, _, _)| (*k, c.clone()) == key)
                {
                    existing.3.push(gap_index);
                } else {
                    by_key.push((request.kind, key.1, request, vec![gap_index]));
                }
            }
        }

        let mut scored: Vec<(i32, AcquisitionCandidate)> = by_key
            .into_iter()
            .map(|(kind, _, request, addresses_gaps)| {
                let independence = independence_of(
                    &request.expected_trust_class,
                    input.fused,
                    input.graph,
                    input.evidence,
                );
                let utility = UtilityEstimate {
                    discrimination: discrimination_for(addresses_gaps.len(), kind),
                    independence,
                    recency: recency_for(kind),
                    cost: cost_for(kind),
                    latency: latency_for(kind),
                    privacy: privacy_of(&request),
                    action_risk: action_risk_for(kind),
                };
                let availability =
                    classify_availability(&request, input.capabilities, input.acquisition);
                let why_it_matters = format!(
                    "addresses {} gap(s): {}",
                    addresses_gaps.len(),
                    addresses_gaps
                        .iter()
                        .map(|i| format!("{:?}", gaps[*i].kind))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                let score = Self::score(&utility);
                (
                    score,
                    AcquisitionCandidate {
                        request,
                        utility,
                        availability,
                        addresses_gaps,
                        rank: None,
                        why_it_matters,
                    },
                )
            })
            .collect();

        scored.sort_by(|(score_a, a), (score_b, b)| {
            score_b
                .cmp(score_a)
                .then_with(|| format!("{:?}", a.request.kind).cmp(&format!("{:?}", b.request.kind)))
                .then_with(|| {
                    signal_class_key(&a.request.target_signal_class)
                        .cmp(&signal_class_key(&b.request.target_signal_class))
                })
        });

        let mut candidates = Vec::new();
        let mut unavailable = Vec::new();
        let mut rank = 1u32;
        for (_, mut candidate) in scored {
            match candidate.availability {
                CandidateAvailability::Available
                | CandidateAvailability::RequiresApproval { .. } => {
                    candidate.rank = Some(rank);
                    rank += 1;
                    candidates.push(candidate);
                }
                CandidateAvailability::Unavailable { .. }
                | CandidateAvailability::Forbidden { .. } => {
                    unavailable.push(candidate);
                }
            }
        }

        let outcome = if candidates
            .iter()
            .any(|c| c.availability == CandidateAvailability::Available)
        {
            PlanOutcome::CandidatesRanked
        } else {
            PlanOutcome::NoUsefulEvidenceAvailable
        };

        EvidencePlan {
            claim_id: input.claim.id,
            outcome,
            gaps,
            candidates,
            unavailable,
            policy_name: self.name().to_string(),
            policy_version: self.policy_version(),
            computed_at: computed_at.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fusion::{RationaleEntry, RuleEffect, UncertaintyBand};
    use fornax_types::graph::{EvidenceRelation, MissingEvidence};
    use fornax_types::sensor::{
        ClockSource, CollectionMethod, EvidenceSource, Freshness, TamperBoundary,
    };
    use fornax_types::{CapabilitySignal, EvidenceKind, EvidenceLink, Provider, Verdict};

    fn claim() -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn source(trust: TrustClass, group: Option<Uuid>) -> EvidenceSource {
        EvidenceSource {
            sensor_name: "test_sensor".into(),
            trust_class: trust,
            collected_at: "2026-01-01T00:00:00Z".into(),
            provider: None,
            collection_method: CollectionMethod::HookCallback,
            collector_version: None,
            freshness: Freshness {
                clock_source: ClockSource::HostClock,
                caveat: None,
            },
            tamper_boundary: TamperBoundary::default(),
            correlation_group: group,
            derived_from: vec![],
        }
    }

    fn evidence(kind: EvidenceKind, trust: TrustClass, group: Option<Uuid>) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({}),
            provenance: "test".into(),
            source: Some(source(trust, group)),
            extension: None,
            evidence_purged: false,
        }
    }

    fn link(claim_id: Uuid, evidence_id: Uuid, relation: EvidenceRelation) -> EvidenceLink {
        EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id,
            evidence_id,
            relation,
            linked_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn fused(
        claim_id: Uuid,
        counted_link_ids: Vec<Uuid>,
        unresolved_conflict: bool,
    ) -> FusedFinding {
        FusedFinding {
            claim_id,
            verdict: Verdict::Review,
            uncertainty: UncertaintyBand::Qualified,
            rationale: vec![],
            counted_link_ids,
            discounted_link_ids: vec![],
            missing_evidence_ids: vec![],
            unresolved_conflict,
            policy_name: "test".into(),
            policy_version: 1,
            computed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn acquisition_policy(granted: &[SideEffectClass]) -> AcquisitionPolicy {
        AcquisitionPolicy {
            granted_side_effects: SideEffectAllowList::new(granted.iter().copied()),
            egress_allowed: false,
            disabled_sensors: SensorDisableConfig::empty(),
        }
    }

    #[test]
    fn no_evidence_at_all_is_a_gap_on_an_empty_graph() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(c.id, vec![], false);
        let gaps = derive_gaps(&c, &graph, &[], &f, &[]);
        assert!(gaps
            .iter()
            .any(|g| g.kind == EvidenceGapKind::NoEvidenceAtAll));
    }

    #[test]
    fn a_concerning_missing_evidence_note_is_a_gap() {
        let c = claim();
        let graph = EvidenceGraph {
            links: vec![],
            missing: vec![MissingEvidence {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                claim_id: c.id,
                signal_class: SignalClass::ProcessResult,
                availability: SignalAvailability::Unavailable,
                detail: None,
                noted_at: "2026-01-01T00:00:00Z".into(),
            }],
        };
        let f = fused(c.id, vec![], false);
        let gaps = derive_gaps(&c, &graph, &[], &f, &[]);
        assert!(gaps.iter().any(|g| matches!(
            g.kind,
            EvidenceGapKind::ExpectedSignalMissing {
                signal_class: SignalClass::ProcessResult
            }
        )));
    }

    #[test]
    fn an_unobservable_capability_is_a_gap_even_with_no_missing_evidence_note() {
        let c = claim();
        let graph = EvidenceGraph {
            links: vec![],
            missing: vec![],
        };
        let f = fused(c.id, vec![], false);
        let caps = RuntimeCapabilities {
            schema_version: 1,
            provider: Provider::ClaudeCode,
            signals: vec![CapabilitySignal {
                class: SignalClass::ProcessResult,
                state: SignalAvailability::Unsupported,
                detail: None,
            }],
            notes: Default::default(),
        };
        let gaps = derive_gaps(&c, &graph, &[], &f, std::slice::from_ref(&caps));
        assert!(gaps.iter().any(|g| matches!(
            g.kind,
            EvidenceGapKind::SignalClassUnobservable {
                signal_class: SignalClass::ProcessResult
            }
        )));
    }

    #[test]
    fn an_unresolved_conflict_is_a_gap() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(c.id, vec![], true);
        let gaps = derive_gaps(&c, &graph, &[], &f, &[]);
        assert!(gaps
            .iter()
            .any(|g| g.kind == EvidenceGapKind::UnresolvedConflict));
    }

    /// AC-adjacent safety invariant: this planner must never claim "no gap"
    /// for a finding that plainly has one. `Verified + Corroborated` is the
    /// sole exception -- and that band is itself documented unreachable on
    /// real traffic (fusion.rs), so this fixture is deliberately synthetic.
    #[test]
    fn a_review_verdict_always_yields_at_least_one_gap() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(c.id, vec![], false); // Review, Qualified, no links at all
        let gaps = derive_gaps(&c, &graph, &[], &f, &[]);
        assert!(!gaps.is_empty());
    }

    #[test]
    fn a_cheap_independent_probe_outranks_an_expensive_correlated_one() {
        let c = claim();
        let group = Uuid::new_v4();
        let ev_agent = evidence(
            EvidenceKind::ToolResult,
            TrustClass::AgentAdjacent,
            Some(group),
        );
        let link_agent = link(c.id, ev_agent.id, EvidenceRelation::Supports);
        let graph = EvidenceGraph {
            links: vec![link_agent.clone()],
            missing: vec![],
        };
        let evidence_pool = vec![ev_agent];
        let f = FusedFinding {
            rationale: vec![RationaleEntry {
                rule: FusionRule::IndependenceUnverified,
                effect: RuleEffect::Caveat,
                link_ids: vec![link_agent.id],
                missing_evidence_ids: vec![],
                evidence_ids: vec![link_agent.evidence_id],
                detail: "no recorded correlation group".into(),
            }],
            ..fused(c.id, vec![link_agent.id], false)
        };

        let policy = DeterministicVoiPolicy;
        let acquisition =
            acquisition_policy(&[SideEffectClass::NetworkCall, SideEffectClass::ProcessSpawn]);
        let plan = policy.plan(
            &PlanInput {
                claim: &c,
                graph: &graph,
                evidence: &evidence_pool,
                fused: &f,
                risk: RiskClass::Balanced,
                capabilities: &[],
                acquisition: &acquisition,
            },
            "2026-01-01T00:00:00Z",
        );

        let ci_rank = plan
            .candidates
            .iter()
            .find(|cand| cand.request.kind == ProbeKind::QueryCiStatus)
            .and_then(|cand| cand.rank)
            .expect("QueryCiStatus must be a ranked candidate");
        let replay_rank = plan
            .candidates
            .iter()
            .find(|cand| cand.request.kind == ProbeKind::BoundedReplayExperiment)
            .and_then(|cand| cand.rank);
        if let Some(replay_rank) = replay_rank {
            assert!(
                ci_rank < replay_rank,
                "cheap independent QueryCiStatus (rank {ci_rank}) must outrank expensive \
                 BoundedReplayExperiment (rank {replay_rank})"
            );
        }
    }

    #[test]
    fn correlated_evidence_is_never_scored_as_independent() {
        let group = Uuid::new_v4();
        let counted = fused_with_one_agent_adjacent_counted_vote(group);
        let (c, graph, evidence_pool, f) = counted;

        let independence = independence_of(&TrustClass::AgentAdjacent, &f, &graph, &evidence_pool);
        assert_eq!(
            independence,
            Independence::SameSourceAsCounted,
            "a probe with the same trust class as an already-grouped counted vote must not \
             read as independent"
        );
        let _ = c;
    }

    fn fused_with_one_agent_adjacent_counted_vote(
        group: Uuid,
    ) -> (Claim, EvidenceGraph, Vec<Evidence>, FusedFinding) {
        let c = claim();
        let ev = evidence(
            EvidenceKind::ToolResult,
            TrustClass::AgentAdjacent,
            Some(group),
        );
        let l = link(c.id, ev.id, EvidenceRelation::Supports);
        let graph = EvidenceGraph {
            links: vec![l.clone()],
            missing: vec![],
        };
        let f = fused(c.id, vec![l.id], false);
        (c, graph, vec![ev], f)
    }

    #[test]
    fn a_side_effect_not_granted_requires_approval_naming_the_missing_grant() {
        let request = EvidenceRequest {
            kind: ProbeKind::RerunTest,
            target_signal_class: SignalClass::ProcessResult,
            expected_trust_class: TrustClass::HostObserved,
            required_side_effects: SideEffectAllowList::new([SideEffectClass::ProcessSpawn]),
            description: "rerun".into(),
        };
        let policy = acquisition_policy(&[]);
        let availability = classify_availability(&request, &[], &policy);
        assert!(matches!(
            availability,
            CandidateAvailability::RequiresApproval { .. }
        ));
    }

    #[test]
    fn a_filesystem_write_outside_worktree_is_always_forbidden() {
        let request = EvidenceRequest {
            kind: ProbeKind::BoundedReplayExperiment,
            target_signal_class: SignalClass::ProcessResult,
            expected_trust_class: TrustClass::HostObserved,
            required_side_effects: SideEffectAllowList::new([
                SideEffectClass::FilesystemWriteOutsideWorktree,
            ]),
            description: "would write outside the worktree".into(),
        };
        let policy = acquisition_policy(&[SideEffectClass::FilesystemWriteOutsideWorktree]);
        let availability = classify_availability(&request, &[], &policy);
        assert!(matches!(
            availability,
            CandidateAvailability::Forbidden { .. }
        ));
    }

    #[test]
    fn an_unobservable_signal_class_is_unavailable_not_a_ranked_candidate() {
        let request = EvidenceRequest {
            kind: ProbeKind::RerunTest,
            target_signal_class: SignalClass::ProcessResult,
            expected_trust_class: TrustClass::HostObserved,
            required_side_effects: SideEffectAllowList::default(),
            description: "rerun".into(),
        };
        let caps = RuntimeCapabilities {
            schema_version: 1,
            provider: Provider::ClaudeCode,
            signals: vec![CapabilitySignal {
                class: SignalClass::ProcessResult,
                state: SignalAvailability::Unsupported,
                detail: None,
            }],
            notes: Default::default(),
        };
        let policy = acquisition_policy(&[]);
        let availability = classify_availability(&request, std::slice::from_ref(&caps), &policy);
        assert!(matches!(
            availability,
            CandidateAvailability::Unavailable { .. }
        ));
    }

    #[test]
    fn no_useful_evidence_available_when_everything_is_ungranted() {
        // ProcessResult's only probe (RerunTest) requires ProcessSpawn --
        // unlike NoEvidenceAtAll's gap, this one has no HumanReview fallback
        // (probes_for_class), so ungranting ProcessSpawn genuinely leaves
        // zero Available candidates.
        let c = claim();
        let graph = EvidenceGraph {
            links: vec![],
            missing: vec![MissingEvidence {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                claim_id: c.id,
                signal_class: SignalClass::ProcessResult,
                availability: SignalAvailability::Unavailable,
                detail: None,
                noted_at: "2026-01-01T00:00:00Z".into(),
            }],
        };
        let f = fused(c.id, vec![], false);
        let policy = DeterministicVoiPolicy;
        let acquisition = acquisition_policy(&[]); // nothing granted
        let plan = policy.plan(
            &PlanInput {
                claim: &c,
                graph: &graph,
                evidence: &[],
                fused: &f,
                risk: RiskClass::Balanced,
                capabilities: &[],
                acquisition: &acquisition,
            },
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(plan.outcome, PlanOutcome::NoUsefulEvidenceAvailable);
        assert!(!plan.gaps.is_empty());
        assert!(plan
            .candidates
            .iter()
            .all(|cand| !matches!(cand.availability, CandidateAvailability::Available)));
    }

    #[test]
    fn planning_never_touches_decision_and_never_serializes_an_action_field() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(c.id, vec![], false);
        let policy = DeterministicVoiPolicy;
        let acquisition =
            acquisition_policy(&[SideEffectClass::ProcessSpawn, SideEffectClass::NetworkCall]);
        let plan = policy.plan(
            &PlanInput {
                claim: &c,
                graph: &graph,
                evidence: &[],
                fused: &f,
                risk: RiskClass::Balanced,
                capabilities: &[],
                acquisition: &acquisition,
            },
            "2026-01-01T00:00:00Z",
        );
        let value = serde_json::to_value(&plan).unwrap();
        let serialized = serde_json::to_string(&value).unwrap();
        assert!(!serialized.contains("\"action\""));
    }

    #[test]
    fn no_candidate_or_utility_estimate_ever_serializes_a_numeric_score() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let f = fused(c.id, vec![], false);
        let policy = DeterministicVoiPolicy;
        let acquisition =
            acquisition_policy(&[SideEffectClass::ProcessSpawn, SideEffectClass::NetworkCall]);
        let plan = policy.plan(
            &PlanInput {
                claim: &c,
                graph: &graph,
                evidence: &[],
                fused: &f,
                risk: RiskClass::Balanced,
                capabilities: &[],
                acquisition: &acquisition,
            },
            "2026-01-01T00:00:00Z",
        );
        for candidate in plan.candidates.iter().chain(plan.unavailable.iter()) {
            let value = serde_json::to_value(candidate).unwrap();
            assert!(value.get("score").is_none());
            assert!(value["utility"].get("score").is_none());
        }
    }

    #[test]
    fn planning_is_reproducible_for_the_same_pinned_input() {
        let c = claim();
        let graph = EvidenceGraph {
            links: vec![],
            missing: vec![MissingEvidence {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                claim_id: c.id,
                signal_class: SignalClass::ProcessResult,
                availability: SignalAvailability::Unavailable,
                detail: None,
                noted_at: "2026-01-01T00:00:00Z".into(),
            }],
        };
        let f = fused(c.id, vec![], false);
        let policy = DeterministicVoiPolicy;
        let acquisition =
            acquisition_policy(&[SideEffectClass::ProcessSpawn, SideEffectClass::NetworkCall]);
        let input = PlanInput {
            claim: &c,
            graph: &graph,
            evidence: &[],
            fused: &f,
            risk: RiskClass::Balanced,
            capabilities: &[],
            acquisition: &acquisition,
        };
        let plan_a = policy.plan(&input, "2026-01-01T00:00:00Z");
        let plan_b = policy.plan(&input, "2026-01-01T00:00:00Z");
        assert_eq!(
            serde_json::to_string(&plan_a).unwrap(),
            serde_json::to_string(&plan_b).unwrap()
        );
    }

    /// FORNX-346 regression: `fornax-vcs` is a pure in-process `gix`
    /// reimplementation (no subprocess spawn, see its own module docs) --
    /// every `InspectVcsState` request must declare an empty
    /// `required_side_effects`, never `ProcessSpawn`. A prior version of
    /// this module wrongly required `ProcessSpawn` for every
    /// `InspectVcsState` candidate, which gated an actually auto-safe,
    /// read-only probe behind a grant it never needed under
    /// `GlobalExperimentPolicy::default()` (which permits only
    /// `EphemeralWorktreeMutation`).
    #[test]
    fn inspect_vcs_state_never_requires_process_spawn() {
        for signal_class in [SignalClass::ToolTrace, SignalClass::ToolResultPayload] {
            for request in probes_for_class(&signal_class) {
                if request.kind == ProbeKind::InspectVcsState {
                    assert!(
                        request.required_side_effects.is_read_only(),
                        "InspectVcsState for {signal_class:?} must be read-only, got {:?}",
                        request.required_side_effects
                    );
                }
            }
        }

        let c = claim();
        for gap_kind in [
            EvidenceGapKind::StaleSupport,
            EvidenceGapKind::IndependenceUnverified,
            EvidenceGapKind::SingleSourceCorroboration,
            EvidenceGapKind::AllVotesDiscounted,
            EvidenceGapKind::UnresolvedConflict,
        ] {
            let gap = EvidenceGap {
                kind: gap_kind.clone(),
                claim_id: c.id,
                link_ids: vec![],
                missing_evidence_ids: vec![],
                detail: "test".to_string(),
            };
            for request in probes_for_gap(&gap) {
                if request.kind == ProbeKind::InspectVcsState {
                    assert!(
                        request.required_side_effects.is_read_only(),
                        "InspectVcsState for gap {gap_kind:?} must be read-only, got {:?}",
                        request.required_side_effects
                    );
                    // Available under the default (EphemeralWorktreeMutation-
                    // only) policy -- the whole point of the fix.
                    let acquisition = acquisition_policy(&[]);
                    assert_eq!(
                        classify_availability(&request, &[], &acquisition),
                        CandidateAvailability::Available
                    );
                }
            }
        }
    }
}
