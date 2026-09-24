//! Versioned replay manifest (FORNX-98 AC 1/3/4): the single frozen artifact
//! [`engine::replay`](crate::engine::replay) consumes. Field shape follows
//! `fornax_bench::manifest::RunManifest`'s precedent (explicit schema
//! version separate from policy versions, policy identity read from real
//! policy instances rather than hardcoded) plus
//! `fornax_adapter_conformance::fixtures::FixtureMetadata`'s precedent for
//! naming the observing adapter/provider and its runtime version.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use fornax_types::{Claim, Evidence, EvidenceGraph, Provider, Verdict};
use fornax_verify::decision::{DecisionPolicy, RecommendationAction, RiskClass};
use fornax_verify::fusion::{FusedFinding, FusionInput, FusionPolicy, UncertaintyBand};

/// Schema version of [`ReplayManifest`] itself, independent of the
/// fusion/decision policy versions it records — bump when this struct's own
/// shape changes in a way that could break a consumer parsing an older
/// manifest. Mirrors `fornax_bench::manifest::MANIFEST_SCHEMA_VERSION`.
pub const REPLAY_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The `manifest_schema_version` values this binary knows how to interpret.
/// A manifest outside this set fails explicit validation
/// ([`crate::engine::ReplayError::UnsupportedManifestSchemaVersion`]) rather
/// than being silently accepted or panicking (FORNX-98 AC 4).
pub const SUPPORTED_MANIFEST_SCHEMA_VERSIONS: &[u32] = &[1];

/// A fully self-describing, frozen record of one trajectory's interpretation
/// (FORNX-98 AC 1): which schema version produced it, which adapter/provider
/// (+ runtime version) observed the underlying session, which fusion/decision
/// policy (name + version) computed the recorded outcome, which risk class
/// and sensor-disable configuration were in effect, the frozen
/// claim/evidence/graph itself, and the verdict/uncertainty/action that were
/// recorded for it. Carries everything [`crate::engine::replay`] needs —
/// nothing else is read from disk, network, or any adapter at replay time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayManifest {
    pub manifest_schema_version: u32,

    /// Which provider's adapter produced the frozen observations below, and
    /// which runtime version of that provider it was captured from —
    /// mirrors `FixtureMetadata::{provider, provider_runtime_version}`. Not
    /// used to re-run the adapter (replay never does that); recorded purely
    /// so a comparison can surface "this manifest was captured against
    /// Claude Code v2.1.238" when investigating a drift.
    pub adapter_provider: Provider,
    pub adapter_runtime_version: String,

    pub fusion_policy_name: String,
    pub fusion_policy_version: u32,
    pub decision_policy_name: String,
    pub decision_policy_version: u32,
    pub risk_class: RiskClass,

    /// Sensors whose evidence was excluded before fusion computed the
    /// recorded outcome (empty for a plain run). Recorded so a replay
    /// under a different disable-set is visibly a different config, not
    /// silently compared as if it were the same run.
    #[serde(default)]
    pub disabled_sensors: BTreeSet<String>,

    /// The frozen input: a single claim plus the evidence pool/graph that
    /// was resolved for it. `fornax-store`'s claim/evidence/finding schema
    /// (`crates/fornax-store/src/lib.rs`) is the source of truth for what
    /// these shapes mean; this manifest carries already-materialized
    /// `fornax_types` values, not a store handle.
    pub claim: Claim,
    pub evidence_pool: Vec<Evidence>,
    pub evidence_graph: EvidenceGraph,

    /// What was recorded the last time this exact input was interpreted —
    /// the historical result [`crate::engine::replay`] compares its live
    /// recomputation against.
    pub recorded_verdict: Verdict,
    pub recorded_uncertainty: UncertaintyBand,
    pub recorded_action: RecommendationAction,

    /// RFC3339 timestamp pinned onto both the original and every replayed
    /// `FusedFinding::computed_at` — replay reuses this value rather than
    /// reading the clock, so two replays of the same manifest are
    /// byte-identical (FORNX-98 AC 1; mirrors `fornax_verify::fusion`'s "pure
    /// and sync" discipline and `fornax_bench::manifest::RunManifest::run_at`).
    pub recorded_at: String,
}

/// Builds a [`ReplayManifest`] by running `fusion_policy`/`decision_policy`
/// over `claim`/`graph`/`evidence_pool` once, right now, and freezing both
/// the input and that computed result — this is the one place in this crate
/// a manifest is *produced* rather than merely replayed. Reads policy
/// identity from the real policy instances (never hardcoded), mirroring
/// `fornax_bench::manifest::build_manifest`.
#[allow(clippy::too_many_arguments)]
pub fn build_manifest(
    claim: Claim,
    evidence_pool: Vec<Evidence>,
    evidence_graph: EvidenceGraph,
    adapter_provider: Provider,
    adapter_runtime_version: String,
    fusion_policy: &impl FusionPolicy,
    decision_policy: &impl DecisionPolicy,
    risk_class: RiskClass,
    disabled_sensors: BTreeSet<String>,
    recorded_at: &str,
) -> ReplayManifest {
    let input = FusionInput {
        claim: &claim,
        graph: &evidence_graph,
        evidence: &evidence_pool,
    };
    let fused: FusedFinding = fusion_policy.fuse(&input, recorded_at);
    let recommendation = decision_policy.decide(&fused, risk_class);

    ReplayManifest {
        manifest_schema_version: REPLAY_MANIFEST_SCHEMA_VERSION,
        adapter_provider,
        adapter_runtime_version,
        fusion_policy_name: fusion_policy.name().to_string(),
        fusion_policy_version: fusion_policy.policy_version(),
        decision_policy_name: decision_policy.name().to_string(),
        decision_policy_version: decision_policy.policy_version(),
        risk_class,
        disabled_sensors,
        claim,
        evidence_pool,
        evidence_graph,
        recorded_verdict: fused.verdict,
        recorded_uncertainty: fused.uncertainty,
        recorded_action: recommendation.action,
        recorded_at: recorded_at.to_string(),
    }
}

/// Convenience accessor used by tests/CLI to identify a manifest's claim
/// without reaching into the struct directly.
impl ReplayManifest {
    pub fn claim_id(&self) -> Uuid {
        self.claim.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{EvidenceKind, EvidenceLink, EvidenceRelation};
    use fornax_verify::decision::DefaultRiskPolicy;
    use fornax_verify::fusion::BaselineFusionPolicy;

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

    fn evidence(id: Uuid) -> Evidence {
        Evidence {
            id,
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test".into(),
            source: None,
            extension: None,
        }
    }

    #[test]
    fn manifest_reads_real_policy_identity_and_computes_recorded_outcome() {
        let c = claim();
        let ev = evidence(Uuid::new_v4());
        let graph = EvidenceGraph {
            links: vec![EvidenceLink {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                claim_id: c.id,
                evidence_id: ev.id,
                relation: EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:00Z".into(),
            }],
            missing: vec![],
        };

        let manifest = build_manifest(
            c,
            vec![ev],
            graph,
            Provider::ClaudeCode,
            "2.1.238".into(),
            &BaselineFusionPolicy,
            &DefaultRiskPolicy,
            RiskClass::Balanced,
            BTreeSet::new(),
            "2026-01-02T00:00:00Z",
        );

        assert_eq!(
            manifest.manifest_schema_version,
            REPLAY_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(manifest.fusion_policy_name, "deterministic_baseline_v1");
        assert_eq!(manifest.fusion_policy_version, 1);
        assert_eq!(manifest.decision_policy_name, "default_risk_policy_v1");
        assert_eq!(manifest.decision_policy_version, 1);
        assert_eq!(manifest.recorded_verdict, Verdict::Verified);
    }

    #[test]
    fn manifest_round_trips_through_json() {
        let c = claim();
        let ev = evidence(Uuid::new_v4());
        let graph = EvidenceGraph {
            links: vec![],
            missing: vec![],
        };
        let manifest = build_manifest(
            c,
            vec![ev],
            graph,
            Provider::Codex,
            "0.1.0".into(),
            &BaselineFusionPolicy,
            &DefaultRiskPolicy,
            RiskClass::Strict,
            BTreeSet::new(),
            "2026-01-02T00:00:00Z",
        );
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: ReplayManifest = serde_json::from_str(&json).unwrap();
        // `Claim`/`Evidence` don't implement `PartialEq` (fornax-types), so
        // round-trip fidelity is checked by re-serializing and comparing
        // JSON, rather than by struct equality.
        let reparsed_json = serde_json::to_string(&parsed).unwrap();
        assert_eq!(json, reparsed_json);
        assert_eq!(parsed.fusion_policy_name, manifest.fusion_policy_name);
        assert_eq!(parsed.recorded_verdict, manifest.recorded_verdict);
    }
}
