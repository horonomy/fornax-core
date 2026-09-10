//! Replay engine (FORNX-98 AC 1/2/3/4): validates a frozen
//! [`crate::manifest::ReplayManifest`] and, if valid, re-runs the real
//! `fornax_verify` fusion/decision pipeline over its frozen input, producing
//! a [`ReplayComparison`] against the manifest's recorded outcome.
//!
//! # No external side effects (AC 2)
//!
//! [`replay`] performs no I/O of its own — it takes an already-in-memory
//! [`crate::manifest::ReplayManifest`] and returns a value. It never opens a
//! socket, spawns a subprocess, or calls an adapter/provider; the frozen
//! `Claim`/evidence/graph on the manifest are the only input `fuse`/`decide`
//! ever see. This crate's own `Cargo.toml` carries no networking or process
//! dependency, and `tests/no_side_effects.rs` asserts by source inspection
//! that no such call was ever introduced into this crate's production code.

use fornax_types::Verdict;
use fornax_verify::decision::{DecisionPolicy, DefaultRiskPolicy, RecommendationAction};
use fornax_verify::fusion::{BaselineFusionPolicy, FusionInput, FusionPolicy, UncertaintyBand};
use thiserror::Error;

use crate::manifest::{ReplayManifest, SUPPORTED_MANIFEST_SCHEMA_VERSIONS};

/// Explicit, typed failure for an invalid or incomplete manifest (FORNX-98
/// AC 4) — [`replay`] never panics and never silently produces an empty or
/// default result for a malformed manifest. Follows this crate family's
/// established `thiserror`-based error idiom (see `fornax_vcs::VcsError`,
/// `fornax_verify::judge::JudgeError`).
#[derive(Debug, Error, PartialEq)]
pub enum ReplayError {
    #[error("unsupported manifest_schema_version {got}; this binary supports {supported:?}")]
    UnsupportedManifestSchemaVersion { got: u32, supported: &'static [u32] },

    #[error("manifest is missing required field: {field}")]
    MissingField { field: &'static str },

    #[error(
        "evidence_graph.links[{link_index}] references evidence_id {evidence_id}, \
         which is not present in evidence_pool"
    )]
    DanglingEvidenceLink {
        link_index: usize,
        evidence_id: uuid::Uuid,
    },
}

/// Structural validation only — no policy execution happens here. Checked
/// before [`replay`] touches the fusion/decision pipeline at all, so a
/// malformed manifest fails fast with a specific reason (FORNX-98 AC 4)
/// rather than propagating into `fuse`/`decide` and failing (or worse,
/// succeeding vacuously) somewhere less legible.
pub fn validate_manifest(manifest: &ReplayManifest) -> Result<(), ReplayError> {
    if !SUPPORTED_MANIFEST_SCHEMA_VERSIONS.contains(&manifest.manifest_schema_version) {
        return Err(ReplayError::UnsupportedManifestSchemaVersion {
            got: manifest.manifest_schema_version,
            supported: SUPPORTED_MANIFEST_SCHEMA_VERSIONS,
        });
    }
    if manifest.claim.text.trim().is_empty() {
        return Err(ReplayError::MissingField {
            field: "claim.text",
        });
    }
    if manifest.claim.session_id.trim().is_empty() {
        return Err(ReplayError::MissingField {
            field: "claim.session_id",
        });
    }
    if manifest.fusion_policy_name.trim().is_empty() {
        return Err(ReplayError::MissingField {
            field: "fusion_policy_name",
        });
    }
    if manifest.decision_policy_name.trim().is_empty() {
        return Err(ReplayError::MissingField {
            field: "decision_policy_name",
        });
    }
    if manifest.recorded_at.trim().is_empty() {
        return Err(ReplayError::MissingField {
            field: "recorded_at",
        });
    }
    for (link_index, link) in manifest.evidence_graph.links.iter().enumerate() {
        if !manifest
            .evidence_pool
            .iter()
            .any(|e| e.id == link.evidence_id)
        {
            return Err(ReplayError::DanglingEvidenceLink {
                link_index,
                evidence_id: link.evidence_id,
            });
        }
    }
    Ok(())
}

/// Whether a recorded identity (name + version) drifted from what the live
/// pipeline actually is, right now. `None` means no drift; `Some` carries
/// `(recorded, live)` for the field that differs — this is what makes a
/// version difference "visible in comparison output" rather than silently
/// masked by recomputing under whichever policy this binary happens to ship
/// today (FORNX-98 AC 3).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentityDrift {
    pub recorded: String,
    pub live: String,
}

/// Result of replaying one [`ReplayManifest`]: the live-recomputed outcome
/// alongside the manifest's recorded one, whether they agree, and any
/// policy-identity drift between "what produced the recorded result" and
/// "what this binary computes today".
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReplayComparison {
    pub live_verdict: Verdict,
    pub live_uncertainty: UncertaintyBand,
    pub live_action: RecommendationAction,

    pub recorded_verdict: Verdict,
    pub recorded_uncertainty: UncertaintyBand,
    pub recorded_action: RecommendationAction,

    pub verdict_matches: bool,
    pub uncertainty_matches: bool,
    pub action_matches: bool,

    /// `Some` when the manifest's recorded fusion policy name/version
    /// differs from `BaselineFusionPolicy`'s current identity (name and/or
    /// version, joined into one comparable string) — the live outcome above
    /// was still computed with today's policy either way, so a drift here
    /// explains *why* the outcome might legitimately differ, rather than
    /// leaving that unexplained.
    pub fusion_policy_drift: Option<IdentityDrift>,
    pub decision_policy_drift: Option<IdentityDrift>,
}

fn policy_identity(name: &str, version: u32) -> String {
    format!("{name} v{version}")
}

/// Validates `manifest` ([`validate_manifest`]) and, if valid, re-runs the
/// real `BaselineFusionPolicy` + `DefaultRiskPolicy` pipeline over its frozen
/// `claim`/`evidence_graph`/`evidence_pool`, pinned to `manifest.recorded_at`
/// so two replays of the same manifest are byte-identical (FORNX-98 AC 1).
/// Performs no I/O, no network call, and no subprocess spawn (FORNX-98 AC 2)
/// — see this module's docs.
///
/// This binary currently ships exactly one `FusionPolicy`/`DecisionPolicy`
/// implementation each (`BaselineFusionPolicy`/`DefaultRiskPolicy`), so
/// replay always recomputes under those — a manifest recorded under a
/// different name/version is still replayed (there is nothing else to
/// replay it with), but the difference is surfaced explicitly via
/// [`ReplayComparison::fusion_policy_drift`]/`decision_policy_drift`
/// (FORNX-98 AC 3) rather than silently treated as a match.
pub fn replay(manifest: &ReplayManifest) -> Result<ReplayComparison, ReplayError> {
    validate_manifest(manifest)?;

    let input = FusionInput {
        claim: &manifest.claim,
        graph: &manifest.evidence_graph,
        evidence: &manifest.evidence_pool,
    };
    let fusion_policy = BaselineFusionPolicy;
    let decision_policy = DefaultRiskPolicy;

    let fused = fusion_policy.fuse(&input, &manifest.recorded_at);
    let recommendation = decision_policy.decide(&fused, manifest.risk_class);

    let live_fusion_identity =
        policy_identity(fusion_policy.name(), fusion_policy.policy_version());
    let recorded_fusion_identity =
        policy_identity(&manifest.fusion_policy_name, manifest.fusion_policy_version);
    let fusion_policy_drift =
        (live_fusion_identity != recorded_fusion_identity).then_some(IdentityDrift {
            recorded: recorded_fusion_identity,
            live: live_fusion_identity,
        });

    let live_decision_identity =
        policy_identity(decision_policy.name(), decision_policy.policy_version());
    let recorded_decision_identity = policy_identity(
        &manifest.decision_policy_name,
        manifest.decision_policy_version,
    );
    let decision_policy_drift =
        (live_decision_identity != recorded_decision_identity).then_some(IdentityDrift {
            recorded: recorded_decision_identity,
            live: live_decision_identity,
        });

    Ok(ReplayComparison {
        live_verdict: fused.verdict,
        live_uncertainty: fused.uncertainty,
        live_action: recommendation.action,
        recorded_verdict: manifest.recorded_verdict,
        recorded_uncertainty: manifest.recorded_uncertainty,
        recorded_action: manifest.recorded_action,
        verdict_matches: fused.verdict == manifest.recorded_verdict,
        uncertainty_matches: fused.uncertainty == manifest.recorded_uncertainty,
        action_matches: recommendation.action == manifest.recorded_action,
        fusion_policy_drift,
        decision_policy_drift,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::build_manifest;
    use fornax_types::{
        Claim, Evidence, EvidenceGraph, EvidenceKind, EvidenceLink, EvidenceRelation, Provider,
    };
    use fornax_verify::decision::RiskClass;
    use std::collections::BTreeSet;
    use uuid::Uuid;

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
            evidence_purged: false,
        }
    }

    fn base_manifest() -> ReplayManifest {
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
        build_manifest(
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
        )
    }

    // ---- AC 1: same frozen manifest replayed twice is byte-identical ----

    #[test]
    fn replaying_the_same_manifest_twice_is_identical() {
        let manifest = base_manifest();
        let first = replay(&manifest).unwrap();
        let second = replay(&manifest).unwrap();
        assert_eq!(first, second);
        assert!(first.verdict_matches);
        assert!(first.uncertainty_matches);
        assert!(first.action_matches);
        assert!(first.fusion_policy_drift.is_none());
        assert!(first.decision_policy_drift.is_none());
    }

    // ---- AC 3: a recorded version difference is visible in comparison ----

    #[test]
    fn a_bumped_recorded_fusion_policy_version_surfaces_as_drift() {
        let mut manifest = base_manifest();
        manifest.fusion_policy_version = 99;
        let comparison = replay(&manifest).unwrap();
        let drift = comparison
            .fusion_policy_drift
            .expect("expected fusion policy drift to be reported");
        assert_eq!(drift.recorded, "deterministic_baseline_v1 v99");
        assert_eq!(drift.live, "deterministic_baseline_v1 v1");
        // the outcome fields are still compared -- drift is additive
        // information, not a replacement for the verdict comparison.
        assert!(comparison.verdict_matches);
    }

    #[test]
    fn a_renamed_recorded_decision_policy_surfaces_as_drift() {
        let mut manifest = base_manifest();
        manifest.decision_policy_name = "some_future_policy".to_string();
        let comparison = replay(&manifest).unwrap();
        let drift = comparison
            .decision_policy_drift
            .expect("expected decision policy drift to be reported");
        assert_eq!(drift.recorded, "some_future_policy v1");
        assert_eq!(drift.live, "default_risk_policy_v1 v1");
    }

    #[test]
    fn a_disagreeing_recorded_verdict_is_flagged_not_silently_matched() {
        let mut manifest = base_manifest();
        manifest.recorded_verdict = Verdict::Contradicted;
        let comparison = replay(&manifest).unwrap();
        assert!(!comparison.verdict_matches);
        assert_eq!(comparison.recorded_verdict, Verdict::Contradicted);
        assert_eq!(comparison.live_verdict, Verdict::Verified);
    }

    // ---- AC 4: invalid/incomplete manifests fail explicitly ----

    #[test]
    fn unsupported_schema_version_fails_explicitly() {
        let mut manifest = base_manifest();
        manifest.manifest_schema_version = 999;
        let err = replay(&manifest).unwrap_err();
        assert_eq!(
            err,
            ReplayError::UnsupportedManifestSchemaVersion {
                got: 999,
                supported: SUPPORTED_MANIFEST_SCHEMA_VERSIONS,
            }
        );
    }

    #[test]
    fn empty_claim_text_fails_explicitly() {
        let mut manifest = base_manifest();
        manifest.claim.text = "".to_string();
        let err = replay(&manifest).unwrap_err();
        assert_eq!(
            err,
            ReplayError::MissingField {
                field: "claim.text"
            }
        );
    }

    #[test]
    fn dangling_evidence_link_fails_explicitly_not_silently() {
        let mut manifest = base_manifest();
        manifest.evidence_pool.clear();
        let err = replay(&manifest).unwrap_err();
        match err {
            ReplayError::DanglingEvidenceLink { link_index, .. } => assert_eq!(link_index, 0),
            other => panic!("expected DanglingEvidenceLink, got {other:?}"),
        }
    }

    #[test]
    fn validate_manifest_never_panics_on_any_field_wiped() {
        // Defensive sweep: clearing any single required string field must
        // produce Err, never panic.
        for wipe in [
            "claim.text",
            "claim.session_id",
            "fusion_policy_name",
            "decision_policy_name",
            "recorded_at",
        ] {
            let mut manifest = base_manifest();
            match wipe {
                "claim.text" => manifest.claim.text.clear(),
                "claim.session_id" => manifest.claim.session_id.clear(),
                "fusion_policy_name" => manifest.fusion_policy_name.clear(),
                "decision_policy_name" => manifest.decision_policy_name.clear(),
                "recorded_at" => manifest.recorded_at.clear(),
                _ => unreachable!(),
            }
            assert!(validate_manifest(&manifest).is_err(), "wipe={wipe}");
        }
    }
}
