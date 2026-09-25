//! Integrity Incident Intelligence (FORNX-389): turns a verified
//! agent-integrity failure into a reproducible regression and a durable
//! mitigation-knowledge record, instead of an isolated finding or a prose
//! postmortem.
//!
//! **Extends existing primitives; does not create a second incident
//! store** (an explicit scope constraint):
//!
//! - [`crate::schema::ClaimRef`]/[`crate::schema::EvidenceRef`] (FORNX-350)
//!   for the affected claim/evidence — reference plus fingerprint only,
//!   never a raw payload.
//! - [`crate::assurance_case::AssuranceCase`]'s `case_id` (FORNX-387) links
//!   an incident to the structured "why" behind its verdict, without
//!   re-embedding the case.
//! - [`fornax_types::audit::AuditRef`] (FORNX-116/314) references the audit
//!   trail entries that make up the discovery path — this module defines
//!   no second audit-event type.
//! - [`fornax_types::RetentionClass`] (FORNX-319/341) is reused verbatim
//!   for retention/export policy (AC6) rather than reinventing one.
//! - [`FailureCharacterization::specification_gaming_or_evasion`] mirrors
//!   [`crate::multi_agent::MultiAgentSignal::collusion_hypothesis`]'s exact
//!   `Option<Self>`-gated-construction idiom (FORNX-385): a finding cannot
//!   be silently upgraded to an intent-bearing interpretation without
//!   non-empty supporting evidence (AC7).
//!
//! **Regression fixtures are seeds, not live writes.** A confirmed
//! incident's [`RegressionFixtureSeed`] is a versioned, redaction-safe
//! record shaped after `fornax_bench::adversarial::AttackFixture`'s public
//! fields (AC3) — this crate does not depend on `fornax-bench`, and
//! `fornax-bench` does not depend on this crate (see both crates'
//! `Cargo.toml`), so this module cannot literally append to that crate's
//! static corpus at runtime. A seed carries everything a human (or a
//! follow-up ticket) needs to add it as a real `fixture(...)` entry there.
//! This module's own responsibility ends at producing a correct, complete,
//! non-leaking seed — not at writing Rust source into another crate.
//!
//! **No fabricated real-world data.** Every example this module's own
//! tests construct is a seeded, synthetic scenario — this repository has
//! no real human-adjudicated incident corpus (FORNX-343 remains
//! founder-paused for cost control), and nothing here claims otherwise.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use fornax_types::audit::AuditRef;
use fornax_types::RetentionClass;

use crate::schema::{ClaimRef, EvidenceRef};

pub const INCIDENT_SCHEMA_VERSION: u32 = 1;

/// Investigation lifecycle state. Its own vocabulary — never collapsed into
/// `SatisfactionState`/`Verdict`/`AttackOutcome`/`MultiAgentSignal`, per
/// `docs/adr/0001-architecture-invariants.md`'s never-collapse-vocabularies
/// invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationState {
    Suspected,
    Reproduced,
    RootCauseHypothesis,
    ConfirmedCause,
    Mitigated,
    RegressionPinned,
    Unresolved,
}

/// How severe an incident's real or potential impact is. A local,
/// per-incident judgment — never aggregated into a cross-incident score
/// (AC5's "without creating a global model reputation score").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// AC7: distinguishes accidental unreliability from an intent-bearing
/// interpretation. [`Self::SpecificationGamingOrEvasion`] can only be
/// constructed via [`Self::specification_gaming_or_evasion`], which refuses
/// empty evidence — a finding cannot be silently upgraded to "the agent was
/// gaming the spec" or "evading detection" from mere suspicion or
/// correlation. [`Self::UnprovenIntent`] is the honest, freely-constructible
/// alternative for exactly that case: something looks deliberate, but there
/// is not yet supporting evidence to say so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureCharacterization {
    /// The agent's failure looks like ordinary unreliability — no
    /// indication of deliberate spec-gaming, evasion, or coordination.
    AccidentalUnreliability,
    /// A deliberate, intent-bearing failure mode. Only ever constructed
    /// with non-empty `supporting_evidence` — see
    /// [`Self::specification_gaming_or_evasion`].
    SpecificationGamingOrEvasion { supporting_evidence: Vec<String> },
    /// The failure could plausibly be deliberate, but nothing yet supports
    /// that reading over ordinary unreliability. The honest default when
    /// evidence is inconclusive — never silently promoted to the variant
    /// above.
    UnprovenIntent,
}

impl FailureCharacterization {
    /// The only constructor for [`Self::SpecificationGamingOrEvasion`].
    /// Returns `None` if `supporting_evidence` is empty.
    pub fn specification_gaming_or_evasion(supporting_evidence: Vec<String>) -> Option<Self> {
        if supporting_evidence.is_empty() {
            return None;
        }
        Some(Self::SpecificationGamingOrEvasion {
            supporting_evidence,
        })
    }

    /// `true` for [`Self::SpecificationGamingOrEvasion`] only — the one
    /// variant that asserts deliberate intent.
    pub fn asserts_intent(&self) -> bool {
        matches!(self, Self::SpecificationGamingOrEvasion { .. })
    }
}

/// One hypothesis that was considered and not (yet, or ever) confirmed as
/// the root cause — kept visible rather than discarded once a different
/// hypothesis is confirmed (AC2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlternativeHypothesis {
    pub description: String,
    /// `None` while still genuinely open; `Some(reason)` once ruled out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruled_out_because: Option<String>,
}

/// How confident this investigation is in its named root cause. Its own
/// small, closed vocabulary — never a bare float, and never conflated with
/// `fornax_verify::fusion::UncertaintyBand` (a different layer's
/// uncertainty concept).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootCauseConfidence {
    Hypothesis,
    Probable,
    Confirmed,
}

/// AC2: a root-cause conclusion that preserves its supporting evidence,
/// its own confidence, and every alternative hypothesis considered along
/// the way — never collapsed down to a bare prose conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootCauseConclusion {
    pub description: String,
    pub supporting_evidence: Vec<EvidenceRef>,
    pub confidence: RootCauseConfidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alternative_hypotheses: Vec<AlternativeHypothesis>,
}

/// Exact versions a mitigation was applied and verified against (AC4).
/// Deliberately a plain, comparable struct (`PartialEq`) rather than a
/// free-text description — [`MitigationRecord::needs_recheck_against`]
/// depends on being able to detect that any one of these has moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitigationVersions {
    pub code_commit: String,
    pub contract_schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<u32>,
}

/// AC4: a recorded mitigation, tied to the exact versions it was verified
/// against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitigationRecord {
    pub description: String,
    pub applied_versions: MitigationVersions,
    pub mitigated_at: String,
}

impl MitigationRecord {
    /// `true` if `current` differs from the versions this mitigation was
    /// verified against in any field — a signal that its effectiveness
    /// claim should be re-checked, not silently assumed to still hold
    /// after a model/runtime/policy change (AC4).
    pub fn needs_recheck_against(&self, current: &MitigationVersions) -> bool {
        &self.applied_versions != current
    }
}

/// AC3: a versioned, redaction-safe seed for a regression/adversarial
/// fixture derived from a confirmed incident. Carries only already-redacted
/// references ([`EvidenceRef`]'s `payload_fingerprint`) and caller-authored
/// labels — never a raw evidence payload or raw claim text. See this
/// module's own doc comment for why this is a *seed*, not a live corpus
/// write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionFixtureSeed {
    pub incident_id: Uuid,
    /// A short, caller-authored label for the fixture — must describe the
    /// failure mechanism, never quote raw evidence/claim content. Tested:
    /// [`tests::regression_fixture_seed_never_contains_raw_evidence_payload`].
    pub description: String,
    pub reproduction_command: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub versions: MitigationVersions,
}

/// AC5: the explicit, comparable context two incidents are grouped by —
/// never a numeric similarity score, and never a per-model/per-agent
/// reputation value. Two incidents with an identical key are "the same
/// kind of thing happening again"; nothing here ranks or scores anything.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IncidentContextKey {
    /// [`fornax_types::Claim::subject`]'s coarse category — never claim
    /// text.
    pub claim_subject: String,
    /// The specific invariant/attack-class/trust-boundary this incident's
    /// failure violated (e.g. an `InvariantId` or `AttackClass` variant
    /// name) — a closed label from an existing vocabulary elsewhere in this
    /// codebase, kept as a caller-supplied string here so this module does
    /// not need a dependency on every crate that defines one.
    pub trust_boundary: String,
}

/// One integrity incident record (FORNX-389). Binds the affected claim, the
/// audit trail that discovered it, the assurance case that explains its
/// verdict, its investigation lifecycle, its (gated) failure
/// characterization, and — once confirmed and mitigated — the regression
/// fixture it produced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IncidentRecord {
    pub schema_version: u32,
    pub incident_id: Uuid,
    pub affected_claim: ClaimRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assurance_case_id: Option<Uuid>,
    /// The discovery path: which existing audit events led here. This
    /// module does not define a second audit-event type — it references
    /// [`fornax_types::audit::AuditEvent`]s by [`AuditRef`] only.
    pub discovery_path: Vec<AuditRef>,
    pub severity: IncidentSeverity,
    pub state: InvestigationState,
    pub characterization: FailureCharacterization,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_cause: Option<RootCauseConclusion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<MitigationRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regression_fixture: Option<RegressionFixtureSeed>,
    /// AC6: reused verbatim from `fornax_types` — this record's own
    /// deletion/retention/authorization behavior follows whatever policy
    /// already governs this `RetentionClass`, rather than a parallel
    /// incident-specific policy.
    pub retention_class: RetentionClass,
    pub context_key: IncidentContextKey,
    pub discovered_at: String,
}

impl IncidentRecord {
    pub fn new(
        incident_id: Uuid,
        affected_claim: ClaimRef,
        discovery_path: Vec<AuditRef>,
        severity: IncidentSeverity,
        context_key: IncidentContextKey,
        retention_class: RetentionClass,
        discovered_at: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: INCIDENT_SCHEMA_VERSION,
            incident_id,
            affected_claim,
            assurance_case_id: None,
            discovery_path,
            severity,
            state: InvestigationState::Suspected,
            characterization: FailureCharacterization::UnprovenIntent,
            root_cause: None,
            mitigation: None,
            regression_fixture: None,
            retention_class,
            context_key,
            discovered_at: discovered_at.into(),
        }
    }

    /// AC3: derive a [`RegressionFixtureSeed`] from this incident. Requires
    /// [`InvestigationState::ConfirmedCause`] or later — a merely suspected
    /// or reproduced-but-uncaused incident has nothing reliable to pin as a
    /// regression yet.
    pub fn to_regression_fixture_seed(
        &self,
        description: impl Into<String>,
        reproduction_command: impl Into<String>,
        versions: MitigationVersions,
    ) -> Option<RegressionFixtureSeed> {
        if self.state < InvestigationState::ConfirmedCause {
            return None;
        }
        let evidence_refs = self
            .root_cause
            .as_ref()
            .map(|rc| rc.supporting_evidence.clone())
            .unwrap_or_default();
        Some(RegressionFixtureSeed {
            incident_id: self.incident_id,
            description: description.into(),
            reproduction_command: reproduction_command.into(),
            evidence_refs,
            versions,
        })
    }
}

/// AC5: groups incidents by their explicit [`IncidentContextKey`] — an
/// incident with no comparable peers gets its own singleton group. Never
/// produces a score, ranking, or per-model reputation value; the caller
/// gets back exactly the grouping, nothing more.
pub fn group_by_context(incidents: &[IncidentRecord]) -> BTreeMap<IncidentContextKey, Vec<Uuid>> {
    let mut groups: BTreeMap<IncidentContextKey, Vec<Uuid>> = BTreeMap::new();
    for incident in incidents {
        groups
            .entry(incident.context_key.clone())
            .or_default()
            .push(incident.incident_id);
    }
    for ids in groups.values_mut() {
        ids.sort();
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::sensor::{CollectionMethod, TrustClass};
    use fornax_types::EvidenceKind;

    fn claim_ref() -> ClaimRef {
        ClaimRef {
            claim_id: Uuid::new_v4(),
            session_id: "session-1".to_string(),
            subject: "tests_passed".to_string(),
            claim_text_fingerprint: "fp-claim-abcd1234".to_string(),
            claimed_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn evidence_ref(fingerprint: &str) -> EvidenceRef {
        EvidenceRef {
            evidence_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            relation: fornax_types::graph::EvidenceRelation::Supports,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            trust_class: Some(TrustClass::HostObserved),
            sensor_name: Some("test-runner".to_string()),
            collection_method: Some(CollectionMethod::ProcessObservation),
            payload_fingerprint: fingerprint.to_string(),
            evidence_purged: false,
        }
    }

    fn versions(commit: &str) -> MitigationVersions {
        MitigationVersions {
            code_commit: commit.to_string(),
            contract_schema_version: 1,
            calibration_revision: None,
            policy_version: Some(1),
        }
    }

    fn seeded_audit_ref() -> AuditRef {
        AuditRef::new("fornax-core:test", "evt-seed-0001")
    }

    /// AC1: a SEEDED integrity incident (synthetic, not a real production
    /// incident) can be reconstructed end-to-end from its original evidence
    /// through mitigation and a pinned regression fixture, with every
    /// intermediate artifact still present and traceable at the end.
    #[test]
    fn a_seeded_incident_is_reconstructible_from_evidence_through_mitigation_and_regression() {
        let ev = evidence_ref("fp-exitcode-11112222");
        let mut incident = IncidentRecord::new(
            Uuid::new_v4(),
            claim_ref(),
            vec![seeded_audit_ref()],
            IncidentSeverity::High,
            IncidentContextKey {
                claim_subject: "tests_passed".to_string(),
                trust_boundary: "CapabilityVersionSpoofing".to_string(),
            },
            RetentionClass::DerivedFinding,
            "2026-01-01T00:05:00Z",
        );
        assert_eq!(incident.state, InvestigationState::Suspected);

        // Reproduced.
        incident.state = InvestigationState::Reproduced;

        // Root-cause hypothesis, with an alternative considered and later
        // ruled out (AC2).
        incident.state = InvestigationState::RootCauseHypothesis;
        incident.root_cause = Some(RootCauseConclusion {
            description: "adapter reported ProcessResult capability it did not actually have"
                .to_string(),
            supporting_evidence: vec![ev.clone()],
            confidence: RootCauseConfidence::Hypothesis,
            alternative_hypotheses: vec![AlternativeHypothesis {
                description: "stale cache serving an old capability list".to_string(),
                ruled_out_because: None,
            }],
        });

        // Confirmed cause: the alternative is ruled out, confidence raised,
        // evidence and the alternative both stay visible (AC2).
        incident.state = InvestigationState::ConfirmedCause;
        if let Some(rc) = incident.root_cause.as_mut() {
            rc.confidence = RootCauseConfidence::Confirmed;
            rc.alternative_hypotheses[0].ruled_out_because =
                Some("cache was disabled in this environment; reproduced with cache off".into());
        }
        incident.characterization = FailureCharacterization::AccidentalUnreliability;

        // Mitigated, tied to exact versions (AC4).
        incident.state = InvestigationState::Mitigated;
        incident.mitigation = Some(MitigationRecord {
            description: "assess_with_capabilities now enforces capability_prerequisites"
                .to_string(),
            applied_versions: versions("dcd84cd"),
            mitigated_at: "2026-01-02T00:00:00Z".to_string(),
        });

        // Regression-pinned: a seed is produced (AC3), never leaking raw
        // content — see the dedicated leak test below for the adversarial
        // proof; here we just confirm the happy path wires through.
        let seed = incident
            .to_regression_fixture_seed(
                "capability-spoofing regression",
                "cargo test -p fornax-verify --lib -- contract_satisfaction::tests::plain_assess_is_exploitable_by_a_spoofed_missing_capability",
                versions("dcd84cd"),
            )
            .expect("ConfirmedCause or later must produce a seed");
        incident.regression_fixture = Some(seed);
        incident.state = InvestigationState::RegressionPinned;

        // Reconstruction check: every artifact from every stage is still
        // present at the end -- nothing was overwritten or discarded.
        assert_eq!(incident.state, InvestigationState::RegressionPinned);
        assert_eq!(incident.discovery_path, vec![seeded_audit_ref()]);
        let rc = incident.root_cause.as_ref().unwrap();
        assert_eq!(rc.confidence, RootCauseConfidence::Confirmed);
        assert_eq!(rc.supporting_evidence, vec![ev]);
        assert_eq!(rc.alternative_hypotheses.len(), 1);
        assert!(rc.alternative_hypotheses[0].ruled_out_because.is_some());
        assert!(incident.mitigation.is_some());
        let seed = incident.regression_fixture.as_ref().unwrap();
        assert_eq!(seed.incident_id, incident.incident_id);
        assert_eq!(seed.versions, versions("dcd84cd"));
    }

    /// AC2: root-cause conclusions preserve supporting evidence and every
    /// alternative hypothesis, even ones already ruled out -- nothing is
    /// discarded once a conclusion firms up.
    #[test]
    fn root_cause_preserves_alternatives_even_after_confirmation() {
        let rc = RootCauseConclusion {
            description: "root cause".to_string(),
            supporting_evidence: vec![evidence_ref("fp-a")],
            confidence: RootCauseConfidence::Confirmed,
            alternative_hypotheses: vec![
                AlternativeHypothesis {
                    description: "alt 1".to_string(),
                    ruled_out_because: Some("contradicted by evidence X".to_string()),
                },
                AlternativeHypothesis {
                    description: "alt 2 (never fully excluded)".to_string(),
                    ruled_out_because: None,
                },
            ],
        };
        assert_eq!(rc.alternative_hypotheses.len(), 2);
        assert!(rc.alternative_hypotheses[1].ruled_out_because.is_none());
    }

    /// AC3: this module never accepts a raw evidence payload or raw claim
    /// text anywhere on its input surface -- [`EvidenceRef`]/[`ClaimRef`]
    /// (FORNX-350) are already fingerprint-only by their own type, and
    /// [`IncidentRecord::to_regression_fixture_seed`] only ever forwards
    /// those references plus the caller's own `description`/
    /// `reproduction_command` strings verbatim. Proof: build an incident
    /// whose evidence carries a secret-*shaped* fingerprint value (proving
    /// even a fingerprint field, if misused upstream, round-trips
    /// unchanged rather than being silently duplicated into other fields
    /// this module adds), and confirm the seed's JSON contains that value
    /// exactly once -- never duplicated into `description`,
    /// `reproduction_command`, or anywhere else this module's own code
    /// writes to.
    #[test]
    fn seed_construction_forwards_references_verbatim_and_never_duplicates_them() {
        let suspicious_fingerprint = "fp-should-not-be-copied-elsewhere-9f8e7d6c";
        let ev = evidence_ref(suspicious_fingerprint);
        let mut incident = IncidentRecord::new(
            Uuid::new_v4(),
            claim_ref(),
            vec![],
            IncidentSeverity::Critical,
            IncidentContextKey {
                claim_subject: "tests_passed".to_string(),
                trust_boundary: "ForgedProvenance".to_string(),
            },
            RetentionClass::SanitizedReplayFixture,
            "2026-01-01T00:00:00Z",
        );
        incident.state = InvestigationState::ConfirmedCause;
        incident.root_cause = Some(RootCauseConclusion {
            description: "root cause, no secret text here".to_string(),
            supporting_evidence: vec![ev],
            confidence: RootCauseConfidence::Confirmed,
            alternative_hypotheses: vec![],
        });

        let seed = incident
            .to_regression_fixture_seed(
                "forged provenance regression",
                "cargo test -p fornax-types --lib -- provenance_guard",
                versions("abc123"),
            )
            .unwrap();
        let json = serde_json::to_string(&seed).unwrap();
        assert_eq!(
            json.matches(suspicious_fingerprint).count(),
            1,
            "the fingerprint must appear exactly once (inside evidence_refs), never \
             duplicated into description/reproduction_command or anywhere else: {json}"
        );
        assert!(!seed.description.contains(suspicious_fingerprint));
        assert!(!seed.reproduction_command.contains(suspicious_fingerprint));
    }

    /// AC7: a finding cannot be silently upgraded to a
    /// specification-gaming/evasion characterization from empty evidence --
    /// the constructor refuses, mirroring
    /// `MultiAgentSignal::collusion_hypothesis`'s exact gating.
    #[test]
    fn specification_gaming_cannot_be_constructed_from_empty_evidence() {
        assert!(FailureCharacterization::specification_gaming_or_evasion(vec![]).is_none());
        let real = FailureCharacterization::specification_gaming_or_evasion(vec![
            "agent's own transcript shows it read the test file, saw the assertion, and \
             hardcoded the expected value rather than fixing the implementation"
                .to_string(),
        ]);
        assert!(real.is_some());
        assert!(real.unwrap().asserts_intent());
        assert!(!FailureCharacterization::AccidentalUnreliability.asserts_intent());
        assert!(!FailureCharacterization::UnprovenIntent.asserts_intent());
    }

    /// AC4: a mitigation recorded against one set of versions correctly
    /// flags itself for recheck once the running code/policy has moved on,
    /// and does not falsely flag when nothing changed.
    #[test]
    fn mitigation_flags_recheck_only_when_versions_actually_moved() {
        let mitigation = MitigationRecord {
            description: "fix applied".to_string(),
            applied_versions: versions("commit-a"),
            mitigated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        assert!(!mitigation.needs_recheck_against(&versions("commit-a")));
        assert!(mitigation.needs_recheck_against(&versions("commit-b")));
    }

    /// AC1 negative control: a merely `Suspected` or `Reproduced` incident
    /// (root cause not yet confirmed) cannot produce a regression fixture
    /// seed -- there is nothing reliable yet to pin.
    #[test]
    fn regression_fixture_seed_requires_confirmed_cause_or_later() {
        let incident = IncidentRecord::new(
            Uuid::new_v4(),
            claim_ref(),
            vec![],
            IncidentSeverity::Low,
            IncidentContextKey {
                claim_subject: "x".to_string(),
                trust_boundary: "y".to_string(),
            },
            RetentionClass::DerivedFinding,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(incident.state, InvestigationState::Suspected);
        assert!(incident
            .to_regression_fixture_seed("desc", "cmd", versions("c"))
            .is_none());
    }

    /// AC5: incidents group by their explicit context key alone -- same
    /// key groups together, different keys stay separate, and nothing
    /// resembling a score is ever produced (the return type itself has no
    /// numeric field to hold one).
    #[test]
    fn incidents_group_by_explicit_context_key_only() {
        let make = |subject: &str, boundary: &str| {
            IncidentRecord::new(
                Uuid::new_v4(),
                claim_ref(),
                vec![],
                IncidentSeverity::Medium,
                IncidentContextKey {
                    claim_subject: subject.to_string(),
                    trust_boundary: boundary.to_string(),
                },
                RetentionClass::DerivedFinding,
                "2026-01-01T00:00:00Z",
            )
        };
        let a = make("tests_passed", "CapabilityVersionSpoofing");
        let b = make("tests_passed", "CapabilityVersionSpoofing");
        let c = make("build_succeeded", "Toctou");
        let groups = group_by_context(&[a.clone(), b.clone(), c.clone()]);
        assert_eq!(groups.len(), 2);
        let same_group = groups
            .get(&IncidentContextKey {
                claim_subject: "tests_passed".to_string(),
                trust_boundary: "CapabilityVersionSpoofing".to_string(),
            })
            .unwrap();
        assert_eq!(same_group.len(), 2);
        assert!(same_group.contains(&a.incident_id));
        assert!(same_group.contains(&b.incident_id));
    }

    /// AC6: `retention_class` is the real `fornax_types::RetentionClass`
    /// enum, not a parallel incident-specific policy type -- this is a
    /// compile-time proof by construction (the field's type), reinforced
    /// here by round-tripping through serde with the exact variant names
    /// that type's own callers already use.
    #[test]
    fn retention_class_reuses_the_existing_fornax_types_vocabulary() {
        let incident = IncidentRecord::new(
            Uuid::new_v4(),
            claim_ref(),
            vec![],
            IncidentSeverity::Low,
            IncidentContextKey {
                claim_subject: "x".to_string(),
                trust_boundary: "y".to_string(),
            },
            RetentionClass::SanitizedCandidate,
            "2026-01-01T00:00:00Z",
        );
        let json = serde_json::to_string(&incident).unwrap();
        let back: IncidentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.retention_class, RetentionClass::SanitizedCandidate);
    }
}
