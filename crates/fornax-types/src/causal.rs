//! Causal provenance for evidence: distinguishing observational, replayed,
//! and interventional evidence in finding semantics (FORNX-102, epic
//! FORNX-20 / discovery thesis HVDL-15).
//!
//! [`crate::EvidenceLink`] (FORNX-89) records *that* a piece of evidence
//! relates to a claim. [`crate::CompletedExperiment`] (FORNX-99) records
//! *that* a deliberate intervention was run and compared against a
//! baseline. Neither, on its own, stops a caller from treating ordinary
//! passively-observed evidence as if it had been produced by an
//! intervention — nothing today marks the difference on the evidence side.
//! This module adds that missing dimension, additively:
//!
//! - [`EvidenceProvenanceClass`]: a closed, orthogonal classification of how
//!   one piece of evidence was obtained: [`EvidenceProvenanceClass::Observational`]
//!   (passively observed, the default/implicit class every pre-existing
//!   [`crate::EvidenceLink`] belongs to), [`EvidenceProvenanceClass::Replayed`]
//!   (re-derived from a frozen replay manifest — see that variant's own doc
//!   comment for why `manifest_id` is forward-looking rather than a
//!   reference to an existing FORNX-98 type — still passive, never causal,
//!   merely re-run), and [`EvidenceProvenanceClass::Interventional`]
//!   (produced by a [`crate::CompletedExperiment`]'s intervention phase).
//!   This is a new, orthogonal dimension layered on top of
//!   [`crate::EvidenceRelation`]'s existing three-state vocabulary and
//!   [`crate::Verdict`]'s five-state vocabulary — it never replaces or
//!   collapses either.
//! - [`InterventionalProvenance`]: the payload naming *which* experiment
//!   produced a causal evidence record, mirroring
//!   [`crate::CompletedExperiment::new`]'s precedent — its fields are
//!   private, [`InterventionalProvenance::new`] is the only public
//!   constructor *and* every deserialize path is routed through it too (see
//!   that type's own doc comment for the `try_from` mechanics), so an
//!   `Interventional`-tagged record cannot exist — via Rust construction or
//!   via JSON — without a real experiment id and at least one baseline and
//!   one intervention evidence id (AC1/AC2: "every experiment-derived
//!   finding states what was intervened on and what was observed", "passive
//!   evidence cannot be mislabeled as causal evidence"). This is a
//!   structural guarantee, not a bolt-on flag a caller could set
//!   independently of the experiment reference.
//! - [`CausalEvidenceLink`]: an ordinary [`crate::EvidenceLink`] paired with
//!   its [`EvidenceProvenanceClass`] — composition, not a competing
//!   "finding" concept alongside [`crate::EvidenceLink`]/
//!   `fornax_verify::FusedFinding`.
//! - [`CausalExperimentEvidence`] / [`causal_evidence_from_experiment_result`]:
//!   the mapping from one [`crate::ExperimentResult`] to evidence-graph-shaped
//!   causal data. Mirrors [`crate::ExperimentOutcome`]'s own shape exactly —
//!   only [`CausalExperimentEvidence::Completed`] carries evidence links and
//!   a relation; `Inconclusive`/`Blocked`/`Unsupported`/`Failed` each carry
//!   only a `reason: String`, with no field a caller could default into
//!   looking like [`crate::EvidenceRelation::Supports`]/`Contradicts` (AC3).
//!   [`CausalExperimentEvidence::hypothesis_relation`] is the same
//!   `None`-for-every-non-`Completed`-variant guarantee
//!   [`crate::ExperimentOutcome::hypothesis_relation`] already makes, kept
//!   consistent at this layer rather than silently dropped by the
//!   conversion.
//!
//! # No new confidence/strength score
//!
//! This module adds no numeric confidence field and does not treat
//! intervention count as automatic truth — an [`EvidenceProvenanceClass::Interventional`]
//! record is exactly one more typed, inspectable [`crate::EvidenceLink`];
//! how many of them exist, and how they get weighed into a verdict, stays
//! entirely `fornax_verify::fusion`'s job via the existing
//! [`crate::EvidenceRelation`]/`UncertaintyBand` machinery. Tagging evidence
//! with its provenance class does not by itself change how fusion counts or
//! weighs it.
//!
//! # Traceability (AC5)
//!
//! [`InterventionalProvenance`] carries `baseline_evidence_ids` and
//! `intervention_evidence_ids` (accessible via
//! [`InterventionalProvenance::baseline_evidence_ids`] /
//! [`InterventionalProvenance::intervention_evidence_ids`]) directly on the
//! provenance record attached to every interventional
//! [`CausalEvidenceLink`], so a caller reading one link already has both
//! evidence sides in hand — no separate join back to the originating
//! [`crate::CompletedExperiment`] is required to trace a causal finding back
//! to its baseline and intervention evidence. This satisfies AC5 at the type
//! level: the data an Evidence Explorer needs is structurally present.
//! `fornax-daemon`'s `api_evidence_graph` handler serializes
//! [`crate::EvidenceGraph::links`] (plain [`crate::EvidenceLink`]s) verbatim
//! today; that JSON shape is additively extensible to carry a
//! [`CausalEvidenceLink`]-shaped `{link, provenance}` payload, but no
//! `fornax-daemon`/`fornax-store` surface emits [`CausalEvidenceLink`] yet —
//! wiring it into the live graph/API is a real follow-up, out of this
//! ticket's core-typing scope.
//!
//! # Migration compatibility (AC4)
//!
//! Nothing in this module changes [`crate::EvidenceLink`]'s own shape or the
//! `claim_evidence_links` schema (`fornax-store/migrations/0006_evidence_graph.sql`).
//! [`CausalEvidenceLink`]/[`CausalExperimentEvidence`] are new, additive
//! types computed on top of existing [`crate::EvidenceLink`]/
//! [`crate::ExperimentResult`] data — a pre-existing v0.3 [`crate::EvidenceLink`]
//! row, with no causal provenance recorded at all, keeps reading exactly as
//! it always has; it simply has no [`CausalEvidenceLink`] wrapper computed
//! for it, which is the correct, honest state for evidence nothing ever
//! classified as interventional.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::experiment::{ExperimentOutcome, ExperimentResult};
use crate::graph::{EvidenceLink, EvidenceRelation};

/// Fixed namespace for [`causal_evidence_from_experiment_result`]'s
/// deterministic link id derivation — mirrors
/// `fornax_verify::fusion::PROJECTION_NAMESPACE`'s precedent for the same
/// reason: keeps the mapping a pure function of its inputs (the same
/// `ExperimentResult`, mapped twice, produces byte-identical
/// [`CausalEvidenceLink`] ids), never a fresh random id per call.
const CAUSAL_LINK_NAMESPACE: Uuid = Uuid::from_bytes([
    0x2b, 0x6f, 0x84, 0x1a, 0x9d, 0x33, 0x4c, 0x8e, 0xb2, 0x71, 0x0a, 0x5e, 0x4d, 0x9c, 0x63, 0x1f,
]);

fn causal_link_id(experiment_id: Uuid, experiment_version: u32, tag: &str) -> Uuid {
    Uuid::new_v5(
        &CAUSAL_LINK_NAMESPACE,
        format!("{experiment_id}:{experiment_version}:{tag}").as_bytes(),
    )
}

/// The experiment identity and evidence-side references an
/// [`EvidenceProvenanceClass::Interventional`] record must carry (AC1/AC2).
/// Fields are private; [`Self::new`] is the only public constructor, so a
/// caller cannot construct an interventional-tagged provenance record
/// without naming a real experiment id, version, and at least one baseline
/// and one intervention evidence id — mirroring
/// [`crate::CompletedExperiment::new`]'s precedent exactly. This guarantee
/// holds on the deserialize path too: `#[serde(try_from = ...)]` routes
/// every wire payload through [`Self::new`] via [`InterventionalProvenanceWire`],
/// exactly as [`crate::ExperimentSpec`]/`ExperimentSpecWire` already do — a
/// JSON payload naming empty evidence-id lists is rejected, not silently
/// accepted because the fields happen to be private in Rust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "InterventionalProvenanceWire")]
pub struct InterventionalProvenance {
    experiment_id: Uuid,
    experiment_version: u32,
    baseline_evidence_ids: Vec<Uuid>,
    intervention_evidence_ids: Vec<Uuid>,
}

/// Wire shape accepted on deserialization for [`InterventionalProvenance`] —
/// structurally identical, but plain `Deserialize` derive with no validation,
/// so [`TryFrom`] can route every field through [`InterventionalProvenance::new`]
/// before the domain type is constructed. See [`crate::experiment::ExperimentSpecWire`]
/// for the precedent this mirrors.
#[derive(Debug, Deserialize)]
struct InterventionalProvenanceWire {
    experiment_id: Uuid,
    experiment_version: u32,
    baseline_evidence_ids: Vec<Uuid>,
    intervention_evidence_ids: Vec<Uuid>,
}

impl TryFrom<InterventionalProvenanceWire> for InterventionalProvenance {
    type Error = String;

    fn try_from(w: InterventionalProvenanceWire) -> Result<Self, Self::Error> {
        InterventionalProvenance::new(
            w.experiment_id,
            w.experiment_version,
            w.baseline_evidence_ids,
            w.intervention_evidence_ids,
        )
    }
}

impl InterventionalProvenance {
    /// The only way to construct an [`InterventionalProvenance`]. Returns
    /// `Err` if either evidence id list is empty, rather than silently
    /// accepting a causal record with nothing to point back to (AC1: "every
    /// experiment-derived finding states what was intervened on and what
    /// was observed").
    pub fn new(
        experiment_id: Uuid,
        experiment_version: u32,
        baseline_evidence_ids: Vec<Uuid>,
        intervention_evidence_ids: Vec<Uuid>,
    ) -> Result<Self, String> {
        if baseline_evidence_ids.is_empty() {
            return Err(
                "InterventionalProvenance requires at least one baseline evidence id".to_string(),
            );
        }
        if intervention_evidence_ids.is_empty() {
            return Err(
                "InterventionalProvenance requires at least one intervention evidence id"
                    .to_string(),
            );
        }
        Ok(Self {
            experiment_id,
            experiment_version,
            baseline_evidence_ids,
            intervention_evidence_ids,
        })
    }

    pub fn experiment_id(&self) -> Uuid {
        self.experiment_id
    }

    pub fn experiment_version(&self) -> u32 {
        self.experiment_version
    }

    /// [`crate::Evidence`] ids establishing the pre-intervention state (AC5
    /// traceability). Never empty — see [`Self::new`].
    pub fn baseline_evidence_ids(&self) -> &[Uuid] {
        &self.baseline_evidence_ids
    }

    /// [`crate::Evidence`] ids observed as a result of the intervention (AC5
    /// traceability). Never empty — see [`Self::new`].
    pub fn intervention_evidence_ids(&self) -> &[Uuid] {
        &self.intervention_evidence_ids
    }
}

/// Closed, orthogonal classification of how one piece of evidence backing an
/// [`EvidenceLink`] was obtained (FORNX-102). See the module docs for why
/// this never replaces [`EvidenceRelation`] or [`crate::Verdict`] — it is a
/// new dimension layered on top of both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceProvenanceClass {
    /// Passively observed, without any deliberate intervention. The
    /// implicit class of every [`EvidenceLink`] that predates this module —
    /// no migration/backfill is required to keep reading it that way (AC4).
    Observational,
    /// Re-derived from a frozen replay manifest (FORNX-98's replay engine,
    /// which has not yet defined a manifest-id type as of this ticket —
    /// `manifest_id` is a forward-looking, caller-supplied identifier, not a
    /// reference to an existing `fornax_types` type). Still passive
    /// evidence, never causal — replaying a recorded run is not an
    /// intervention on it.
    Replayed { manifest_id: Uuid },
    /// Produced by a [`crate::CompletedExperiment`]'s intervention phase.
    /// Cannot be constructed without a real experiment reference — see
    /// [`InterventionalProvenance::new`] (AC2: "passive evidence cannot be
    /// mislabeled as causal evidence").
    Interventional(InterventionalProvenance),
}

impl EvidenceProvenanceClass {
    /// `true` for [`Self::Interventional`] only. Convenience for callers
    /// that want to filter a graph down to causally-derived evidence
    /// without matching on the enum directly.
    pub fn is_interventional(&self) -> bool {
        matches!(self, EvidenceProvenanceClass::Interventional(_))
    }
}

/// An [`EvidenceLink`] paired with its [`EvidenceProvenanceClass`]
/// (FORNX-102). Composition, not a new competing "finding"/"evidence"
/// concept — everything about the underlying edge (claim, evidence,
/// relation, when it was linked) still lives on `link` exactly as
/// [`crate::graph`] already defines it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalEvidenceLink {
    pub link: EvidenceLink,
    pub provenance: EvidenceProvenanceClass,
}

/// The result of mapping one [`ExperimentResult`] to evidence-graph-shaped
/// causal data (FORNX-102). Deliberately mirrors [`ExperimentOutcome`]'s own
/// shape: only [`Self::Completed`] carries evidence links and a relation
/// ([`Self::hypothesis_relation`] returns `None` for every other variant,
/// both in Rust and on the wire — see the module tests). The other four
/// variants each carry only a `reason: String`, copied verbatim from the
/// source [`ExperimentOutcome`] — there is no field on any of them a caller
/// could read as a support/contradiction result (AC3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalExperimentEvidence {
    /// The experiment completed and produced a real comparison. `relation`
    /// is copied verbatim from the source [`crate::CompletedExperiment::hypothesis_relation`]
    /// — this mapping never invents or defaults a relation.
    Completed {
        relation: EvidenceRelation,
        /// Pre-intervention evidence, tagged [`EvidenceProvenanceClass::Observational`]
        /// — the baseline state itself was not produced by the
        /// intervention, only compared against.
        baseline_links: Vec<CausalEvidenceLink>,
        /// Post-intervention evidence, tagged
        /// [`EvidenceProvenanceClass::Interventional`] — this is the
        /// evidence the deliberate intervention actually produced (AC1).
        intervention_links: Vec<CausalEvidenceLink>,
    },
    /// Mirrors [`ExperimentOutcome::Inconclusive`]. Never conflated with
    /// `Completed` carrying a `Neutral` relation.
    Inconclusive { reason: String },
    /// Mirrors [`ExperimentOutcome::Blocked`].
    Blocked { reason: String },
    /// Mirrors [`ExperimentOutcome::Unsupported`].
    Unsupported { reason: String },
    /// Mirrors [`ExperimentOutcome::Failed`].
    Failed { reason: String },
}

impl CausalExperimentEvidence {
    /// The comparison this causal evidence carries, if any. `None` for
    /// every variant except [`Self::Completed`] — the AC3 guarantee as a
    /// callable function, matching
    /// [`ExperimentOutcome::hypothesis_relation`]'s own shape so a caller
    /// cannot get a relation out of `Blocked`/`Failed`/`Unsupported`/
    /// `Inconclusive` no matter how it is pattern-matched.
    pub fn hypothesis_relation(&self) -> Option<EvidenceRelation> {
        match self {
            CausalExperimentEvidence::Completed { relation, .. } => Some(*relation),
            CausalExperimentEvidence::Inconclusive { .. }
            | CausalExperimentEvidence::Blocked { .. }
            | CausalExperimentEvidence::Unsupported { .. }
            | CausalExperimentEvidence::Failed { .. } => None,
        }
    }
}

/// Map one [`ExperimentResult`] to evidence-graph-shaped causal data
/// (FORNX-102). Pure and clock-free — `result.computed_at` is reused
/// verbatim as every produced [`EvidenceLink::linked_at`], never
/// `Utc::now()` — so the same result, mapped twice, produces byte-identical
/// output (link ids are derived deterministically via
/// [`causal_link_id`]/`Uuid::new_v5`, never `Uuid::new_v4`).
///
/// Only [`ExperimentOutcome::Completed`] produces
/// [`CausalExperimentEvidence::Completed`] with real links; every other
/// [`ExperimentOutcome`] variant maps straight to its
/// [`CausalExperimentEvidence`] counterpart carrying only `reason` — this
/// function never defaults a missing/non-completed outcome to a
/// support/contradiction result (AC3), the same guarantee
/// [`ExperimentOutcome::hypothesis_relation`] already makes about the
/// experiment layer itself.
///
/// Returns `Err` rather than panicking if `completed`'s evidence-id lists
/// are empty. `CompletedExperiment::new` normally prevents this, but its
/// fields are public (so a struct literal or a deserialized payload can
/// still construct a `CompletedExperiment` with empty lists bypassing that
/// constructor) — this function must never launder such a malformed
/// `Completed` outcome into a different, non-`Completed`
/// [`CausalExperimentEvidence`] variant, which would misrepresent what
/// actually happened; it surfaces the construction failure instead.
pub fn causal_evidence_from_experiment_result(
    result: &ExperimentResult,
    session_id: &str,
) -> Result<CausalExperimentEvidence, String> {
    match &result.outcome {
        ExperimentOutcome::Completed(completed) => {
            let provenance = InterventionalProvenance::new(
                result.experiment_id,
                result.experiment_version,
                completed.baseline_evidence_ids.clone(),
                completed.intervention_evidence_ids.clone(),
            )?;

            let baseline_links = completed
                .baseline_evidence_ids
                .iter()
                .map(|evidence_id| CausalEvidenceLink {
                    link: EvidenceLink {
                        id: causal_link_id(
                            result.experiment_id,
                            result.experiment_version,
                            &format!("baseline:{evidence_id}"),
                        ),
                        session_id: session_id.to_string(),
                        claim_id: completed.hypothesis_claim_id,
                        evidence_id: *evidence_id,
                        relation: EvidenceRelation::Neutral,
                        linked_at: result.computed_at.clone(),
                    },
                    provenance: EvidenceProvenanceClass::Observational,
                })
                .collect();

            let intervention_links = completed
                .intervention_evidence_ids
                .iter()
                .map(|evidence_id| CausalEvidenceLink {
                    link: EvidenceLink {
                        id: causal_link_id(
                            result.experiment_id,
                            result.experiment_version,
                            &format!("intervention:{evidence_id}"),
                        ),
                        session_id: session_id.to_string(),
                        claim_id: completed.hypothesis_claim_id,
                        evidence_id: *evidence_id,
                        relation: completed.hypothesis_relation,
                        linked_at: result.computed_at.clone(),
                    },
                    provenance: EvidenceProvenanceClass::Interventional(provenance.clone()),
                })
                .collect();

            Ok(CausalExperimentEvidence::Completed {
                relation: completed.hypothesis_relation,
                baseline_links,
                intervention_links,
            })
        }
        ExperimentOutcome::Inconclusive { reason } => Ok(CausalExperimentEvidence::Inconclusive {
            reason: reason.clone(),
        }),
        ExperimentOutcome::Blocked { reason } => Ok(CausalExperimentEvidence::Blocked {
            reason: reason.clone(),
        }),
        ExperimentOutcome::Unsupported { reason } => Ok(CausalExperimentEvidence::Unsupported {
            reason: reason.clone(),
        }),
        ExperimentOutcome::Failed { reason } => Ok(CausalExperimentEvidence::Failed {
            reason: reason.clone(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experiment::CompletedExperiment;

    fn completed_result(
        baseline_ids: Vec<Uuid>,
        intervention_ids: Vec<Uuid>,
        relation: EvidenceRelation,
    ) -> ExperimentResult {
        ExperimentResult {
            experiment_id: Uuid::new_v4(),
            experiment_version: 1,
            outcome: ExperimentOutcome::Completed(
                CompletedExperiment::new(
                    Uuid::new_v4(),
                    relation,
                    baseline_ids,
                    intervention_ids,
                    "reverting the file changed the outcome",
                )
                .unwrap(),
            ),
            computed_at: "2026-01-02T00:00:00Z".into(),
        }
    }

    // --- AC1/AC2: Interventional cannot be constructed without an experiment ---

    #[test]
    fn interventional_provenance_rejects_empty_baseline_ids() {
        let err = InterventionalProvenance::new(Uuid::new_v4(), 1, vec![], vec![Uuid::new_v4()])
            .unwrap_err();
        assert!(err.contains("baseline"));
    }

    #[test]
    fn interventional_provenance_rejects_empty_intervention_ids() {
        let err = InterventionalProvenance::new(Uuid::new_v4(), 1, vec![Uuid::new_v4()], vec![])
            .unwrap_err();
        assert!(err.contains("intervention"));
    }

    #[test]
    fn interventional_provenance_populates_experiment_and_both_evidence_sides() {
        let experiment_id = Uuid::new_v4();
        let baseline_id = Uuid::new_v4();
        let intervention_id = Uuid::new_v4();
        let provenance = InterventionalProvenance::new(
            experiment_id,
            3,
            vec![baseline_id],
            vec![intervention_id],
        )
        .unwrap();
        assert_eq!(provenance.experiment_id(), experiment_id);
        assert_eq!(provenance.experiment_version(), 3);
        assert_eq!(provenance.baseline_evidence_ids(), &[baseline_id]);
        assert_eq!(provenance.intervention_evidence_ids(), &[intervention_id]);
    }

    #[test]
    fn causal_evidence_link_carrying_observational_is_never_interventional() {
        let link = EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id: Uuid::new_v4(),
            evidence_id: Uuid::new_v4(),
            relation: EvidenceRelation::Supports,
            linked_at: "2026-01-01T00:00:00Z".into(),
        };
        let causal = CausalEvidenceLink {
            link,
            provenance: EvidenceProvenanceClass::Observational,
        };
        assert!(!causal.provenance.is_interventional());
    }

    // --- AC3: non-Completed outcomes cannot look like a comparison ---------

    #[test]
    fn only_completed_causal_evidence_carries_a_hypothesis_relation() {
        let completed = causal_evidence_from_experiment_result(
            &completed_result(
                vec![Uuid::new_v4()],
                vec![Uuid::new_v4()],
                EvidenceRelation::Contradicts,
            ),
            "s1",
        )
        .unwrap();
        assert_eq!(
            completed.hypothesis_relation(),
            Some(EvidenceRelation::Contradicts)
        );

        for outcome in [
            ExperimentOutcome::Inconclusive {
                reason: "evidence did not resolve either way".into(),
            },
            ExperimentOutcome::Blocked {
                reason: "precondition failed".into(),
            },
            ExperimentOutcome::Unsupported {
                reason: "no executor for this kind".into(),
            },
            ExperimentOutcome::Failed {
                reason: "executor errored".into(),
            },
        ] {
            let result = ExperimentResult {
                experiment_id: Uuid::new_v4(),
                experiment_version: 1,
                outcome,
                computed_at: "2026-01-02T00:00:00Z".into(),
            };
            let causal = causal_evidence_from_experiment_result(&result, "s1").unwrap();
            assert_eq!(
                causal.hypothesis_relation(),
                None,
                "{causal:?} must never yield a hypothesis_relation"
            );
        }
    }

    /// The AC3 requirement pinned at the wire level, not just in Rust: a
    /// naive downstream consumer reading JSON must not find any field on a
    /// non-`Completed` `CausalExperimentEvidence` that looks like "the
    /// intervention contradicted the hypothesis".
    #[test]
    fn blocked_causal_evidence_json_carries_no_relation_or_link_shaped_key() {
        let result = ExperimentResult {
            experiment_id: Uuid::new_v4(),
            experiment_version: 1,
            outcome: ExperimentOutcome::Blocked {
                reason: "safety policy violated".into(),
            },
            computed_at: "2026-01-02T00:00:00Z".into(),
        };
        let causal = causal_evidence_from_experiment_result(&result, "s1").unwrap();
        let json = serde_json::to_value(&causal).unwrap();
        let blocked_body = &json["blocked"];
        assert!(blocked_body.get("relation").is_none());
        assert!(blocked_body.get("baseline_links").is_none());
        assert!(blocked_body.get("intervention_links").is_none());
        assert_eq!(
            blocked_body["reason"],
            serde_json::json!("safety policy violated")
        );
    }

    #[test]
    fn causal_experiment_evidence_round_trips_for_every_variant() {
        let variants = [
            causal_evidence_from_experiment_result(
                &completed_result(
                    vec![Uuid::new_v4()],
                    vec![Uuid::new_v4()],
                    EvidenceRelation::Supports,
                ),
                "s1",
            )
            .unwrap(),
            CausalExperimentEvidence::Inconclusive { reason: "r".into() },
            CausalExperimentEvidence::Blocked { reason: "r".into() },
            CausalExperimentEvidence::Unsupported { reason: "r".into() },
            CausalExperimentEvidence::Failed { reason: "r".into() },
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: CausalExperimentEvidence = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // --- AC5: trace an interventional record back to baseline + intervention --

    #[test]
    fn interventional_causal_evidence_traces_back_to_baseline_and_intervention_evidence() {
        let baseline_id = Uuid::new_v4();
        let intervention_id = Uuid::new_v4();
        let result = completed_result(
            vec![baseline_id],
            vec![intervention_id],
            EvidenceRelation::Supports,
        );
        let causal = causal_evidence_from_experiment_result(&result, "s1").unwrap();

        let CausalExperimentEvidence::Completed {
            relation,
            baseline_links,
            intervention_links,
        } = &causal
        else {
            panic!("expected Completed, got {causal:?}");
        };
        assert_eq!(*relation, EvidenceRelation::Supports);

        assert_eq!(baseline_links.len(), 1);
        assert_eq!(baseline_links[0].link.evidence_id, baseline_id);
        assert_eq!(
            baseline_links[0].provenance,
            EvidenceProvenanceClass::Observational
        );

        assert_eq!(intervention_links.len(), 1);
        assert_eq!(intervention_links[0].link.evidence_id, intervention_id);
        assert_eq!(
            intervention_links[0].link.relation,
            EvidenceRelation::Supports
        );
        match &intervention_links[0].provenance {
            EvidenceProvenanceClass::Interventional(provenance) => {
                assert_eq!(provenance.experiment_id(), result.experiment_id);
                assert_eq!(provenance.experiment_version(), result.experiment_version);
                assert_eq!(provenance.baseline_evidence_ids(), &[baseline_id]);
                assert_eq!(provenance.intervention_evidence_ids(), &[intervention_id]);
            }
            other => panic!("expected Interventional provenance, got {other:?}"),
        }
    }

    #[test]
    fn causal_evidence_from_experiment_result_is_deterministic() {
        let result = completed_result(
            vec![Uuid::new_v4()],
            vec![Uuid::new_v4()],
            EvidenceRelation::Supports,
        );
        let a = causal_evidence_from_experiment_result(&result, "s1").unwrap();
        let b = causal_evidence_from_experiment_result(&result, "s1").unwrap();
        assert_eq!(a, b);
    }

    /// A malformed `Completed` outcome (empty evidence-id lists) reaches
    /// this function despite `CompletedExperiment::new`'s guardrail,
    /// because `CompletedExperiment`'s fields are public -- a struct literal
    /// or deserialized payload can still build one. This function must
    /// surface that as an error, never launder it into a different,
    /// non-`Completed` variant that would misrepresent what the experiment
    /// actually produced.
    #[test]
    fn malformed_completed_outcome_with_empty_evidence_ids_is_rejected_not_laundered() {
        let malformed = CompletedExperiment {
            hypothesis_claim_id: Uuid::new_v4(),
            hypothesis_relation: EvidenceRelation::Supports,
            baseline_evidence_ids: vec![],
            intervention_evidence_ids: vec![Uuid::new_v4()],
            summary: "malformed".into(),
        };
        let result = ExperimentResult {
            experiment_id: Uuid::new_v4(),
            experiment_version: 1,
            outcome: ExperimentOutcome::Completed(malformed),
            computed_at: "2026-01-02T00:00:00Z".into(),
        };
        let err = causal_evidence_from_experiment_result(&result, "s1").unwrap_err();
        assert!(err.contains("baseline"));
    }

    // --- EvidenceProvenanceClass: closed vocabulary, stable wire names -----

    #[test]
    fn evidence_provenance_class_has_stable_wire_names() {
        let observational = EvidenceProvenanceClass::Observational;
        let json = serde_json::to_value(&observational).unwrap();
        assert_eq!(json, serde_json::json!("observational"));
        let back: EvidenceProvenanceClass = serde_json::from_value(json).unwrap();
        assert_eq!(observational, back);

        let manifest_id = Uuid::new_v4();
        let replayed = EvidenceProvenanceClass::Replayed { manifest_id };
        let json = serde_json::to_value(&replayed).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "replayed": { "manifest_id": manifest_id } })
        );
        let back: EvidenceProvenanceClass = serde_json::from_value(json).unwrap();
        assert_eq!(replayed, back);

        let experiment_id = Uuid::new_v4();
        let baseline_id = Uuid::new_v4();
        let intervention_id = Uuid::new_v4();
        let interventional = EvidenceProvenanceClass::Interventional(
            InterventionalProvenance::new(
                experiment_id,
                1,
                vec![baseline_id],
                vec![intervention_id],
            )
            .unwrap(),
        );
        let json = serde_json::to_value(&interventional).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "interventional": {
                    "experiment_id": experiment_id,
                    "experiment_version": 1,
                    "baseline_evidence_ids": [baseline_id],
                    "intervention_evidence_ids": [intervention_id],
                }
            })
        );
        let back: EvidenceProvenanceClass = serde_json::from_value(json).unwrap();
        assert_eq!(interventional, back);

        // Exhaustiveness check: every variant must be exercised above.
        match &observational {
            EvidenceProvenanceClass::Observational
            | EvidenceProvenanceClass::Replayed { .. }
            | EvidenceProvenanceClass::Interventional(_) => {}
        }
    }

    #[test]
    fn interventional_provenance_wire_payload_with_empty_evidence_ids_fails_loudly() {
        let json = serde_json::json!({
            "experiment_id": Uuid::new_v4(),
            "experiment_version": 1,
            "baseline_evidence_ids": [],
            "intervention_evidence_ids": [],
        });
        let err = serde_json::from_value::<InterventionalProvenance>(json).unwrap_err();
        assert!(err.to_string().contains("baseline"));
    }

    // --- AC4: pre-existing EvidenceLink data is untouched by this module ---

    /// This module changes nothing about `EvidenceLink`'s own wire shape --
    /// a frozen pre-FORNX-102 `EvidenceLink` JSON payload (no causal
    /// provenance concept existed when it was written) must keep
    /// deserializing exactly as it always has, mirroring
    /// `experiment::tests::frozen_v1_fixture_still_reads_correctly`'s
    /// precedent.
    #[test]
    fn frozen_pre_causal_evidence_link_fixture_still_reads_correctly() {
        let json = r#"{
            "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            "session_id": "s1",
            "claim_id": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
            "evidence_id": "3fa85f64-5717-4562-b3fc-2c963f66afa8",
            "relation": "supports",
            "linked_at": "2026-01-01T00:00:00Z"
        }"#;
        let link: EvidenceLink = serde_json::from_str(json).unwrap();
        assert_eq!(link.session_id, "s1");
        assert_eq!(link.relation, EvidenceRelation::Supports);
        // Nothing on EvidenceLink itself carries a causal-provenance field
        // -- classifying it is done externally via CausalEvidenceLink,
        // which this fixture never mentions and does not need to.
        let reser = serde_json::to_value(&link).unwrap();
        assert!(reser.get("provenance").is_none());
        assert!(reser.get("causal_provenance").is_none());
    }
}
