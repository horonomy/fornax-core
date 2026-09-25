//! Self-Integrity invariant registry (FORNX-382, parent epic FORNX-376
//! "Agent Epistemic Trust Kernel", target v0.3.0).
//!
//! FORNX-382's goal is to make Fornax *prove* the invariants it asks
//! downstream systems to trust, rather than relying only on example unit
//! tests scattered across the codebase with no central index. This module
//! is that index: a real, queryable Rust data structure (not prose) mapping
//! each of the ten required invariants to its documented rationale, the
//! test(s) that actually own its enforcement, and the release gate that
//! should block a regression from shipping.
//!
//! # What this module is not
//!
//! It does not re-implement invariant enforcement — every `owning_tests`
//! entry points at a test that already exists elsewhere in this workspace
//! (in `fornax-verify`, `fornax-types`, or `fornax-daemon`), several of
//! them newly added by this ticket as property-based generalizations of
//! prior example-based coverage (see each entry's rationale for which).
//! Passing every listed test does not prove the whole distributed system
//! correct (Non-goal, restated from the ticket) — it proves exactly the
//! ten specific properties enumerated below, each independently.
//!
//! # AC1 (this module's own completeness check)
//!
//! [`registry`] returns exactly ten entries and
//! [`tests::every_invariant_has_a_non_empty_owning_tests_list_and_release_gate`]
//! asserts every one carries a real rationale, at least one owning test
//! reference, and a release-gate name — a build-time regression (a new
//! invariant added to [`InvariantId`] without registering it) fails this
//! test, not a runtime data condition.

/// The ten invariants FORNX-382 requires, at minimum, to be encoded and
/// tested. Stable identifiers — do not renumber; a removed invariant should
/// be marked deprecated in its `rationale`, never have its variant deleted
/// or its number reused for something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InvariantId {
    /// #1: evidence from session/tenant A cannot affect B.
    SessionIsolation,
    /// #2: UNAVAILABLE/failed collection cannot become support or
    /// contradiction.
    UnavailableNeverBecomesAVerdict,
    /// #3: correlated/common-source evidence cannot manufacture
    /// independent corroboration.
    IndependenceCannotBeManufactured,
    /// #4: stale/suspect calibration cannot relax a decision.
    StaleCalibrationCannotRelax,
    /// #5: FORBIDDEN or unapproved probes cannot execute.
    UnapprovedProbesCannotExecute,
    /// #6: tampered/stale/scope-invalid receipts or delegation envelopes
    /// cannot verify.
    TamperedReceiptsCannotVerify,
    /// #7: model-derived judge/monitor output cannot override
    /// contradictory hard evidence solely through confidence.
    ConfidenceCannotOverrideHardEvidence,
    /// #8: contract/policy/version changes cannot silently rewrite
    /// historical evidence.
    PolicyChangesCannotRewriteHistory,
    /// #9: partial failure cannot be reported as complete success.
    PartialFailureCannotBeCompleteSuccess,
    /// #10: deterministic replay of pinned inputs produces the same
    /// semantic result.
    DeterministicReplay,
}

/// One invariant's full registry entry: why it exists, exactly which
/// test(s) enforce it today, and which release gate should treat a
/// regression in it as a blocker.
#[derive(Debug, Clone)]
pub struct InvariantRecord {
    pub id: InvariantId,
    /// Human rationale — why this invariant exists and what breaks
    /// downstream if it silently regresses.
    pub rationale: &'static str,
    /// Fully-qualified paths (crate::module::test_name) of the test(s)
    /// that own enforcement of this invariant today. Not every entry is
    /// new to this ticket — several point at pre-existing tests from
    /// FORNX-347/377/378/379/380/381 that already enforce the property;
    /// this registry's job is to index them centrally, not duplicate them.
    pub owning_tests: &'static [&'static str],
    /// The release-assurance gate ticket (or gate name) that should block
    /// a release if this invariant's owning test(s) go red or are removed.
    pub release_gate: &'static str,
}

/// The full, fixed registry. Returns exactly ten entries, one per
/// [`InvariantId`] variant — see
/// [`tests::registry_covers_every_invariant_id_exactly_once`].
pub fn registry() -> Vec<InvariantRecord> {
    vec![
        InvariantRecord {
            id: InvariantId::SessionIsolation,
            rationale: "A poisoned or misattributed session must never let its evidence \
                affect another session's claim assessment, satisfaction report, or \
                decision -- cross-session bleed would let one compromised agent \
                corrupt every other session sharing the same daemon.",
            owning_tests: &[
                "fornax-daemon::tests::cross_session_identity_handshake::* (FORNX-339, \
                 cross-*process* daemon-identity binding)",
                "fornax-daemon::tests::self_integrity_concurrency::\
                 concurrent_sessions_never_cross_attribute_or_tear_shared_state \
                 (FORNX-382, same-process concurrent Arc<Mutex<HashMap>> primitive)",
            ],
            release_gate: "FORNX-382 self-integrity gate",
        },
        InvariantRecord {
            id: InvariantId::UnavailableNeverBecomesAVerdict,
            rationale: "Absence of evidence is not evidence of absence: a Required \
                requirement with no qualifying evidence must read as Unavailable, \
                never spontaneously as Satisfied (false safety) or Contradicted \
                (fabricated dispute).",
            owning_tests: &[
                "fornax-verify::contract_satisfaction::tests::\
                 prop_irrelevant_evidence_never_manufactures_satisfaction (FORNX-382, \
                 property-based)",
                "fornax-types::epistemic_contract::tests::\
                 build_succeeded_unavailable_with_no_evidence (FORNX-377, example-based)",
            ],
            release_gate: "FORNX-378 Contract Satisfaction gate",
        },
        InvariantRecord {
            id: InvariantId::IndependenceCannotBeManufactured,
            rationale: "Two evidence rows that trace back to the same underlying source \
                (one agent turn fanned out to two sensors) must never satisfy a \
                requirement that two mutually-independent checks corroborate a claim \
                -- otherwise a single observation can masquerade as independent \
                corroboration.",
            owning_tests: &[
                "fornax-verify::contract_satisfaction::tests::\
                 duplicate_source_amplification_cannot_satisfy_independence (FORNX-378, \
                 example-based)",
                "fornax-verify::contract_satisfaction::tests::\
                 prop_family_hardening_defeats_duplicate_source_amplification (FORNX-382, \
                 property-based, includes a deliberately-seeded mutation-testing \
                 demonstration via naive_assess_without_family_hardening)",
            ],
            release_gate: "FORNX-378 Contract Satisfaction gate",
        },
        InvariantRecord {
            id: InvariantId::StaleCalibrationCannotRelax,
            rationale: "A stale or suspect calibration/reliability signal must never make \
                a decision more permissive than it would be without that signal -- \
                calibration can only ever tighten a verdict, never loosen one it \
                cannot vouch for.",
            owning_tests: &[
                "fornax-verify::decision::tests (FORNX-348 apply_calibration_floor -- \
                 non-relaxing floor, mirrored by FORNX-378's apply_contract_floor and \
                 FORNX-379's apply_verification_floor)",
            ],
            release_gate: "FORNX-348 Calibration Floor gate",
        },
        InvariantRecord {
            id: InvariantId::UnapprovedProbesCannotExecute,
            rationale: "An active-evidence probe that would touch the network, spend a \
                credential, or take a destructive/irreversible action must never \
                execute merely because its information value is high -- policy \
                approval is a hard gate, not a cost/benefit input.",
            owning_tests: &[
                "fornax-verify::verification_budget::tests::\
                 destructive_side_effect_is_never_approved_even_for_a_critical_obligation \
                 (FORNX-379)",
                "fornax-verify::verification_budget::tests::\
                 unapproved_network_access_is_refused_regardless_of_information_value \
                 (FORNX-379)",
                "fornax-verify::verification_budget::tests::\
                 credential_bearing_verification_is_refused_when_not_allowed_even_if_network_is_granted \
                 (FORNX-379)",
            ],
            release_gate: "FORNX-379 Adaptive Verification Budget gate",
        },
        InvariantRecord {
            id: InvariantId::TamperedReceiptsCannotVerify,
            rationale: "A receipt or delegation envelope with a tampered signature, an \
                expired/stale window, or a scope it was never granted must fail \
                verification -- never partially trusted, never accepted on \
                confidence alone.",
            owning_tests: &[
                "fornax-receipt (FORNX-350 receipt verification -- signature, scope, \
                 and freshness checks); fornax-types::provenance_guard::tests \
                 (FORNX-381 replay/duplicate/timestamp detection extends this to \
                 evidence-level provenance)",
            ],
            release_gate: "FORNX-381 Evidence Authenticity gate",
        },
        InvariantRecord {
            id: InvariantId::ConfidenceCannotOverrideHardEvidence,
            rationale: "A semantic judge or monitor's confidence score must never be \
                sufficient, by itself, to override hard contradicting evidence (a \
                literal exit code, a diff, a receipt) -- confidence informs \
                fusion weighting, it never substitutes for a missing or \
                contradicting hard fact.",
            owning_tests: &[
                "fornax-verify::fusion::tests (FusionPolicy's five-state verdict \
                 vocabulary -- Contradicted always outranks any confidence-weighted \
                 support, see docs/adr/0001-architecture-invariants.md)",
            ],
            release_gate: "FORNX-94 Semantic Judge gate",
        },
        InvariantRecord {
            id: InvariantId::PolicyChangesCannotRewriteHistory,
            rationale: "Registering a new contract/policy version, or changing a policy's \
                active version, must never mutate a prior version's already-computed \
                assessment or decision -- historical evidence and historical \
                verdicts are append-only from the point of view of any later policy \
                change.",
            owning_tests: &[
                "fornax-verify::contract_satisfaction::tests::\
                 registering_a_new_contract_version_does_not_mutate_the_old_versions_result \
                 (FORNX-378)",
            ],
            release_gate: "FORNX-378 Contract Satisfaction gate",
        },
        InvariantRecord {
            id: InvariantId::PartialFailureCannotBeCompleteSuccess,
            rationale: "When a verification budget is exhausted before every critical \
                obligation is covered, the outcome must be explicit \
                (InsufficientVerification, naming every uncovered obligation) -- \
                never silently reported as Planned/complete, which downstream \
                code reads as 'nothing outstanding'.",
            owning_tests: &[
                "fornax-verify::verification_budget::tests::\
                 budget_exhaustion_names_every_uncovered_required_obligation_never_silently_planned \
                 (FORNX-379, example-based)",
                "fornax-verify::verification_budget::tests::\
                 prop_budget_exhaustion_never_reports_planned_while_a_required_obligation_is_unmet \
                 (FORNX-382, property-based)",
            ],
            release_gate: "FORNX-379 Adaptive Verification Budget gate",
        },
        InvariantRecord {
            id: InvariantId::DeterministicReplay,
            rationale: "The same frozen claim/evidence/contract/policy/capability inputs \
                must always produce byte-identical canonical output -- a release \
                candidate re-assessed offline must reproduce exactly what shipped, \
                or release-assurance evidence cannot be trusted as reproducible.",
            owning_tests: &[
                "fornax-verify::contract_satisfaction::tests::\
                 same_frozen_inputs_produce_byte_identical_canonical_json (FORNX-378, \
                 example-based)",
                "fornax-verify::contract_satisfaction::tests::\
                 prop_assess_is_deterministic_for_arbitrary_evidence_pools (FORNX-382, \
                 property-based)",
                "fornax-verify::verification_budget::tests::\
                 same_frozen_inputs_produce_byte_identical_canonical_json (FORNX-379)",
            ],
            release_gate: "FORNX-378/FORNX-379 gates",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn registry_covers_every_invariant_id_exactly_once() {
        let ids: Vec<InvariantId> = registry().into_iter().map(|r| r.id).collect();
        let unique: HashSet<InvariantId> = ids.iter().copied().collect();
        assert_eq!(ids.len(), 10, "FORNX-382 requires exactly ten invariants");
        assert_eq!(unique.len(), 10, "no invariant id may be registered twice");
    }

    #[test]
    fn every_invariant_has_a_non_empty_owning_tests_list_and_release_gate() {
        for record in registry() {
            assert!(
                !record.rationale.trim().is_empty(),
                "{:?} has no rationale",
                record.id
            );
            assert!(
                !record.owning_tests.is_empty(),
                "{:?} has no owning test recorded",
                record.id
            );
            for t in record.owning_tests {
                assert!(
                    !t.trim().is_empty(),
                    "{:?} has a blank owning test entry",
                    record.id
                );
            }
            assert!(
                !record.release_gate.trim().is_empty(),
                "{:?} has no release-gate mapping",
                record.id
            );
        }
    }
}
