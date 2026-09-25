//! Evidence provenance authenticity guard (FORNX-381, parent epic FORNX-376,
//! Stage 9). Hardens Fornax so evidence *strength* reflects how hard it
//! would be for the monitored agent (or an adjacent component) to make that
//! evidence lie, not merely the evidence's apparent content — closing two
//! real gaps FORNX-380's attack corpus disclosed but did not fix:
//!
//! - **`fornx380-11-forged-trust-class-label`** (`Escaped`): nothing in
//!   `fornax-verify` cryptographically verified that a
//!   [`crate::sensor::TrustClass::HostObserved`] label on an
//!   [`crate::sensor::EvidenceSource`] was actually assigned by the real
//!   host-observation sensor rather than fabricated upstream — the pipeline
//!   trusted the label it was handed. [`CollectorAuthority`] /
//!   [`authorize_evidence_source`] close this: a named collector may only
//!   assert the trust classes it is explicitly registered for; an
//!   unregistered or mismatched sensor identity is quarantined, never
//!   trusted at face value.
//! - **`fornx380-10-receipt-replay-cross-claim`** (`Escaped`): the same
//!   physical [`crate::Evidence`] row could satisfy two entirely unrelated
//!   claims, since `contract_satisfaction::assess` is a pure per-call
//!   function with no cross-call memory of which evidence has already been
//!   "spent". [`EvidenceConsumptionLedger`] is that cross-call memory — an
//!   explicit ledger a caller (the daemon, or any orchestrating layer) can
//!   hold across multiple `assess` calls.
//!
//! Also closes a third, previously *undisclosed* gap found while building
//! this ticket: neither `assess` nor `assess_with_capabilities` ever checks
//! that a piece of evidence's `session_id` matches the claim it is being
//! used to support — an adapter could submit evidence carrying a different
//! session's id and have it accepted identically. [`bind_evidence_to_session`]
//! closes this (AC2's session axis).
//!
//! # Non-goals (inherited from the ticket)
//!
//! No mandatory TPM/TEE/eBPF dependency — [`digest_of`]/[`EvidenceIntegrity`]
//! supply an honest content digest and an explicit "nothing was signed"
//! default, never a fabricated verification claim, since no device/service
//! identity or key-management infrastructure exists in this repo today. No
//! claim that a digest, a signature, or an authorized-collector check proves
//! the *semantic* claim behind the evidence — only that the pipeline can (or
//! cannot) vouch for who produced it.
//!
//! # Scope note: session binding only, not daemon/acquisition-request
//! identity
//!
//! The ticket's AC2 also names "daemon" and "acquisition" identity as
//! binding axes. This repo has no `daemon_run_id`/`acquisition_request_id`
//! concept attached to [`crate::Evidence`] today (only `session_id` and
//! `source_event_id` exist) — inventing new identity fields plumbed through
//! every adapter/daemon evidence-construction call site is a materially
//! larger, cross-cutting change than this ticket's other six ACs, and doing
//! it as a rushed side effect here risks exactly the kind of half-finished
//! surface this codebase's conventions reject. [`bind_evidence_to_session`]
//! implements the concrete, already-real session axis fully and genuinely —
//! cross-session attribution fails closed today — while the daemon/
//! acquisition axes remain a disclosed, real gap for a future ticket, not a
//! fabricated pass.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::sensor::{EvidenceSource, TrustClass};
use crate::{Claim, Evidence};

// ---------------------------------------------------------------------
// AC1: collector authority — a named collector may only assert the trust
// classes it is registered for.
// ---------------------------------------------------------------------

/// An explicit allowlist of which [`TrustClass`] a named collector
/// (`EvidenceSource::sensor_name`) is authorized to assert (AC1). Built from
/// this repo's own shipped sensors' declared `EvidenceSensor::trust_class()`
/// (FORNX-157/159) via [`Self::known_sensors`] — extend it when a new sensor
/// ships. An unregistered `sensor_name` is never assumed trustworthy: the
/// authority itself is the trust anchor, never anything read from the
/// untrusted payload/source record it is checking.
#[derive(Debug, Clone, Default)]
pub struct CollectorAuthority {
    allowed: HashMap<String, HashSet<TrustClass>>,
}

impl CollectorAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `sensor_name` as authorized to assert `trust_class`. A
    /// sensor may be authorized for more than one trust class only if it
    /// genuinely operates at more than one boundary (none of this repo's
    /// shipped sensors do — see [`Self::known_sensors`]).
    pub fn authorize_sensor(
        mut self,
        sensor_name: impl Into<String>,
        trust_class: TrustClass,
    ) -> Self {
        self.allowed
            .entry(sensor_name.into())
            .or_default()
            .insert(trust_class);
        self
    }

    /// This repo's real, currently-shipped sensors
    /// (`fornax-adapter-claude`/`-codex`/`-opencode`), each authorized for
    /// exactly the trust class its own `EvidenceSensor::trust_class()`
    /// implementation declares — never a broader ceiling than what the
    /// sensor itself already claims in code. Read directly from each
    /// adapter crate's source at the time this module was written; keep in
    /// sync when a sensor is added, renamed, or its trust class changes.
    pub fn known_sensors() -> Self {
        Self::new()
            .authorize_sensor("claude_bash_exit_code_sensor_v1", TrustClass::AgentAdjacent)
            .authorize_sensor(
                "claude_edit_write_diff_sensor_v1",
                TrustClass::AgentAdjacent,
            )
            .authorize_sensor(
                "claude_file_write_confirmed_sensor_v1",
                TrustClass::HostObserved,
            )
            .authorize_sensor("claude_git_outcome_sensor_v1", TrustClass::AgentAdjacent)
            .authorize_sensor(
                "claude_git_working_tree_sensor_v1",
                TrustClass::HostObserved,
            )
            .authorize_sensor(
                "codex_exec_command_end_sensor_v1",
                TrustClass::AgentAdjacent,
            )
            .authorize_sensor(
                "codex_custom_tool_call_output_sensor_v1",
                TrustClass::AgentAdjacent,
            )
            .authorize_sensor(
                "opencode_tool_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            )
            .authorize_sensor(
                "opencode_command_duration_sensor_v1",
                TrustClass::AgentAdjacent,
            )
    }

    /// True only if `sensor_name` is registered under this exact
    /// `trust_class` — not merely registered at all.
    pub fn is_authorized(&self, sensor_name: &str, trust_class: &TrustClass) -> bool {
        self.allowed
            .get(sensor_name)
            .is_some_and(|set| set.contains(trust_class))
    }

    /// True if `sensor_name` is registered under any trust class — used to
    /// distinguish "known collector claiming an unauthorized class" from
    /// "completely unknown collector identity" in
    /// [`authorize_evidence_source`]'s reason text.
    pub fn is_registered(&self, sensor_name: &str) -> bool {
        self.allowed.contains_key(sensor_name)
    }
}

/// AC1/AC4: the outcome of checking one [`EvidenceSource`] against a
/// [`CollectorAuthority`]. A distinct, small vocabulary from
/// `epistemic_contract::SatisfactionState` / `Verdict` / `fornax-bench`'s
/// `AttackOutcome` (`docs/adr/0001-architecture-invariants.md`'s
/// never-collapse-vocabularies discipline) — this answers "can we vouch for
/// who produced this", not "does the evidence satisfy a requirement" or
/// "did an attack get through".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceVerdict {
    /// The named collector is authorized to assert this trust class.
    Trusted,
    /// The named collector is not authorized to assert this trust class —
    /// either registered under a different one, or not registered at all.
    /// AC4: quarantined evidence must be marked invalid/unavailable
    /// downstream, never counted negatively *or* positively — a caller must
    /// not turn a quarantine into a fabricated contradiction.
    Quarantined { reason: String },
}

/// Check one [`EvidenceSource`] against `authority` (AC1). Reads only
/// `authority` and the source's own `sensor_name`/`trust_class` — never
/// infers authorization from any other field on the source or its owning
/// [`Evidence`], since every other field is exactly the kind of
/// caller-supplied payload metadata an untrusted adapter could set.
pub fn authorize_evidence_source(
    authority: &CollectorAuthority,
    source: &EvidenceSource,
) -> ProvenanceVerdict {
    if authority.is_authorized(&source.sensor_name, &source.trust_class) {
        return ProvenanceVerdict::Trusted;
    }
    let reason = if authority.is_registered(&source.sensor_name) {
        format!(
            "collector '{}' is registered but not authorized to assert trust_class {:?}",
            source.sensor_name, source.trust_class
        )
    } else {
        format!(
            "collector '{}' is not a registered, known collector identity — its claimed \
             trust_class {:?} cannot be vouched for",
            source.sensor_name, source.trust_class
        )
    };
    ProvenanceVerdict::Quarantined { reason }
}

// ---------------------------------------------------------------------
// AC2 (session axis): cross-session attribution fails closed.
// ---------------------------------------------------------------------

/// One piece of evidence attributed to the wrong session — its `session_id`
/// does not match the claim it is being used to support. Never silently
/// dropped without a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBindingViolation {
    pub evidence_id: Uuid,
    pub evidence_session_id: String,
    pub claim_session_id: String,
}

/// AC2 (session axis): partitions `evidence` into `(bound, violations)` —
/// only evidence whose `session_id` matches `claim.session_id` is bound.
/// Cross-session attribution fails closed: a piece of evidence from a
/// different session is never silently accepted, only ever reported as a
/// violation. Callers should pass only `bound` onward to
/// `contract_satisfaction::assess`/`assess_with_capabilities` — see this
/// module's tests for the concrete before/after against a real session-mix
/// attack.
pub fn bind_evidence_to_session<'a>(
    claim: &Claim,
    evidence: &'a [Evidence],
) -> (Vec<&'a Evidence>, Vec<SessionBindingViolation>) {
    let mut bound = Vec::new();
    let mut violations = Vec::new();
    for ev in evidence {
        if ev.session_id == claim.session_id {
            bound.push(ev);
        } else {
            violations.push(SessionBindingViolation {
                evidence_id: ev.id,
                evidence_session_id: ev.session_id.clone(),
                claim_session_id: claim.session_id.clone(),
            });
        }
    }
    (bound, violations)
}

// ---------------------------------------------------------------------
// AC3/AC7: replay/duplicate detection across calls — closes FORNX-380
// fixture 10 (cross-claim receipt replay).
// ---------------------------------------------------------------------

/// Outcome of recording one `(evidence_id, claim_id)` consumption attempt
/// against an [`EvidenceConsumptionLedger`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayVerdict {
    /// Not previously consumed by any claim; now recorded.
    FreshlyRecorded,
    /// Already recorded, for the *same* claim — a duplicate report, not a
    /// cross-claim replay. (`contract_satisfaction::assess`'s own per-call
    /// dedup already handles the same-call, same-claim case; this covers
    /// the cross-*call*, same-claim case, e.g. a claim re-assessed after new
    /// evidence arrives.)
    AlreadyConsumedBySameClaim,
    /// Already recorded for a *different* claim — a genuine cross-claim
    /// replay attempt (FORNX-380 fixture 10).
    ReplayedAcrossClaims { originally_consumed_by: Uuid },
}

/// AC3/AC7: closes `fornx380-10-receipt-replay-cross-claim` — the same
/// physical [`Evidence`] row satisfying two entirely unrelated claims, since
/// `contract_satisfaction::assess` is a pure per-call function with no
/// cross-call memory of which evidence has already been "spent". This
/// ledger *is* that cross-call memory: an explicit, in-process record a
/// caller (the daemon, or any orchestrating layer above `assess`) holds
/// across multiple assessment calls. Deliberately a plain in-memory map, not
/// a persisted store table — wiring this into `fornax-store`/the live daemon
/// binary's request path is a larger, separate integration task than this
/// ticket's other six ACs; this type is the real, usable, tested mechanism a
/// future integration wires in, not a placeholder.
#[derive(Debug, Clone, Default)]
pub struct EvidenceConsumptionLedger {
    consumed: HashMap<Uuid, Uuid>,
}

impl EvidenceConsumptionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `evidence_id` is being used to satisfy `claim_id`, and
    /// report whether this is a fresh consumption, a duplicate for the same
    /// claim, or a replay across two different claims. Never silently
    /// overwrites a prior record — a `ReplayedAcrossClaims` verdict leaves
    /// the ledger's original `(evidence_id -> claim_id)` entry unchanged.
    pub fn record_and_check(&mut self, evidence_id: Uuid, claim_id: Uuid) -> ReplayVerdict {
        match self.consumed.get(&evidence_id).copied() {
            Some(existing) if existing == claim_id => ReplayVerdict::AlreadyConsumedBySameClaim,
            Some(existing) => ReplayVerdict::ReplayedAcrossClaims {
                originally_consumed_by: existing,
            },
            None => {
                self.consumed.insert(evidence_id, claim_id);
                ReplayVerdict::FreshlyRecorded
            }
        }
    }

    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }
}

// ---------------------------------------------------------------------
// AC6: optional digest support — honest "unsigned" default, no crypto
// verification claim without real key-management infrastructure.
// ---------------------------------------------------------------------

/// AC6: whether a piece of evidence carries any cryptographic integrity
/// guarantee at all. [`Self::Unsigned`] is the honest default for every
/// sensor this repo ships today — none of them sign anything. Reporting
/// `Unsigned` must never be silently upgraded to imply integrity that was
/// never actually checked; that is the exact fabrication AC6 forbids
/// ("never implies endpoint integrity beyond reality").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceIntegrity {
    /// No digest/signature accompanies this evidence — the honest default.
    /// This says nothing about whether the evidence is trustworthy; that
    /// axis is [`ProvenanceVerdict`]'s job, not this one.
    Unsigned,
    /// A digest was supplied, but this module has no verifying key
    /// configured for the claimed signer — neither confirmed authentic nor
    /// rejected as forged, explicitly unresolved rather than assumed either
    /// way.
    DigestPresentButUnverifiable { digest: String },
}

/// A stable content digest of one piece of evidence (SHA-256 over its
/// identity, session, observation time, and payload) — deliberately *not*
/// itself a signature. A future protected-collector seam (an OS/sandbox/CI
/// attestation identity, per the ticket's scope) would sign over exactly
/// this digest; this module supplies the digest, never the signing or
/// verification, since no device/service identity or key-management
/// infrastructure exists in this repo yet (Non-goal: no TPM/TEE/eBPF
/// dependency in v0.3.0).
pub fn digest_of(evidence: &Evidence) -> String {
    let mut hasher = Sha256::new();
    hasher.update(evidence.id.as_bytes());
    hasher.update(evidence.session_id.as_bytes());
    hasher.update(evidence.observed_at.as_bytes());
    hasher.update(evidence.payload.to_string().as_bytes());
    let hash = hasher.finalize();
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// The honest integrity status of `evidence` today: always [`EvidenceIntegrity::Unsigned`],
/// since no sensor this repo ships attaches a digest or signature. A future
/// signing sensor would populate a real field this function reads instead of
/// this constant — kept as a named function rather than inlining the
/// constant at call sites so that future change is a one-place edit, not a
/// grep-and-replace.
pub fn integrity_of(_evidence: &Evidence) -> EvidenceIntegrity {
    EvidenceIntegrity::Unsigned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensor::{CollectionMethod, EvidenceSource};
    use crate::{EvidenceKind, Provider};

    fn claim(session_id: &str) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id: Uuid::new_v4(),
            text: "tests passed".to_string(),
            subject: "tests_passed".to_string(),
            claimed_at: "2026-09-25T00:10:00Z".to_string(),
        }
    }

    fn evidence_with(session_id: &str, sensor_name: &str, trust_class: TrustClass) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-09-25T00:00:00Z".to_string(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test-fixture".to_string(),
            source: Some(EvidenceSource {
                sensor_name: sensor_name.to_string(),
                trust_class,
                collected_at: "2026-09-25T00:00:00Z".to_string(),
                provider: Some(Provider::ClaudeCode),
                collection_method: CollectionMethod::HookCallback,
                collector_version: None,
                freshness: Default::default(),
                tamper_boundary: Default::default(),
                correlation_group: None,
                derived_from: Vec::new(),
            }),
            extension: None,
            evidence_purged: false,
        }
    }

    // --- AC1: CollectorAuthority / authorize_evidence_source ------------

    #[test]
    fn a_known_sensor_asserting_its_own_declared_trust_class_is_trusted() {
        let authority = CollectorAuthority::known_sensors();
        let source = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        )
        .source
        .unwrap();
        assert_eq!(
            authorize_evidence_source(&authority, &source),
            ProvenanceVerdict::Trusted
        );
    }

    #[test]
    fn fornx380_11_forged_host_observed_label_from_an_agent_only_sensor_is_quarantined() {
        // The FORNX-380 exploit: something claims TrustClass::HostObserved
        // under a sensor identity this repo only ever authorizes for
        // AgentAdjacent (its own tool_response account). Before this
        // module, nothing checked this at all -- see fixture
        // `fornx380-11-forged-trust-class-label`, marked `Escaped`.
        let authority = CollectorAuthority::known_sensors();
        let forged_source = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1", // real sensor name
            TrustClass::HostObserved,          // but a trust class it never actually asserts
        )
        .source
        .unwrap();
        let verdict = authorize_evidence_source(&authority, &forged_source);
        assert!(matches!(verdict, ProvenanceVerdict::Quarantined { .. }));
    }

    #[test]
    fn a_completely_unknown_collector_identity_is_quarantined_not_trusted_by_default() {
        let authority = CollectorAuthority::known_sensors();
        let source = evidence_with("s1", "totally_made_up_sensor_v99", TrustClass::HostObserved)
            .source
            .unwrap();
        let verdict = authorize_evidence_source(&authority, &source);
        match verdict {
            ProvenanceVerdict::Quarantined { reason } => {
                assert!(reason.contains("not a registered"));
            }
            ProvenanceVerdict::Trusted => panic!("an unknown collector must never be Trusted"),
        }
    }

    #[test]
    fn hard_negative_every_known_sensors_own_declared_trust_class_is_authorized() {
        // Proves the registry doesn't accidentally reject the very sensors
        // it was built from -- a genuine hard negative, mirroring
        // FORNX-380's discipline of proving the detector doesn't
        // false-positive on legitimate input.
        let authority = CollectorAuthority::known_sensors();
        let legitimate = [
            ("claude_bash_exit_code_sensor_v1", TrustClass::AgentAdjacent),
            (
                "claude_file_write_confirmed_sensor_v1",
                TrustClass::HostObserved,
            ),
            (
                "codex_exec_command_end_sensor_v1",
                TrustClass::AgentAdjacent,
            ),
            (
                "opencode_tool_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            ),
        ];
        for (sensor_name, trust_class) in legitimate {
            let source = evidence_with("s1", sensor_name, trust_class.clone())
                .source
                .unwrap();
            assert_eq!(
                authorize_evidence_source(&authority, &source),
                ProvenanceVerdict::Trusted,
                "sensor {sensor_name} should be authorized for its own declared trust class"
            );
        }
    }

    // --- AC2: session binding --------------------------------------------

    #[test]
    fn cross_session_evidence_is_a_violation_never_silently_bound() {
        let c = claim("session-A");
        let matching = evidence_with(
            "session-A",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        let foreign = evidence_with(
            "session-B", // a different session's evidence, submitted against claim's session
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        let all = vec![matching.clone(), foreign.clone()];
        let (bound, violations) = bind_evidence_to_session(&c, &all);
        assert_eq!(bound.len(), 1);
        assert_eq!(bound[0].id, matching.id);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].evidence_id, foreign.id);
        assert_eq!(violations[0].evidence_session_id, "session-B");
        assert_eq!(violations[0].claim_session_id, "session-A");
    }

    #[test]
    fn hard_negative_same_session_evidence_is_fully_bound_with_no_violations() {
        let c = claim("session-A");
        let all = vec![
            evidence_with(
                "session-A",
                "claude_bash_exit_code_sensor_v1",
                TrustClass::AgentAdjacent,
            ),
            evidence_with(
                "session-A",
                "claude_git_outcome_sensor_v1",
                TrustClass::AgentAdjacent,
            ),
        ];
        let (bound, violations) = bind_evidence_to_session(&c, &all);
        assert_eq!(bound.len(), 2);
        assert!(violations.is_empty());
    }

    // --- AC3/AC7: EvidenceConsumptionLedger (FORNX-380 fixture 10) --------

    #[test]
    fn fornx380_10_the_same_evidence_row_cannot_satisfy_two_unrelated_claims_via_the_ledger() {
        let mut ledger = EvidenceConsumptionLedger::new();
        let evidence_id = Uuid::new_v4();
        let claim_a = Uuid::new_v4();
        let claim_b = Uuid::new_v4();

        assert_eq!(
            ledger.record_and_check(evidence_id, claim_a),
            ReplayVerdict::FreshlyRecorded
        );
        // Fixture 10's exact exploit: the same physical evidence row
        // submitted again to satisfy a second, unrelated claim.
        let replay = ledger.record_and_check(evidence_id, claim_b);
        assert_eq!(
            replay,
            ReplayVerdict::ReplayedAcrossClaims {
                originally_consumed_by: claim_a
            }
        );
        assert_eq!(
            ledger.len(),
            1,
            "the ledger must not overwrite the original claim"
        );
    }

    #[test]
    fn hard_negative_re_recording_for_the_same_claim_is_not_a_cross_claim_replay() {
        let mut ledger = EvidenceConsumptionLedger::new();
        let evidence_id = Uuid::new_v4();
        let claim_a = Uuid::new_v4();
        assert_eq!(
            ledger.record_and_check(evidence_id, claim_a),
            ReplayVerdict::FreshlyRecorded
        );
        assert_eq!(
            ledger.record_and_check(evidence_id, claim_a),
            ReplayVerdict::AlreadyConsumedBySameClaim
        );
    }

    #[test]
    fn distinct_evidence_rows_for_distinct_claims_are_all_freshly_recorded() {
        let mut ledger = EvidenceConsumptionLedger::new();
        for _ in 0..5 {
            assert_eq!(
                ledger.record_and_check(Uuid::new_v4(), Uuid::new_v4()),
                ReplayVerdict::FreshlyRecorded
            );
        }
        assert_eq!(ledger.len(), 5);
        assert!(!ledger.is_empty());
    }

    // --- AC6: EvidenceIntegrity / digest_of -------------------------------

    #[test]
    fn every_evidence_this_repo_produces_today_is_honestly_unsigned() {
        let ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        assert_eq!(integrity_of(&ev), EvidenceIntegrity::Unsigned);
    }

    #[test]
    fn digest_of_is_deterministic_and_content_sensitive() {
        let ev_a = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        let digest_1 = digest_of(&ev_a);
        let digest_2 = digest_of(&ev_a);
        assert_eq!(
            digest_1, digest_2,
            "digest must be deterministic for the same evidence"
        );

        let mut ev_b = ev_a.clone();
        ev_b.payload = serde_json::json!({"exit_code": 1});
        assert_ne!(
            digest_of(&ev_b),
            digest_1,
            "a changed payload must change the digest"
        );
    }
}
