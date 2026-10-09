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
use crate::{Claim, Evidence, Provider};

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
// FORNX-431 (builds on FORNX-381's AC1): authenticated collector identity
// must derive from trusted registry/transport, not evidence payload
// labels. `authorize_evidence_source` above already refuses to trust a
// *trust_class* claim at face value; this section closes the remaining
// gap — nothing yet refuses to trust the *origin* (how the row physically
// arrived at the daemon) at face value either. A payload can set
// `sensor_name`/`trust_class` to anything; it can never set its own
// `EvidenceOrigin`, because that value is never a field on the wire
// `Evidence` type at all — only the receiving process (fornax-daemon, in a
// later slice) can stamp it, from which transport handed the row over.
// ---------------------------------------------------------------------

/// How a piece of evidence physically arrived, as determined by the
/// *receiving* process — never by anything the payload itself claims.
/// Deliberately not a field on [`Evidence`]: adding it there would make it
/// exactly the kind of untrusted, caller-supplied label this type exists to
/// not be. A future integration (`fornax-store`, FORNX-431 slice 2) stamps
/// this server-side at the moment a row is persisted, from the real
/// transport/call path, and is the only thing that may ever construct an
/// [`AdmissionContext`] carrying one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceOrigin {
    /// Arrived over the daemon's UDS ingest socket, as an
    /// `IngestMessage::Evidence` line — i.e. from a sensor process, subject
    /// to [`CollectorAuthority`]'s per-sensor allowlist.
    UdsIngest,
    /// Written by the daemon's own `/api/acquire-evidence` acquisition
    /// path. The daemon is the collector here, not an external sensor — a
    /// missing [`EvidenceSource`] is expected, not a quarantine reason.
    DaemonAcquisition,
    /// Written by a privileged, non-adapter executor process (e.g.
    /// `fornax-acquire-exec`) that this deployment has explicitly
    /// authorized to write evidence directly. Same trust posture as
    /// `DaemonAcquisition`: authorized by origin alone.
    PrivilegedExecutor,
    /// No receiving process stamped an origin for this row — either a
    /// legacy row written before this mechanism existed, or a row read
    /// back without going through the real admission path. Always
    /// quarantined: an unknown origin is never upgraded to trusted by
    /// anything the row itself says.
    Unknown,
}

impl EvidenceOrigin {
    /// The `evidence.ingress_origin` column value for this origin (FORNX-431
    /// slice 2's migration), as `fornax-store`'s `origin_from_column` parses
    /// it back. `Unknown` has no column representation of its own — it is
    /// the NULL/not-yet-stamped state, never a literal value a row could be
    /// written with, so storing one would be indistinguishable from a
    /// genuinely legacy row (which is the point: there is nothing a caller
    /// can do to assert "unknown" as if it were a real, determined origin).
    pub fn as_column_str(&self) -> Option<&'static str> {
        match self {
            EvidenceOrigin::UdsIngest => Some("uds_ingest"),
            EvidenceOrigin::DaemonAcquisition => Some("daemon_acquisition"),
            EvidenceOrigin::PrivilegedExecutor => Some("privileged_executor"),
            EvidenceOrigin::Unknown => None,
        }
    }
}

/// Who, if anyone, has announced themselves as the owning provider for a
/// session (via `runtime_capabilities`, i.e. a real `SessionStart`/
/// capability announcement — never guessed from a sensor-name prefix or
/// any other heuristic). Used to catch evidence whose claimed
/// `source.provider` doesn't match what the session itself has actually
/// announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionOwner {
    /// No provider has announced itself for this session yet. Never
    /// treated as "any provider is fine" — evidence citing a provider for
    /// an unclaimed session is exactly the kind of unverifiable claim this
    /// module exists to catch.
    Unknown,
    /// Exactly one provider has announced itself.
    Single(Provider),
    /// More than one provider has announced itself for the same session
    /// (e.g. two adapters racing, or a forged announcement). Fails closed:
    /// an ambiguous owner can never be used to *validate* a provider claim,
    /// only to reject one.
    Ambiguous,
}

/// AC1 (FORNX-431 extension)/AC4: the outcome of checking one piece of
/// evidence's origin and (for [`EvidenceOrigin::UdsIngest`]) its collector
/// identity, against `authority` and the claim's session owner. A
/// deliberately separate vocabulary from [`ProvenanceVerdict`] — that type
/// answers "is this *trust_class* claim vouched for"; this one answers "is
/// this row admissible at all, given how it arrived and who owns the
/// session it claims to belong to".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// Admissible: a trusted origin, and (for `UdsIngest`) a registered
    /// collector asserting a provider that matches the session's real
    /// owner (or the session has no announced owner yet, counted as
    /// consistent rather than contradictory — see
    /// [`admission_decision`]'s doc comment).
    Admitted,
    /// Not admissible. Carries the same `reason` discipline as
    /// [`ProvenanceVerdict::Quarantined`] — never silently dropped.
    Quarantined { reason: String },
}

/// Decide whether one piece of evidence is admissible for `claim`, given
/// how it arrived (`origin`) and who the claim's session has actually
/// announced as its owning provider (`owner`). This is the pure decision
/// function both the in-process guard and a future `fornax-store`
/// persistence layer (FORNX-431 slice 2) call, so the rule never drifts
/// between the two.
///
/// Deliberately permissive on `SessionOwner::Unknown`: a session with no
/// announced provider yet is not evidence of forgery, only of a session
/// that hasn't sent a capability announcement — the verifiers downstream
/// already return `Unavailable` for an unannounced session on their own
/// terms, so this function does not need to additionally fail it closed
/// here. `SessionOwner::Ambiguous` is the opposite: two or more real
/// announcements for one session is itself the anomaly, and is never used
/// to admit a provider match.
pub fn admission_decision(
    evidence: &Evidence,
    origin: EvidenceOrigin,
    authority: &CollectorAuthority,
    owner: SessionOwner,
) -> AdmissionVerdict {
    match origin {
        EvidenceOrigin::Unknown => AdmissionVerdict::Quarantined {
            reason: "evidence has no known ingress origin — never admitted on a payload's \
                     own say-so"
                .to_string(),
        },
        EvidenceOrigin::DaemonAcquisition | EvidenceOrigin::PrivilegedExecutor => {
            // Authorized by origin alone: the daemon/executor is the
            // collector here, so a missing `source` is expected, not a
            // quarantine reason — mirrors `CollectorAuthority`'s own
            // "authority is the trust anchor" principle, just anchored on
            // origin instead of a named sensor.
            AdmissionVerdict::Admitted
        }
        EvidenceOrigin::UdsIngest => {
            let Some(source) = &evidence.source else {
                return AdmissionVerdict::Quarantined {
                    reason: "uds-ingest evidence with no EvidenceSource cannot be vouched for"
                        .to_string(),
                };
            };
            if let ProvenanceVerdict::Quarantined { reason } =
                authorize_evidence_source(authority, source)
            {
                return AdmissionVerdict::Quarantined { reason };
            }
            match (source.provider, owner) {
                (_, SessionOwner::Unknown) => AdmissionVerdict::Admitted,
                (Some(claimed), SessionOwner::Single(real)) if claimed == real => {
                    AdmissionVerdict::Admitted
                }
                (Some(claimed), SessionOwner::Single(real)) => AdmissionVerdict::Quarantined {
                    reason: format!(
                        "evidence source claims provider {claimed:?}, but this session's \
                         announced owner is {real:?}"
                    ),
                },
                (None, SessionOwner::Single(_)) => AdmissionVerdict::Admitted,
                (_, SessionOwner::Ambiguous) => AdmissionVerdict::Quarantined {
                    reason: "session has ambiguous/conflicting provider announcements — \
                             cannot validate a provider claim against it"
                        .to_string(),
                },
            }
        }
    }
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
    /// Already recorded for a *different* claim, but that claim shares the
    /// same anchor (`claim.session_id` + `claim.source_event_id`) as the
    /// new one — e.g. one `AgentEvent` turn yielding two claims
    /// (`command_executed` and `command_success`) that legitimately cite
    /// the same evidence row. FORNX-431's "no blanket ban on one
    /// observation supporting legitimately related claims" — scoped to the
    /// *anchor*, not `Claim::subject`: subject is an open-ended, coarse
    /// free-text category ("test_result" etc.) many genuinely unrelated
    /// claims across different sessions/turns can share, so it is too weak
    /// a compatibility key on its own. A caller downgrades the new
    /// finding (e.g. to `Review`), never treats it as an unrelated
    /// contradiction.
    ReusedByRelatedClaim { originally_consumed_by: Uuid },
}

/// The identity of the "turn" a claim came from — `claim.session_id` plus
/// `claim.source_event_id`, i.e. literally the same `AgentEvent`. Two
/// claims sharing an anchor are claims minted from the same observed turn
/// (the retry/multi-claim-per-turn case); two claims with different
/// anchors are, per FORNX-380 fixture 10's own framing, "entirely unrelated
/// claims" even if they happen to share a `subject` string.
pub type ClaimAnchor = (String, Uuid);

/// `claim`'s anchor (see [`ClaimAnchor`]).
pub fn anchor_of(claim: &Claim) -> ClaimAnchor {
    (claim.session_id.clone(), claim.source_event_id)
}

/// The anchor-aware sibling of [`EvidenceConsumptionLedger::record_and_check`]
/// (which only ever distinguishes "same claim" from "any other claim").
/// This is the pure decision both an in-memory ledger and a future
/// `fornax-store` persisted ledger (FORNX-431 slice 2) call, so the
/// compatibility rule never drifts between the two. `existing` is the
/// current owner, if any: `(claim_id, anchor)` of whichever claim first
/// consumed this evidence row.
pub fn classify_consumption_by_anchor(
    existing: Option<(Uuid, ClaimAnchor)>,
    claim_id: Uuid,
    anchor: &ClaimAnchor,
) -> ReplayVerdict {
    match existing {
        None => ReplayVerdict::FreshlyRecorded,
        Some((owner_claim_id, _)) if owner_claim_id == claim_id => {
            ReplayVerdict::AlreadyConsumedBySameClaim
        }
        Some((owner_claim_id, owner_anchor)) if owner_anchor == *anchor => {
            ReplayVerdict::ReusedByRelatedClaim {
                originally_consumed_by: owner_claim_id,
            }
        }
        Some((owner_claim_id, _)) => ReplayVerdict::ReplayedAcrossClaims {
            originally_consumed_by: owner_claim_id,
        },
    }
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

    fn claim_with_anchor(session_id: &str, source_event_id: Uuid, subject: &str) -> Claim {
        let mut c = claim(session_id);
        c.source_event_id = source_event_id;
        c.subject = subject.to_string();
        c
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

    // --- FORNX-431: EvidenceOrigin / admission_decision -------------------

    #[test]
    fn unknown_origin_is_always_quarantined() {
        let ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::Unknown,
            &authority,
            SessionOwner::Unknown,
        );
        assert!(matches!(verdict, AdmissionVerdict::Quarantined { .. }));
    }

    #[test]
    fn daemon_acquisition_origin_is_admitted_without_a_source() {
        let mut ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        ev.source = None; // acquisition evidence never has one
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::DaemonAcquisition,
            &authority,
            SessionOwner::Unknown,
        );
        assert_eq!(verdict, AdmissionVerdict::Admitted);
    }

    #[test]
    fn privileged_executor_origin_is_admitted_without_a_source() {
        let mut ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        ev.source = None;
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::PrivilegedExecutor,
            &authority,
            SessionOwner::Unknown,
        );
        assert_eq!(verdict, AdmissionVerdict::Admitted);
    }

    #[test]
    fn uds_ingest_with_an_unregistered_sensor_is_quarantined() {
        let ev = evidence_with("s1", "totally_made_up_sensor", TrustClass::HostObserved);
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::UdsIngest,
            &authority,
            SessionOwner::Unknown,
        );
        assert!(matches!(verdict, AdmissionVerdict::Quarantined { .. }));
    }

    #[test]
    fn uds_ingest_forged_trust_class_label_is_quarantined() {
        // Same FORNX-380 fixture 11 exploit as authorize_evidence_source's
        // own test, routed through the full admission decision.
        let ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1", // only ever AgentAdjacent
            TrustClass::HostObserved,
        );
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::UdsIngest,
            &authority,
            SessionOwner::Unknown,
        );
        assert!(matches!(verdict, AdmissionVerdict::Quarantined { .. }));
    }

    #[test]
    fn uds_ingest_with_no_source_is_quarantined() {
        let mut ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        ev.source = None;
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::UdsIngest,
            &authority,
            SessionOwner::Unknown,
        );
        assert!(matches!(verdict, AdmissionVerdict::Quarantined { .. }));
    }

    #[test]
    fn provider_matching_the_sessions_single_announced_owner_is_admitted() {
        let ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::UdsIngest,
            &authority,
            SessionOwner::Single(Provider::ClaudeCode),
        );
        assert_eq!(verdict, AdmissionVerdict::Admitted);
    }

    #[test]
    fn provider_mismatching_the_sessions_single_announced_owner_is_quarantined() {
        let ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::UdsIngest,
            &authority,
            SessionOwner::Single(Provider::Codex),
        );
        assert!(matches!(verdict, AdmissionVerdict::Quarantined { .. }));
    }

    #[test]
    fn ambiguous_session_owner_never_admits_a_provider_claim() {
        let ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::UdsIngest,
            &authority,
            SessionOwner::Ambiguous,
        );
        assert!(matches!(verdict, AdmissionVerdict::Quarantined { .. }));
    }

    #[test]
    fn unannounced_session_owner_is_not_treated_as_forgery() {
        let ev = evidence_with(
            "s1",
            "claude_bash_exit_code_sensor_v1",
            TrustClass::AgentAdjacent,
        );
        let authority = CollectorAuthority::known_sensors();
        let verdict = admission_decision(
            &ev,
            EvidenceOrigin::UdsIngest,
            &authority,
            SessionOwner::Unknown,
        );
        assert_eq!(verdict, AdmissionVerdict::Admitted);
    }

    // --- FORNX-431: anchor-based related-claim reuse ----------------------

    #[test]
    fn same_claim_id_reconsumption_is_idempotent() {
        let claim_a = claim_with_anchor("s1", Uuid::new_v4(), "test_result");
        let anchor = anchor_of(&claim_a);
        let verdict =
            classify_consumption_by_anchor(Some((claim_a.id, anchor.clone())), claim_a.id, &anchor);
        assert_eq!(verdict, ReplayVerdict::AlreadyConsumedBySameClaim);
    }

    #[test]
    fn two_claims_from_the_same_turn_are_a_legitimate_related_reuse() {
        // One AgentEvent turn yielding two claims (e.g. command_executed +
        // command_success) — same session, same source_event_id, different
        // claim ids and even different subjects.
        let event_id = Uuid::new_v4();
        let claim_a = claim_with_anchor("s1", event_id, "command_executed");
        let claim_b = claim_with_anchor("s1", event_id, "command_success");
        let anchor_b = anchor_of(&claim_b);
        assert_eq!(anchor_of(&claim_a), anchor_b, "same turn => same anchor");

        let verdict = classify_consumption_by_anchor(
            Some((claim_a.id, anchor_b.clone())),
            claim_b.id,
            &anchor_b,
        );
        assert_eq!(
            verdict,
            ReplayVerdict::ReusedByRelatedClaim {
                originally_consumed_by: claim_a.id
            }
        );
    }

    #[test]
    fn two_unrelated_claims_sharing_a_subject_but_not_an_anchor_is_a_real_replay() {
        // fornx380-10's exact exploit, and the reason `subject` alone is
        // the wrong compatibility key: two different sessions/turns, same
        // free-text subject string ("test_result"), citing one row.
        let claim_a = claim_with_anchor("session-a", Uuid::new_v4(), "test_result");
        let claim_b = claim_with_anchor("session-b", Uuid::new_v4(), "test_result");
        let anchor_a = anchor_of(&claim_a);
        let anchor_b = anchor_of(&claim_b);
        assert_ne!(anchor_a, anchor_b, "different session => different anchor");

        let verdict =
            classify_consumption_by_anchor(Some((claim_a.id, anchor_a)), claim_b.id, &anchor_b);
        assert_eq!(
            verdict,
            ReplayVerdict::ReplayedAcrossClaims {
                originally_consumed_by: claim_a.id
            },
            "same subject, different anchor must still be a real replay, not a related reuse"
        );
    }

    #[test]
    fn a_fresh_anchor_with_no_prior_owner_is_freshly_recorded() {
        let claim_a = claim("s1");
        let anchor = anchor_of(&claim_a);
        let verdict = classify_consumption_by_anchor(None, claim_a.id, &anchor);
        assert_eq!(verdict, ReplayVerdict::FreshlyRecorded);
    }
}
