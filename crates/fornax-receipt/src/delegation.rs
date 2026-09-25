//! Proof-carrying delegation envelope (FORNX-384, parent epic FORNX-376 /
//! Stage 9). Extends FORNX-350's Integrity Receipt so a parent agent,
//! downstream agent, workflow engine, CI job, or human evaluating a
//! *delegated* task receives more than a prose "done" from the agent it
//! delegated to.
//!
//! **What this extends, never replaces.** [`crate::schema::IntegrityReceipt`]
//! already answers "what does this receipt prove about one claim/finding."
//! A [`DelegationEnvelope`] answers a different, higher-level question: did
//! the agent I delegated *this specific task* to actually satisfy the
//! obligations I delegated, using evidence I can independently verify,
//! within the scope and freshness window I authorized? It carries one or
//! more [`crate::schema::IntegrityReceipt`]s as its evidentiary backing; it
//! never duplicates their internals, and it never re-derives fusion/
//! satisfaction logic that [`fornax_verify::contract_satisfaction`] (FORNX-378)
//! already owns.
//!
//! **Its own closed vocabulary, never collapsed into another layer's.**
//! Mirrors [`crate::gate`]'s established discipline: [`fornax_types::Verdict`]
//! (what was observed), [`fornax_verify::decision::RecommendationAction`]
//! (what Fornax recommends), [`fornax_types::epistemic_contract::SatisfactionState`]
//! (whether one obligation was met), [`crate::gate::GateOutcome`] (whether
//! one receipt authorizes one pipeline step), and now [`DelegationOutcome`]
//! (whether *this delegated task* was fulfilled) are five distinct
//! vocabularies answering five distinct questions -- never conflated. A
//! consumer's policy decision over a delegation envelope reuses
//! [`crate::gate::GateOutcome`] itself (see [`evaluate_delegation_gate`])
//! rather than inventing a sixth accept/reject vocabulary for the same
//! underlying question "may this delegated result authorize what comes
//! next."
//!
//! **Tamper evidence.** [`DelegationEnvelope`]'s `Deserialize` impl recomputes
//! [`DelegationEnvelopeBody`]'s digest and rejects any hand-edited body --
//! the exact mechanism [`crate::schema::IntegrityReceipt`] already uses (AC3:
//! "tampered ... delegation is rejected/held with an explainable reason").
//!
//! **Independence across nesting (AC4).** [`merged_source_family_bases`]
//! deduplicates every embedded receipt's own `coverage.source_family_bases`
//! -- two delegation levels that both cite evidence from the same
//! underlying source family never manufacture more independent
//! corroboration than genuinely exists, the same discipline
//! `fornax_verify::contract_satisfaction::assess`'s own family-independence
//! hardening (FORNX-378) applies within a single assessment.
//!
//! **Redaction-safe by default (AC7).** Scope free text (permitted actions,
//! expected outputs) is fingerprinted, never carried raw, mirroring
//! [`crate::schema::ClaimRef::claim_text_fingerprint`]'s existing
//! discipline. Every embedded [`crate::schema::IntegrityReceipt`] is already
//! reference-only by FORNX-350's own AC3 guarantee, so embedding one adds no
//! new raw-payload surface.
//!
//! # Non-goals (inherited from FORNX-350/377/378)
//!
//! No new signing scheme -- this crate stays verification-only in
//! production (see [`crate::verify`]'s module docs); tamper-evidence here is
//! digest-only, the same as a bare (unsigned) [`crate::schema::IntegrityReceipt`].
//! No generic workflow engine, no authorization replacement, no claim that a
//! `Fulfilled` outcome is semantically true beyond the evidence its receipts
//! actually carry (Jira AC/Non-goals).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use fornax_types::epistemic_contract::{ClaimClassId, RequirementLevel, SatisfactionState};
use fornax_verify::contract_satisfaction::SatisfactionReport;
use fornax_verify::independence::FamilyBasis;

use crate::freshness::{assess_freshness_of, Freshness};
use crate::gate::GateOutcome;
use crate::schema::{short_fingerprint, IntegrityReceipt};

pub const DELEGATION_SCHEMA_VERSION: u32 = 1;

/// Fixed namespace for [`derive_envelope_id`] -- an arbitrary constant, the
/// same trick [`crate::schema`]'s `RECEIPT_ID_NAMESPACE` uses to get a
/// deterministic id without a second hashing scheme. Distinct bytes from
/// that constant so a receipt id and an envelope id can never collide by
/// construction even given identical input content.
const DELEGATION_ID_NAMESPACE: Uuid = Uuid::from_bytes([
    0x1c, 0x9f, 0x3d, 0x6a, 0x8b, 0x02, 0x4e, 0x77, 0xa1, 0x5c, 0x9d, 0x3e, 0x7f, 0x21, 0x6b, 0x94,
]);

/// What the delegated task actually accomplished, judged from the evidence
/// its receipts carry -- never inferred from the child agent's own prose
/// summary (AC2). Its own closed vocabulary; see module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationOutcome {
    /// Every `Required` obligation named by `scope.claim_class`'s contract
    /// is [`SatisfactionState::Satisfied`], and the assessment reached a
    /// definite overall verdict (not `Unknown`).
    Fulfilled,
    /// At least one `Required` obligation is not `Satisfied`, but a real,
    /// partial assessment exists -- never collapsed into `Fulfilled` (AC5:
    /// "partial completion ... cannot be represented as complete success").
    PartiallyFulfilled,
    /// The named obligations could not be assessed at all from the evidence
    /// provided (e.g. an unrecognized claim class, or the overall
    /// assessment came back [`SatisfactionState::Unknown`]) -- an
    /// evaluation problem, distinct from a child-reported one.
    Insufficient,
    /// The child agent itself reported it could not attempt or complete the
    /// delegated task at all (e.g. a required tool was unavailable, or it
    /// was blocked before producing any assessable result) -- distinct from
    /// `Insufficient`, which describes an evaluation problem rather than a
    /// child-reported one.
    Unavailable,
}

/// One participant in a delegation -- a parent or a child. `agent_id` is a
/// free-form, non-authenticating label (the same posture as
/// [`crate::schema::ReceiptBody::home_identity`]); this module has no
/// identity/authentication scheme of its own. `task_id` is the specific
/// delegated task's identifier, never a broader session id -- see
/// [`DelegationScope`]'s doc comment for why a receipt valid for one task
/// cannot authorize unrelated work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationIdentity {
    pub agent_id: String,
    pub task_id: Uuid,
}

/// What was delegated. `claim_class` binds this envelope to exactly one
/// [`fornax_types::epistemic_contract::ClaimContract`] (by name and
/// version) -- the delegated obligations are that contract's own
/// `EvidenceRequirement`s, referenced here, never re-listed or duplicated.
/// `permitted_actions_fingerprint`/`expected_outputs_fingerprint` are
/// [`short_fingerprint`]s of redacted free text, never the raw text itself
/// (AC7) -- a scope-mismatch check compares fingerprints, which is exactly
/// as discriminating as comparing the (never-carried) raw text would be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationScope {
    pub claim_class: ClaimClassId,
    pub permitted_actions_fingerprint: String,
    pub expected_outputs_fingerprint: String,
}

/// One ancestor this delegation was nested under -- named by digest and
/// identity only, never re-embedding that ancestor's own receipts/evidence
/// (scope item: "without duplicating raw protected evidence"). An empty
/// `lineage` means this is a root delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageEntry {
    pub parent_envelope_digest: String,
    pub parent_task_id: Uuid,
    pub depth: u32,
}

/// The delegation envelope's content. Field order is normative wire order,
/// mirroring [`crate::schema::ReceiptBody`]'s identical discipline --
/// `canonical_bytes` serializes with `serde_json::to_vec`, which preserves
/// declaration order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationEnvelopeBody {
    pub envelope_schema_version: u32,
    /// Deterministic -- see [`derive_envelope_id`]. Not a random UUID:
    /// re-issuing an envelope from byte-identical inputs at the same
    /// `issued_at` produces the same id.
    pub envelope_id: Uuid,
    pub issued_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    pub parent: DelegationIdentity,
    pub child: DelegationIdentity,
    pub scope: DelegationScope,
    pub outcome: DelegationOutcome,
    pub satisfaction_overall: SatisfactionState,
    /// Every `Required` requirement id from `scope.claim_class`'s contract
    /// that is not `Satisfied`/`NotApplicable` -- never omitted when
    /// `outcome` is anything but `Fulfilled` (AC5).
    pub unresolved_requirement_ids: Vec<String>,
    /// The evidentiary backing for `outcome`/`satisfaction_overall` --
    /// already reference-only, redaction-safe receipts (FORNX-350 AC3).
    /// Sorted by `receipt_id` for determinism.
    pub receipts: Vec<IntegrityReceipt>,
    /// Deduplicated, sorted union of every embedded receipt's own
    /// `coverage.source_family_bases` -- the aggregate independence picture
    /// a consumer must judge this delegation's evidence against (AC4). See
    /// [`merged_source_family_bases`].
    pub aggregate_source_family_bases: Vec<FamilyBasis>,
    /// Empty for a root delegation. See [`LineageEntry`].
    pub lineage: Vec<LineageEntry>,
}

/// Deterministic content bytes of `body` -- the input to [`digest_of`].
pub fn canonical_bytes(body: &DelegationEnvelopeBody) -> Vec<u8> {
    serde_json::to_vec(body).expect("DelegationEnvelopeBody serialization cannot fail")
}

fn full_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// A delegation envelope body's content digest. A distinct type from
/// [`crate::schema::ReceiptDigest`] even though the wire shape is identical
/// -- the two are never interchangeable, mirroring this crate's existing
/// per-layer-vocabulary discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationDigest(String);

impl DelegationDigest {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DelegationDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn digest_of(body: &DelegationEnvelopeBody) -> DelegationDigest {
    DelegationDigest(full_digest(&canonical_bytes(body)))
}

/// Deduplicated, sorted union of `receipts`' own
/// `coverage.source_family_bases` (AC4). Two receipts sharing a family
/// basis -- e.g. because a nested delegation cited evidence derived from
/// the same underlying agent turn at two different depths -- contribute
/// that basis only once here, so a downstream consumer never sees more
/// independent corroboration than genuinely exists.
pub fn merged_source_family_bases(receipts: &[IntegrityReceipt]) -> Vec<FamilyBasis> {
    let mut all: Vec<FamilyBasis> = receipts
        .iter()
        .flat_map(|r| r.body().coverage.source_family_bases.clone())
        .collect();
    all.sort();
    all.dedup();
    all
}

/// `Uuid::new_v5(DELEGATION_ID_NAMESPACE, sha256(canonical_bytes(body with envelope_id nil)))` --
/// deterministic given every other field, mirroring
/// [`crate::schema::ReceiptBody::derive_id`]'s identical technique.
fn derive_envelope_id(body: &DelegationEnvelopeBody) -> Uuid {
    let mut for_id = body.clone();
    for_id.envelope_id = Uuid::nil();
    let bytes = canonical_bytes(&for_id);
    let digest = Sha256::digest(&bytes);
    Uuid::new_v5(&DELEGATION_ID_NAMESPACE, &digest)
}

/// Wire form: body plus its own digest, deserialized together so the digest
/// can be recomputed and checked before [`DelegationEnvelope`] ever exists --
/// the exact shape [`crate::schema::IntegrityReceipt`]'s own
/// `IntegrityReceiptWire` uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DelegationEnvelopeWire {
    body: DelegationEnvelopeBody,
    digest: DelegationDigest,
}

/// A delegation envelope is malformed the instant its own declared digest
/// disagrees with a fresh recompute over its body -- this is
/// [`crate::schema::ReceiptDigestMismatch`]'s identical tamper detector,
/// applied here so a hand-edited body can never enter the type system via
/// `Deserialize` (AC3: tampered delegation is rejected with an explainable
/// reason).
#[derive(Debug, Clone, thiserror::Error)]
#[error("delegation envelope digest {declared} does not match recomputed digest {recomputed} -- body was altered after issuance")]
pub struct DelegationDigestMismatch {
    pub declared: String,
    pub recomputed: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DelegationEnvelopeWire")]
pub struct DelegationEnvelope {
    body: DelegationEnvelopeBody,
    digest: DelegationDigest,
}

impl DelegationEnvelope {
    pub fn body(&self) -> &DelegationEnvelopeBody {
        &self.body
    }

    pub fn digest(&self) -> &DelegationDigest {
        &self.digest
    }
}

impl TryFrom<DelegationEnvelopeWire> for DelegationEnvelope {
    type Error = DelegationDigestMismatch;

    fn try_from(wire: DelegationEnvelopeWire) -> Result<Self, Self::Error> {
        let recomputed = digest_of(&wire.body);
        if recomputed != wire.digest {
            return Err(DelegationDigestMismatch {
                declared: wire.digest.0,
                recomputed: recomputed.0,
            });
        }
        Ok(DelegationEnvelope {
            body: wire.body,
            digest: wire.digest,
        })
    }
}

/// Every input [`issue_delegation_envelope`] needs, already computed by the
/// caller -- this function performs no fusion/satisfaction computation
/// itself, only projection, mirroring [`crate::issue::issue_receipt`]'s
/// identical "pure projection" discipline.
pub struct DelegationInputs<'a> {
    pub parent: DelegationIdentity,
    pub child: DelegationIdentity,
    pub claim_class: ClaimClassId,
    /// Raw free text describing what actions were permitted -- redacted and
    /// fingerprinted by [`issue_delegation_envelope`], never carried raw
    /// into the envelope (AC7).
    pub permitted_actions_text: &'a str,
    /// Raw free text describing the expected output shape -- redacted and
    /// fingerprinted the same way.
    pub expected_outputs_text: &'a str,
    /// The real [`fornax_verify::contract_satisfaction::assess`] result for
    /// `claim_class` against the child's evidence -- this ticket never
    /// re-derives satisfaction, only reports it (AC2: "consumed without
    /// trusting the child's prose summary").
    pub assessment: &'a SatisfactionReport,
    /// The reference-only receipts backing `assessment` -- sorted by
    /// [`issue_delegation_envelope`] before being embedded.
    pub receipts: Vec<IntegrityReceipt>,
    pub lineage: Vec<LineageEntry>,
    /// `true` when the child agent itself reported it could not attempt the
    /// delegated task at all, distinguishing [`DelegationOutcome::Unavailable`]
    /// from an evaluable-but-unsatisfied result.
    pub child_reported_unavailable: bool,
}

/// Projects `inputs` into a [`DelegationEnvelope`], stamped `issued_at`.
/// `ttl_seconds` controls [`DelegationEnvelopeBody::not_after`]: `None`
/// leaves it unset (see [`crate::freshness`] for why an absent `not_after`
/// is its own, non-"fresh forever" state under the default gate policy).
pub fn issue_delegation_envelope(
    inputs: DelegationInputs<'_>,
    issued_at: &str,
    ttl_seconds: Option<i64>,
) -> DelegationEnvelope {
    let unresolved_requirement_ids: Vec<String> = inputs
        .assessment
        .assessment
        .per_requirement
        .iter()
        .filter(|ra| {
            matches!(ra.level, RequirementLevel::Required)
                && !matches!(
                    ra.state,
                    SatisfactionState::Satisfied | SatisfactionState::NotApplicable
                )
        })
        .map(|ra| ra.requirement_id.clone())
        .collect();

    let outcome = if inputs.child_reported_unavailable {
        DelegationOutcome::Unavailable
    } else {
        match inputs.assessment.assessment.overall {
            SatisfactionState::Unknown => DelegationOutcome::Insufficient,
            SatisfactionState::Satisfied if unresolved_requirement_ids.is_empty() => {
                DelegationOutcome::Fulfilled
            }
            _ => DelegationOutcome::PartiallyFulfilled,
        }
    };

    let mut receipts = inputs.receipts;
    receipts.sort_by_key(|r| r.body().receipt_id);

    let aggregate_source_family_bases = merged_source_family_bases(&receipts);

    let permitted_actions_fingerprint = short_fingerprint(
        fornax_types::redact::redact_text(inputs.permitted_actions_text).as_bytes(),
    );
    let expected_outputs_fingerprint = short_fingerprint(
        fornax_types::redact::redact_text(inputs.expected_outputs_text).as_bytes(),
    );

    let not_after = ttl_seconds.and_then(|ttl| {
        let issued: chrono::DateTime<chrono::Utc> = issued_at.parse().ok()?;
        Some((issued + chrono::Duration::seconds(ttl)).to_rfc3339())
    });

    let mut body = DelegationEnvelopeBody {
        envelope_schema_version: DELEGATION_SCHEMA_VERSION,
        envelope_id: Uuid::nil(),
        issued_at: issued_at.to_string(),
        not_after,
        parent: inputs.parent,
        child: inputs.child,
        scope: DelegationScope {
            claim_class: inputs.claim_class,
            permitted_actions_fingerprint,
            expected_outputs_fingerprint,
        },
        outcome,
        satisfaction_overall: inputs.assessment.assessment.overall.clone(),
        unresolved_requirement_ids,
        receipts,
        aggregate_source_family_bases,
        lineage: inputs.lineage,
    };
    body.envelope_id = derive_envelope_id(&body);
    let digest = digest_of(&body);

    DelegationEnvelope { body, digest }
}

/// Assesses a [`DelegationEnvelopeBody`]'s freshness against `now`. Reuses
/// [`assess_freshness_of`] -- the exact fail-closed expiry/clock-skew
/// reasoning [`crate::freshness::assess_freshness`] already applies to a
/// [`crate::schema::ReceiptBody`], generalized so this module never
/// re-derives it.
pub fn assess_delegation_freshness(
    body: &DelegationEnvelopeBody,
    now: chrono::DateTime<chrono::Utc>,
) -> Freshness {
    assess_freshness_of(&body.issued_at, body.not_after.as_deref(), now)
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DelegationRejection {
    #[error("artifact could not be parsed or verified as a delegation envelope: {detail}")]
    Invalid { detail: String },
}

/// Deserializes and tamper-verifies `bytes` as a [`DelegationEnvelope`] with
/// no access to the producing agent's own state -- the verification
/// library/API scope item, and the mechanism [`evaluate_delegation_gate`]'s
/// own end-to-end test exercises as an independent consumer (AC6).
pub fn verify_delegation_envelope_bytes(
    bytes: &[u8],
) -> Result<DelegationEnvelope, DelegationRejection> {
    serde_json::from_slice::<DelegationEnvelope>(bytes).map_err(|e| DelegationRejection::Invalid {
        detail: e.to_string(),
    })
}

/// What a consumer expects this delegation envelope to be *about* --
/// checked against the envelope's own declared `parent`/`scope` rather than
/// trusted from the envelope alone (AC3: "wrong-parent, wrong-scope ...
/// delegation is rejected/held").
pub struct ExpectedDelegationContext {
    pub parent_agent_id: String,
    pub parent_task_id: Uuid,
    pub expected_claim_class: ClaimClassId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationGateReasonCode {
    PolicyUncalibrated,
    WrongParent,
    /// Also covers a claim class this consumer does not recognize/support
    /// at all -- see module docs: a consumer names the one scope it is
    /// willing to accept via [`ExpectedDelegationContext`], and any
    /// mismatch (unrecognized or merely different) is "not what I asked
    /// for."
    WrongScope,
    ReceiptExpired,
    NoExpiryDeclared,
    IssuedInFuture,
    MalformedTimestamp,
    OutcomeNotAllowed,
    UnresolvedCriticalObligation,
    AllChecksSatisfied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationGateReason {
    pub code: DelegationGateReasonCode,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationGateDecision {
    pub outcome: GateOutcome,
    pub reasons: Vec<DelegationGateReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationGatePolicy {
    /// `false` resolves the whole gate to [`GateOutcome::Untested`] before
    /// any rule below is evaluated -- the same fail-closed empty-policy
    /// trap [`crate::gate::evaluate_receipt_gate`] guards against.
    pub calibrated: bool,
    pub policy_name: String,
    pub policy_version: u32,
    pub allowed_outcomes: Vec<DelegationOutcome>,
    pub require_expiry: bool,
}

impl DelegationGatePolicy {
    /// This module's own named default policy: "require Fulfilled and a
    /// declared expiry."
    pub fn require_fulfilled_only() -> Self {
        Self {
            calibrated: true,
            policy_name: "require_fulfilled_only".to_string(),
            policy_version: 1,
            allowed_outcomes: vec![DelegationOutcome::Fulfilled],
            require_expiry: true,
        }
    }
}

/// Evaluates `envelope` against `expected` and `policy` -- the "independent
/// consumer applies a policy decision" scope item (AC6). Never short-
/// circuits on the first failing check; every reason is collected and the
/// overall outcome is the worst of them, mirroring
/// [`crate::gate::evaluate_receipt_gate`]'s identical discipline.
pub fn evaluate_delegation_gate(
    envelope: &DelegationEnvelope,
    expected: &ExpectedDelegationContext,
    policy: &DelegationGatePolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> DelegationGateDecision {
    if !policy.calibrated || policy.allowed_outcomes.is_empty() {
        return DelegationGateDecision {
            outcome: GateOutcome::Untested,
            reasons: vec![DelegationGateReason {
                code: DelegationGateReasonCode::PolicyUncalibrated,
                detail: "delegation gate policy is not calibrated (or names no allowed \
                         outcomes) -- no threshold exists yet to judge this envelope against"
                    .to_string(),
            }],
        };
    }

    let mut reasons = Vec::new();
    let body = envelope.body();

    if body.parent.agent_id != expected.parent_agent_id
        || body.parent.task_id != expected.parent_task_id
    {
        reasons.push(DelegationGateReason {
            code: DelegationGateReasonCode::WrongParent,
            detail: format!(
                "envelope names parent {:?}/{}, expected {:?}/{}",
                body.parent.agent_id,
                body.parent.task_id,
                expected.parent_agent_id,
                expected.parent_task_id
            ),
        });
    }

    if body.scope.claim_class != expected.expected_claim_class {
        reasons.push(DelegationGateReason {
            code: DelegationGateReasonCode::WrongScope,
            detail: format!(
                "envelope scopes claim class {:?}, expected {:?}",
                body.scope.claim_class, expected.expected_claim_class
            ),
        });
    }

    match assess_delegation_freshness(body, now) {
        Freshness::Expired { not_after, now } => reasons.push(DelegationGateReason {
            code: DelegationGateReasonCode::ReceiptExpired,
            detail: format!("expired at {not_after}, now {now}"),
        }),
        Freshness::NoExpiryDeclared if policy.require_expiry => {
            reasons.push(DelegationGateReason {
                code: DelegationGateReasonCode::NoExpiryDeclared,
                detail: "policy requires a declared expiry; this envelope has none".to_string(),
            })
        }
        Freshness::IssuedInFuture { issued_at, now } => reasons.push(DelegationGateReason {
            code: DelegationGateReasonCode::IssuedInFuture,
            detail: format!("issued_at {issued_at} is after now {now}"),
        }),
        Freshness::MalformedTimestamp { field, value } => reasons.push(DelegationGateReason {
            code: DelegationGateReasonCode::MalformedTimestamp,
            detail: format!("{field} is malformed: {value:?}"),
        }),
        _ => {}
    }

    if !policy.allowed_outcomes.contains(&body.outcome) {
        reasons.push(DelegationGateReason {
            code: DelegationGateReasonCode::OutcomeNotAllowed,
            detail: format!(
                "outcome {:?} is not in the allowed set {:?}",
                body.outcome, policy.allowed_outcomes
            ),
        });
    }

    // Defensive: a consumer must never trust `outcome` alone. Even a
    // hand-crafted (but digest-consistent, i.e. self-issued) envelope
    // claiming `Fulfilled` while still naming unresolved requirements is
    // rejected here -- AC5's "cannot be represented as complete success"
    // applies at the consumer, not just at issuance.
    if !body.unresolved_requirement_ids.is_empty()
        && matches!(body.outcome, DelegationOutcome::Fulfilled)
    {
        reasons.push(DelegationGateReason {
            code: DelegationGateReasonCode::UnresolvedCriticalObligation,
            detail: format!(
                "outcome is Fulfilled but {} requirement(s) remain unresolved: {:?}",
                body.unresolved_requirement_ids.len(),
                body.unresolved_requirement_ids
            ),
        });
    }

    if reasons.is_empty() {
        return DelegationGateDecision {
            outcome: GateOutcome::Accept,
            reasons: vec![DelegationGateReason {
                code: DelegationGateReasonCode::AllChecksSatisfied,
                detail: format!("all checks satisfied under policy {:?}", policy.policy_name),
            }],
        };
    }

    let worst = reasons
        .iter()
        .map(|r| outcome_of(&r.code))
        .max_by_key(|o| gate_outcome_severity(*o))
        .unwrap_or(GateOutcome::Reject);

    DelegationGateDecision {
        outcome: worst,
        reasons,
    }
}

fn gate_outcome_severity(outcome: GateOutcome) -> u8 {
    match outcome {
        GateOutcome::Accept => 0,
        GateOutcome::Untested => 1,
        GateOutcome::Hold => 2,
        GateOutcome::Reject => 3,
    }
}

fn outcome_of(code: &DelegationGateReasonCode) -> GateOutcome {
    match code {
        DelegationGateReasonCode::NoExpiryDeclared => GateOutcome::Hold,
        DelegationGateReasonCode::AllChecksSatisfied
        | DelegationGateReasonCode::PolicyUncalibrated => {
            unreachable!("handled by their own early-return branches")
        }
        _ => GateOutcome::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::sensor::{CollectionMethod, EvidenceSource, TrustClass};
    use fornax_types::{
        Claim, Evidence, EvidenceGraph, EvidenceKind, EvidenceLink, EvidenceRelation,
    };
    use fornax_verify::calibration::{CalibrationAssessment, CalibrationState};
    use fornax_verify::contract_satisfaction::default_registry;
    use fornax_verify::decision::{Recommendation, RecommendationAction, RiskClass};
    use fornax_verify::fusion::{FusedFinding, UncertaintyBand};
    use fornax_verify::independence::SourceFamilyMap;

    fn claim(subject: &str) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "session-1".to_string(),
            source_event_id: Uuid::new_v4(),
            text: format!("claim about {subject}"),
            subject: subject.to_string(),
            claimed_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    fn evidence(kind: EvidenceKind, trust: TrustClass) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "session-1".to_string(),
            source_event_id: Uuid::new_v4(),
            kind,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            payload: serde_json::json!({"exit_code": 0}),
            provenance: "test".to_string(),
            source: Some(EvidenceSource {
                sensor_name: "test_sensor".to_string(),
                trust_class: trust,
                collected_at: "2026-01-01T00:00:00Z".to_string(),
                provider: None,
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

    fn provenance() -> fornax_types::calibration::CalibrationProvenance {
        fornax_types::calibration::CalibrationProvenance {
            schema_version: 1,
            provider: "claude_code".into(),
            adapter_version: None,
            capability_schema_version: 1,
            capability_fingerprint: vec![],
            fusion_policy_name: "baseline".into(),
            fusion_policy_version: 2,
            decision_policy_name: "default".into(),
            decision_policy_version: 1,
            reliability_policy_version: 1,
            disabled_sensors: vec![],
            active_policy_revision_digest: None,
            model_version: None,
            model_family: None,
        }
    }

    fn calibration() -> CalibrationAssessment {
        CalibrationAssessment {
            state: CalibrationState::NoActiveCalibration,
            policy_version: 1,
        }
    }

    /// Issues one real reference-only receipt for `c`/`evs`, projecting a
    /// `Verified`/`Proceed` finding regardless of the actual satisfaction
    /// result -- the receipt records what evidence exists, independent of
    /// what a contract concludes about it. Mirrors
    /// `crate::issue`'s own test fixtures.
    fn issue_one_receipt(c: &Claim, evs: &[Evidence]) -> IntegrityReceipt {
        let links: Vec<EvidenceLink> = evs
            .iter()
            .map(|e| EvidenceLink {
                id: Uuid::new_v4(),
                session_id: c.session_id.clone(),
                claim_id: c.id,
                evidence_id: e.id,
                relation: EvidenceRelation::Supports,
                linked_at: "2026-01-01T00:00:00Z".to_string(),
            })
            .collect();
        let graph = EvidenceGraph {
            links,
            missing: vec![],
        };
        let fused = FusedFinding {
            claim_id: c.id,
            verdict: fornax_types::Verdict::Verified,
            uncertainty: UncertaintyBand::Qualified,
            rationale: vec![],
            counted_link_ids: evs.iter().map(|e| e.id).collect(),
            discounted_link_ids: vec![],
            missing_evidence_ids: vec![],
            unresolved_conflict: false,
            policy_name: "baseline".to_string(),
            policy_version: 2,
            computed_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let rec = Recommendation {
            claim_id: c.id,
            action: RecommendationAction::Proceed,
            risk_class: RiskClass::Balanced,
            policy_name: "default".to_string(),
            policy_version: 1,
            rationale_summary: "ok".to_string(),
        };
        let families = SourceFamilyMap::build(evs);
        let prov = provenance();
        let cal = calibration();
        let inputs = crate::issue::ReceiptInputs {
            claim: c,
            graph: &graph,
            evidence: evs,
            fused: &fused,
            recommendation: &rec,
            gaps: &[],
            families: &families,
            provenance: &prov,
            calibration: &cal,
            issuer: "fornax-cli/delegation-issue/v1",
            home_identity: "abcd1234",
        };
        crate::issue::issue_receipt(&inputs, "2026-01-01T00:00:00Z", None)
            .expect("well-formed test inputs always issue")
    }

    fn base_inputs<'a>(
        assessment: &'a SatisfactionReport,
        receipts: Vec<IntegrityReceipt>,
    ) -> DelegationInputs<'a> {
        DelegationInputs {
            parent: DelegationIdentity {
                agent_id: "agent-a".to_string(),
                task_id: Uuid::from_u128(1),
            },
            child: DelegationIdentity {
                agent_id: "agent-b".to_string(),
                task_id: Uuid::from_u128(2),
            },
            claim_class: ClaimClassId::new("tests_passed", 1),
            permitted_actions_text: "run the test suite and report the result",
            expected_outputs_text: "a pass/fail verdict with evidence",
            assessment,
            receipts,
            lineage: vec![],
            child_reported_unavailable: false,
        }
    }

    // --- AC1: envelope binds identity, scope, authority, obligations,
    // result, evidence and versions explicitly ---------------------------

    #[test]
    fn issuing_the_same_delegation_twice_is_byte_identical() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);

        let a = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt.clone()]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );
        let b = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );
        assert_eq!(
            canonical_bytes(a.body()),
            canonical_bytes(b.body()),
            "byte-identical inputs must issue a byte-identical envelope"
        );
        assert_eq!(a.body().envelope_id, b.body().envelope_id);
    }

    #[test]
    fn envelope_names_claim_class_parent_child_and_versions_explicitly() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt]),
            "2026-01-01T00:00:00Z",
            None,
        );
        assert_eq!(env.body().parent.agent_id, "agent-a");
        assert_eq!(env.body().child.agent_id, "agent-b");
        assert_eq!(
            env.body().scope.claim_class,
            ClaimClassId::new("tests_passed", 1)
        );
        assert_eq!(
            env.body().envelope_schema_version,
            DELEGATION_SCHEMA_VERSION
        );
    }

    // --- AC2: a valid child result can be consumed without trusting the
    // child's prose summary ------------------------------------------------

    #[test]
    fn outcome_is_derived_from_the_real_assessment_never_from_a_prose_flag() {
        // No evidence at all -- a real `tests_passed` assessment must not
        // reach `Satisfied`, regardless of what the child *claims*.
        let c = claim("tests_passed");
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(&registry, &cc, &c, &[], &[])
            .expect("assess ok");
        assert_ne!(assessment.assessment.overall, SatisfactionState::Satisfied);

        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![]),
            "2026-01-01T00:00:00Z",
            None,
        );
        assert_ne!(
            env.body().outcome,
            DelegationOutcome::Fulfilled,
            "an empty-evidence assessment must never issue as Fulfilled, no matter what a \
             child's own prose summary might claim"
        );
    }

    // --- AC3: stale, tampered, wrong-parent, wrong-scope or unsupported
    // delegation is rejected/held with an explainable reason ---------------

    #[test]
    fn a_hand_edited_envelope_fails_the_digest_check_on_deserialize() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );

        let json = serde_json::to_string(&env).unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        // This scenario's real outcome is already `fulfilled` (one valid
        // observation satisfies `tests_passed`); tamper with the parent
        // identity instead, so the edit is guaranteed to actually change
        // the content and not silently no-op.
        value["body"]["parent"]["agent_id"] = serde_json::json!("attacker-controlled-agent");
        let tampered = serde_json::to_vec(&value).unwrap();

        let result = verify_delegation_envelope_bytes(&tampered);
        assert!(
            result.is_err(),
            "a hand-edited envelope must fail verification"
        );
    }

    #[test]
    fn wrong_parent_is_rejected() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );

        let expected = ExpectedDelegationContext {
            parent_agent_id: "someone-else".to_string(),
            parent_task_id: Uuid::from_u128(1),
            expected_claim_class: ClaimClassId::new("tests_passed", 1),
        };
        let decision = evaluate_delegation_gate(
            &env,
            &expected,
            &DelegationGatePolicy::require_fulfilled_only(),
            "2026-01-01T00:00:00Z".parse().unwrap(),
        );
        assert_eq!(decision.outcome, GateOutcome::Reject);
        assert!(decision
            .reasons
            .iter()
            .any(|r| r.code == DelegationGateReasonCode::WrongParent));
    }

    #[test]
    fn wrong_scope_claim_class_is_rejected() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );

        let expected = ExpectedDelegationContext {
            parent_agent_id: "agent-a".to_string(),
            parent_task_id: Uuid::from_u128(1),
            expected_claim_class: ClaimClassId::new("build_succeeded", 1),
        };
        let decision = evaluate_delegation_gate(
            &env,
            &expected,
            &DelegationGatePolicy::require_fulfilled_only(),
            "2026-01-01T00:00:00Z".parse().unwrap(),
        );
        assert_eq!(decision.outcome, GateOutcome::Reject);
        assert!(decision
            .reasons
            .iter()
            .any(|r| r.code == DelegationGateReasonCode::WrongScope));
    }

    #[test]
    fn an_expired_envelope_is_rejected() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );

        let expected = ExpectedDelegationContext {
            parent_agent_id: "agent-a".to_string(),
            parent_task_id: Uuid::from_u128(1),
            expected_claim_class: ClaimClassId::new("tests_passed", 1),
        };
        let decision = evaluate_delegation_gate(
            &env,
            &expected,
            &DelegationGatePolicy::require_fulfilled_only(),
            "2026-01-03T00:00:00Z".parse().unwrap(), // long past the 1-hour TTL
        );
        assert_eq!(decision.outcome, GateOutcome::Reject);
        assert!(decision
            .reasons
            .iter()
            .any(|r| r.code == DelegationGateReasonCode::ReceiptExpired));
    }

    // --- AC4: nested delegation preserves lineage and does not transform
    // derived/model-authored evidence into independent evidence -----------

    #[test]
    fn overlapping_source_families_across_receipts_are_never_double_counted() {
        let mut e1 = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let mut e2 = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        // Same correlation_group -- both evidence items belong to the same
        // underlying source family, simulating two delegation levels citing
        // evidence from the same real observation.
        e1.source.as_mut().unwrap().correlation_group = Some(Uuid::from_u128(42));
        e2.source.as_mut().unwrap().correlation_group = Some(Uuid::from_u128(42));

        let c1 = claim("tests_passed");
        let c2 = claim("tests_passed");
        let receipt_1 = issue_one_receipt(&c1, &[e1]);
        let receipt_2 = issue_one_receipt(&c2, &[e2]);

        let merged = merged_source_family_bases(&[receipt_1, receipt_2]);
        let concatenated_len: usize = merged.len();
        // Whatever the real family-basis count is for one receipt, two
        // receipts sharing the same correlation group must not double it --
        // the merged set is deduplicated, not concatenated.
        let single = merged_source_family_bases(&[issue_one_receipt(&claim("tests_passed"), &{
            let mut e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
            e.source.as_mut().unwrap().correlation_group = Some(Uuid::from_u128(42));
            vec![e]
        })]);
        assert_eq!(
            concatenated_len,
            single.len(),
            "two receipts sharing one source family must merge to the same family-basis \
             count as a single receipt citing it once -- nesting must never manufacture \
             independence"
        );
    }

    #[test]
    fn lineage_entries_never_embed_ancestor_evidence() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let mut inputs = base_inputs(&assessment, vec![receipt]);
        inputs.lineage = vec![LineageEntry {
            parent_envelope_digest: "sha256:deadbeef".to_string(),
            parent_task_id: Uuid::from_u128(999),
            depth: 1,
        }];
        let env = issue_delegation_envelope(inputs, "2026-01-01T00:00:00Z", None);
        assert_eq!(env.body().lineage.len(), 1);
        // A lineage entry is a name/digest reference, never a receipt --
        // this is enforced by `LineageEntry`'s own type, which has no
        // evidence-carrying field at all.
        let json = serde_json::to_value(&env.body().lineage).unwrap();
        assert!(json.to_string().contains("sha256:deadbeef"));
        assert!(!json.to_string().contains("evidence_id"));
    }

    // --- AC5: partial completion and unresolved critical gaps cannot be
    // represented as complete success ---------------------------------------

    #[test]
    fn partially_fulfilled_never_gates_to_accept_under_require_fulfilled_only() {
        let c = claim("tests_passed");
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        // No evidence -> genuinely unsatisfied/unresolved obligations.
        let assessment = fornax_verify::contract_satisfaction::assess(&registry, &cc, &c, &[], &[])
            .expect("assess ok");
        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );
        assert_ne!(env.body().outcome, DelegationOutcome::Fulfilled);

        let expected = ExpectedDelegationContext {
            parent_agent_id: "agent-a".to_string(),
            parent_task_id: Uuid::from_u128(1),
            expected_claim_class: ClaimClassId::new("tests_passed", 1),
        };
        let decision = evaluate_delegation_gate(
            &env,
            &expected,
            &DelegationGatePolicy::require_fulfilled_only(),
            "2026-01-01T00:00:00Z".parse().unwrap(),
        );
        assert_ne!(
            decision.outcome,
            GateOutcome::Accept,
            "a non-Fulfilled outcome must never gate to Accept under a policy that requires \
             Fulfilled: {decision:?}"
        );
    }

    #[test]
    fn a_hand_crafted_fulfilled_claim_with_unresolved_requirements_is_still_rejected() {
        // Defensive test for the gate's own belt-and-suspenders check: even
        // if `outcome` were (incorrectly) `Fulfilled` while
        // `unresolved_requirement_ids` is non-empty, the gate itself must
        // catch it rather than trusting the flag.
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );
        let mut body = env.body().clone();
        body.outcome = DelegationOutcome::Fulfilled;
        body.unresolved_requirement_ids = vec!["some_requirement".to_string()];
        let digest = digest_of(&body);
        let tampered_json =
            serde_json::to_value(DelegationEnvelopeWireTest { body, digest }).unwrap();
        let bytes = serde_json::to_vec(&tampered_json).unwrap();
        let reconstructed = verify_delegation_envelope_bytes(&bytes)
            .expect("digest is internally consistent, so this parses");

        let expected = ExpectedDelegationContext {
            parent_agent_id: "agent-a".to_string(),
            parent_task_id: Uuid::from_u128(1),
            expected_claim_class: ClaimClassId::new("tests_passed", 1),
        };
        let decision = evaluate_delegation_gate(
            &reconstructed,
            &expected,
            &DelegationGatePolicy::require_fulfilled_only(),
            "2026-01-01T00:00:00Z".parse().unwrap(),
        );
        assert_eq!(decision.outcome, GateOutcome::Reject);
        assert!(decision
            .reasons
            .iter()
            .any(|r| r.code == DelegationGateReasonCode::UnresolvedCriticalObligation));
    }

    /// Test-only mirror of the private `DelegationEnvelopeWire` so the test
    /// above can construct a digest-consistent (but semantically
    /// inconsistent) envelope without reaching into this module's private
    /// items from outside `mod tests`.
    #[derive(Serialize)]
    struct DelegationEnvelopeWireTest {
        body: DelegationEnvelopeBody,
        digest: DelegationDigest,
    }

    // --- AC6: at least one independent consumer verifies the envelope and
    // applies a policy decision ---------------------------------------------

    #[test]
    fn an_independent_consumer_with_only_serialized_bytes_verifies_and_gates() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![receipt]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );
        let bytes = serde_json::to_vec(&env).unwrap();

        // The "consumer" from here on has no access to `assessment`,
        // `registry`, or any producing-agent state -- only the bytes.
        let reconstructed =
            verify_delegation_envelope_bytes(&bytes).expect("valid envelope bytes verify");
        let expected = ExpectedDelegationContext {
            parent_agent_id: "agent-a".to_string(),
            parent_task_id: Uuid::from_u128(1),
            expected_claim_class: ClaimClassId::new("tests_passed", 1),
        };
        let decision = evaluate_delegation_gate(
            &reconstructed,
            &expected,
            &DelegationGatePolicy::require_fulfilled_only(),
            "2026-01-01T00:00:00Z".parse().unwrap(),
        );
        // This particular envelope's assessment is genuinely Satisfied
        // (one ExitCode + HostObserved observation matches `tests_passed`'s
        // representative contract), so the independent consumer accepts it.
        assert_eq!(decision.outcome, GateOutcome::Accept, "{decision:?}");
    }

    // --- AC7: raw source/prompt/tool payload remains local; envelope is
    // redaction-safe by default ----------------------------------------------

    #[test]
    fn no_raw_scope_text_appears_anywhere_in_the_serialized_envelope() {
        let c = claim("tests_passed");
        let e = evidence(EvidenceKind::ExitCode, TrustClass::HostObserved);
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(
            &registry,
            &cc,
            &c,
            std::slice::from_ref(&e),
            &[],
        )
        .expect("assess ok");
        let receipt = issue_one_receipt(&c, &[e]);
        let mut inputs = base_inputs(&assessment, vec![receipt]);
        inputs.permitted_actions_text = "run `rm -rf /home/user/secret-project` if needed";
        inputs.expected_outputs_text = "a report containing api_key=SUPER-SECRET-TOKEN";
        let env = issue_delegation_envelope(inputs, "2026-01-01T00:00:00Z", None);
        let json = serde_json::to_string(&env).unwrap();
        assert!(
            !json.contains("secret-project") && !json.contains("SUPER-SECRET-TOKEN"),
            "raw scope free text must never appear in the serialized envelope: {json}"
        );
        assert!(!env.body().scope.permitted_actions_fingerprint.is_empty());
        assert!(!env.body().scope.expected_outputs_fingerprint.is_empty());
    }

    // --- Real end-to-end flow: Agent A delegates to Agent B, and holds an
    // insufficient result (the ticket's headline scope item) ----------------

    #[test]
    fn agent_a_delegates_to_agent_b_and_holds_an_insufficient_result_end_to_end() {
        // Agent A delegates a `tests_passed` claim to Agent B, but Agent B's
        // evidence collection genuinely failed to produce anything -- Agent
        // B is free to *say* it passed in its own prose, but this envelope
        // never carries that prose, only the real assessment.
        let c = claim("tests_passed");
        let registry = default_registry();
        let cc = ClaimClassId::new("tests_passed", 1);
        let assessment = fornax_verify::contract_satisfaction::assess(&registry, &cc, &c, &[], &[])
            .expect("assess ok");
        assert_ne!(
            assessment.assessment.overall,
            SatisfactionState::Satisfied,
            "precondition: this scenario must be a genuine failure to satisfy, not a stubbed one"
        );

        let env = issue_delegation_envelope(
            base_inputs(&assessment, vec![]),
            "2026-01-01T00:00:00Z",
            Some(3600),
        );
        let bytes = serde_json::to_vec(&env).unwrap();

        // Agent A's consumer, working from bytes alone:
        let reconstructed = verify_delegation_envelope_bytes(&bytes).expect("valid bytes verify");
        let expected = ExpectedDelegationContext {
            parent_agent_id: "agent-a".to_string(),
            parent_task_id: Uuid::from_u128(1),
            expected_claim_class: ClaimClassId::new("tests_passed", 1),
        };
        let decision = evaluate_delegation_gate(
            &reconstructed,
            &expected,
            &DelegationGatePolicy::require_fulfilled_only(),
            "2026-01-01T00:00:00Z".parse().unwrap(),
        );
        assert_ne!(
            decision.outcome,
            GateOutcome::Accept,
            "Agent A must never authorize downstream work on an insufficient delegated result: \
             {decision:?}"
        );
    }
}
