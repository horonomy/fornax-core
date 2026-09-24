//! Canonical Fornax domain types (FORNX-24).
//!
//! Provider-native Claude Code / Codex events are thin adapter inputs; core
//! code (verifiers, storage, status/detail/dashboard) consumes only these
//! normalized concepts. Evidence must preserve provenance. Missing signals
//! are represented explicitly as `Unavailable`, never inferred or dropped.
//!
//! Grounded in observed payload shapes (see docs/research/adapter-capability-matrix.md):
//! Claude Code hook stdin JSON carries `session_id`, `transcript_path`, `cwd`,
//! `hook_event_name`, plus event-specific `tool_name`/`tool_input`/`tool_response`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod adapter;
pub mod audit;
pub mod audit_checkpoint;
pub mod capabilities;
pub mod causal;
pub mod experiment;
pub mod extension;
pub mod graph;
pub mod policy;
pub mod privacy;
pub mod redact;
pub mod reliability_context;
pub mod sensor;
pub mod sensor_config;

pub use adapter::{AgentAdapter, NormalizationOutcome};
pub use audit::{
    validate_audit_event, AuditAction, AuditActor, AuditEvent, AuditEventRejection,
    AuditExportClass, AuditOutcome, AuditRef, AuditRefParseError, AuditTarget,
    AUDIT_SCHEMA_VERSION, SUPPORTED_AUDIT_SCHEMA_VERSIONS,
};
pub use audit_checkpoint::{
    divergence_kind_wire, verify_audit_checkpoint, AuditCheckpointPayload, AuditCheckpointRequest,
    CheckpointRejection, DeviceReportedChainStatus, LedgerHead, PrevCheckpoint,
    SignedAuditCheckpoint, VerifiedAuditCheckpoint, AUDIT_CHECKPOINT_SCHEMA_VERSION,
    AUDIT_CHECKPOINT_SIGNING_DOMAIN, SUPPORTED_CHECKPOINT_SCHEMA_VERSIONS,
};
pub use capabilities::{
    CapabilityProbe, CapabilitySignal, LegacyCapabilitiesWire, RuntimeCapabilities,
    SignalAvailability, SignalClass, CAPABILITY_SCHEMA_VERSION,
};
pub use causal::{
    causal_evidence_from_experiment_result, CausalEvidenceLink, CausalExperimentEvidence,
    EvidenceProvenanceClass, InterventionalProvenance,
};
pub use experiment::{
    Baseline, CompletedExperiment, ExpectedObservation, ExperimentKind, ExperimentOutcome,
    ExperimentProvenance, ExperimentResult, ExperimentSpec, Hypothesis, Intervention,
    SideEffectAllowList, SideEffectClass, StopCondition, EXPERIMENT_SCHEMA_VERSION,
    SUPPORTED_EXPERIMENT_SCHEMA_VERSIONS,
};
pub use extension::{
    ContentClass, ExtensionEnvelope, EXTENSION_SCHEMA_VERSION, SUPPORTED_EXTENSION_SCHEMA_VERSIONS,
};
pub use graph::{
    staleness_of, staleness_of_default, EvidenceConflict, EvidenceGraph, EvidenceLink,
    EvidenceRelation, FreshnessWindow, MissingEvidence, StalenessAssessment,
    DEFAULT_EXIT_CODE_FRESHNESS_SECONDS,
};
pub use policy::{
    classify_action_class, compute_posture, effective_outcome, evaluate_activation,
    evaluate_revocation_ingest, freshness, member_freshness, resolve, resolve_trust_store,
    staleness_floor, verify_bundle, verify_revocation_list, ActionClass, ActivationDecision,
    ActivationOutcome, ActivationRejection, BoundRevision, BundleRejection, CacheGeneration,
    CacheScope, CacheSlotKind, CachedBundleRef, CollectionScope, DeviceContext, DiagnosticCode,
    DiagnosticSeverity, EffectivePolicy, EgressContentClass, EgressScope, EnforcementOutcome,
    EnforcementRule, EnforcementScope, FieldProvenance, FreshnessTier, KeyId, MemberFreshness,
    OsFamily, PayloadDigest, PolicyBinding, PolicyCacheState, PolicyContent,
    PolicyDegradationReason, PolicyDiagnostic, PolicyDraft, PolicyFieldId, PolicyFreshness,
    PolicyId, PolicyPosture, PolicyRevisionBody, PolicyRevisionRef, PolicyValidationReport,
    PublishedPolicyRevision, RedactionProfile, ResolvedPolicy, ResolvedValues, RevisionDigest,
    RevocationEntry, RevocationHit, RevocationHitMeta, RevocationIngestDecision,
    RevocationIngestRejection, RevocationPayload, RevocationRejection, RevocationSet,
    RevocationTarget, RiskClass, RiskClassSeconds, RiskClassTiers, SensorScope, SequenceHighWater,
    SignedRevocationList, TargetLevel, TargetScope, TargetSelector, TrustedVerificationKeys,
    VerdictOutcomes, VerifiedPolicyBundle, VerifiedRevocationList, MAX_REVOCATION_ENTRIES,
    POLICY_CACHE_SCHEMA_VERSION, POLICY_SCHEMA_VERSION, REVOCATION_SCHEMA_VERSION,
    REVOCATION_SIGNING_DOMAIN, SUPPORTED_POLICY_SCHEMA_VERSIONS,
    SUPPORTED_REVOCATION_SCHEMA_VERSIONS,
};
pub use reliability_context::{
    aggregate_context, capability_fingerprint, cohort_id_for, evaluate_sample_support,
    CohortIdentity, DatasetLineageTag, ModelFamily, RawReliabilityContext, RawRepositoryContext,
    ReliabilityContextKey, RepositoryClass, RetentionClass, SampleSupport, TaskClass, TenantRef,
    ToolClass, MINIMUM_COHORT_SAMPLE_SUPPORT, RELIABILITY_CONTEXT_SCHEMA_VERSION,
};
pub use sensor::{
    collect_with_disable_check, ClockSource, CollectionMethod, EvidenceSensor, EvidenceSource,
    Freshness, SensorOutcome, TamperBoundary, TrustClass,
};
pub use sensor_config::{default_fornax_home, SensorConfigError, SensorDisableConfig};

/// Which coding-agent runtime an event/capability originated from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    ClaudeCode,
    Codex,
    OpenCode,
    /// No adapter has announced itself for this session yet. This is a
    /// local, in-process placeholder only (FORNX-288) — it must never be
    /// persisted via `upsert_capabilities` or exported to `fornax-cloud`'s
    /// separate, closed ingest enum, which does not know this variant.
    /// `default_unknown_caps()` is the only producer of this value.
    Unknown,
}

/// Normalized lifecycle event kind. One variant per canonical concept a
/// provider *might* expose; a provider that doesn't expose a given kind
/// simply never emits it (see `RuntimeCapabilities`), it is not synthesized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    SessionStart,
    SessionEnd,
    UserPromptSubmit,
    PreToolUse,
    PostToolUse,
    SubagentStart,
    SubagentStop,
    Notification,
}

/// An immutable, provider-normalized observation. Persisted verbatim
/// (including `raw`) before any claim/verification logic runs, so sessions
/// can be replayed against future verifiers/calibration (FORNX-49).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub id: Uuid,
    pub session_id: String,
    pub provider: Provider,
    pub kind: EventKind,
    /// RFC3339 timestamp this event was observed locally (not provider time).
    pub observed_at: String,
    pub tool_name: Option<String>,
    pub tool_input: Option<serde_json::Value>,
    /// Provider's own serialized result for the tool call, when the provider
    /// exposes one (e.g. Claude Code's PostToolUse `tool_response`). This is
    /// the provider's summarized view, not a guaranteed raw capture.
    pub tool_response: Option<serde_json::Value>,
    /// Full untouched provider payload for this event, for replay/debugging.
    pub raw: serde_json::Value,
}

/// A natural-language or structured assertion extracted from agent output
/// (e.g. "All tests passed"). Claims are hypotheses to check, not facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub id: Uuid,
    pub session_id: String,
    pub source_event_id: Uuid,
    pub text: String,
    /// Coarse claim category a verifier can match on, e.g. "test_result",
    /// "file_written", "command_succeeded". Open-ended by design (string, not
    /// enum) until enough verifier families exist to justify closing it.
    pub subject: String,
    pub claimed_at: String,
}

/// Evidence kind — what was directly observed, independent of any claim.
///
/// **Closed on purpose — do not add a variant.** `fornax-cloud` (a separate
/// repo) mirrors this enum as a closed enum with no catch-all in
/// `crates/fornax-uploader/src/types.rs` and `crates/fornax-ingest/src/types.rs`.
/// Adding a new variant here would silently break cloud ingestion for it (a
/// coordinated two-repo change). A new evidence shape must instead widen an
/// existing variant's canonical payload struct (see e.g.
/// [`ProcessObservationPayload`]'s `observation` field, added FORNX-14) —
/// payload is opaque `serde_json::Value` on the cloud side, so widening a
/// payload struct's fields is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    ToolResult,
    ExitCode,
    FileDiff,
    ProcessObservation,
    TranscriptExcerpt,
}

/// A single piece of observed, provenance-carrying evidence. Evidence exists
/// independent of any claim; a verifier links relevant evidence to a claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: Uuid,
    pub session_id: String,
    pub source_event_id: Uuid,
    pub kind: EvidenceKind,
    pub observed_at: String,
    pub payload: serde_json::Value,
    /// Human-readable provenance, e.g. "claude_code:PostToolUse:Bash#tool_response".
    pub provenance: String,
    /// Structured sensor/trust provenance (FORNX-157). `None` means this
    /// evidence predates the sensor contract or was produced by code not
    /// yet migrated onto it — see `sensor::EvidenceSource`'s doc comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<sensor::EvidenceSource>,
    /// Versioned provider-extension data (FORNX-158) that doesn't fit
    /// `payload`'s canonical shape for `kind`. `None` is the common case —
    /// most evidence needs no extension at all. See
    /// `extension::ExtensionEnvelope`'s doc comment for the full
    /// canonical-vs-extension boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<extension::ExtensionEnvelope>,
    /// FORNX-319: `true` once this row's raw `payload` has been purged by
    /// the local retention sweep (`fornax_store::retention`) after its
    /// `RetentionClass::RawLocal` retention window elapsed. `false` for
    /// every row written before this field existed and for every row whose
    /// evidence has not (yet) expired — `#[serde(default)]` keeps the wire
    /// shape backward compatible. When `true`, `payload` no longer holds
    /// the original observation; it holds an explicit "evidence expired"
    /// marker (see `fornax_store::retention::purge_evidence_payload`) so a
    /// renderer never mistakes a purge for "no evidence was ever
    /// collected" (ADR-0001 D4: the verdict/rationale this evidence once
    /// supported are never recomputed or altered by a purge).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub evidence_purged: bool,
}

/// Strongly-typed canonical payload shapes, one per [`EvidenceKind`] variant
/// (FORNX-158 AC: "canonical fields remain strongly typed and validated").
///
/// `Evidence::payload` itself stays `serde_json::Value` — every producer of
/// canonical evidence already builds a `serde_json::Value` directly (see
/// `fornax-adapter-claude`/`fornax-adapter-codex`'s `ExitCode` sensors), and
/// changing that field's storage type is out of scope for this ticket. This
/// enum instead gives that JSON a typed contract to be checked against via
/// [`validate_canonical_payload`] — a producer or a conformance test can
/// confirm a given `(kind, payload)` pair actually matches the canonical
/// shape for `kind`, rather than accepting anything.
///
/// Only [`EvidenceKind::ExitCode`] has a real producer today (both adapters'
/// exit-code sensors). The remaining variants are typed ahead of any
/// producer existing, the same way FORNX-157's `ReasoningSummarySensor`
/// worked example types a signal class before any provider exposes it —
/// giving a future sensor a canonical shape to target from day one rather
/// than inventing one ad hoc when it lands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitCodePayload {
    /// The command invoked. Kept as `Value` because providers report it in
    /// different shapes (Claude Code: array from `tool_input.command`;
    /// Codex: whatever `resp["command"]` already is) — typing this further
    /// would require picking one provider's shape as canonical, which
    /// FORNX-158 does not ask for.
    pub command: serde_json::Value,
    pub exit_code: i64,
    /// True when `exit_code` was inferred from a heuristic (e.g. "stderr is
    /// empty") rather than a literal exit-code field the provider reported.
    #[serde(default)]
    pub heuristic: bool,
}

/// Not yet produced by any sensor — see [`ExitCodePayload`]'s doc comment
/// for why these are typed ahead of a producer existing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultPayload {
    pub summary: String,
}

/// Not yet produced by any sensor — see [`ExitCodePayload`]'s doc comment
/// for why these are typed ahead of a producer existing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileDiffPayload {
    pub path: String,
    pub diff: String,
}

/// `description` predates any producer (see [`ExitCodePayload`]'s doc
/// comment for why canonical payloads are typed ahead of a producer
/// existing). `observation` (FORNX-14) is this payload's first real producer
/// field: `fornax-adapter-claude`'s `ClaudeGitOutcomeSensor` populates it for
/// a git commit/push outcome observed in a Bash `tool_response`. Widening
/// this struct's fields — rather than adding a new [`EvidenceKind`] variant —
/// is the deliberate way to add a new evidence shape; see that enum's doc
/// comment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservationPayload {
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<ProcessObservationDetail>,
}

/// Structured detail for a [`ProcessObservationPayload`] (FORNX-14). An
/// `HttpProbe` variant is planned for a follow-up PR (FORNX-14's HTTP-health
/// work) but deliberately not added here.
///
/// `FileWriteObserved` and `CommandDuration` (FORNX-91) are the second and
/// third real producers, following the same "widen this enum, no new
/// `EvidenceKind` variant, no new `fornax-store` column" precedent
/// `VcsOperation` established — see this enum's home module doc
/// ([`EvidenceKind`]'s "closed on purpose" note) for why a new evidence
/// shape lands here rather than as a new top-level kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "observation_kind",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ProcessObservationDetail {
    VcsOperation {
        operation: VcsOperation,
        outcome: VcsOutcome,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commit_sha: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        branch: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remote: Option<String>,
    },
    /// FORNX-91: whether the *actual host filesystem* (independent of
    /// anything a provider claimed) shows `claimed_path` existing, and
    /// whether its modification time is consistent with the claim. Produced
    /// by a `TrustClass::HostObserved` sensor that calls `std::fs::metadata`
    /// itself, never by parsing a provider's own tool-result text — see
    /// `fornax-adapter-claude`'s `ClaudeFileWriteConfirmedSensor` for the one
    /// producer that exists today.
    FileWriteObserved {
        claimed_path: String,
        exists: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        modified_at: Option<String>,
        consistent_with_claim: bool,
    },
    /// FORNX-91: a command's actual wall-clock duration, computed from
    /// provider-reported start/end timestamps already present on a tool
    /// result payload (not a new OS-level process-monitoring mechanism —
    /// see `fornax-adapter-opencode`'s `OpenCodeCommandDurationSensor`, the
    /// one producer that exists today, for the exact fields it reads).
    CommandDuration { duration_ms: i64 },
    /// FORNX-302: whether the *real git working tree* (queried in-process
    /// via `fornax-vcs`, independent of anything a provider claimed)
    /// considers `claimed_path` dirty (uncommitted/unstaged/untracked),
    /// cross-checking a claimed Edit/Write/MultiEdit or `git commit`/`git
    /// push` against actual working-tree/HEAD state. Distinct from
    /// [`Self::FileWriteObserved`] (plain `std::fs::metadata`, no git
    /// awareness) and from [`Self::VcsOperation`] (parses a provider's own
    /// reported `git` stdout/stderr, `TrustClass::AgentAdjacent`) — this
    /// variant is produced by a `TrustClass::HostObserved` sensor that
    /// queries git itself. Produced today only by
    /// `fornax-adapter-claude`'s `ClaudeGitWorkingTreeSensor`.
    WorkingTreeStatusObserved {
        claimed_path: String,
        is_repo: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        head_commit: Option<String>,
        path_is_dirty: bool,
    },
    /// FORNX-302: aggregated CI check-run status for one commit SHA, queried
    /// from the CI provider's own API (GitHub Actions, via the `fornax-ci`
    /// crate's `GitHubCiStatusSensor` — the one producer today).
    /// `TrustClass::IndependentExternal` — reported by a system outside both
    /// the coding agent and the local host, independent of what either
    /// claims happened.
    CiCheckStatus {
        /// `"owner/repo"` slug the check-runs were queried for.
        repo: String,
        commit_sha: String,
        total_count: i64,
        overall: CiOverallStatus,
    },
}

/// Coarse aggregate of a commit's CI check-runs
/// ([`ProcessObservationDetail::CiCheckStatus`]), derived by the querying
/// sensor from each individual check-run's `status`/`conclusion` — never a
/// raw pass-through of GitHub's own per-check vocabulary, so downstream
/// verifiers have one small, closed vocabulary to match on regardless of how
/// many individual checks a repository happens to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiOverallStatus {
    /// Every check-run completed with a conclusion of `success`, `neutral`,
    /// or `skipped`.
    Success,
    /// At least one check-run completed with `failure`, `timed_out`,
    /// `cancelled`, or `action_required`.
    Failure,
    /// At least one check-run has not yet completed (`queued`/`in_progress`),
    /// and none have failed.
    Pending,
    /// No check-runs were reported for this commit at all (`total_count ==
    /// 0`), or a check-run reported a conclusion this binary does not
    /// recognize — an honest "cannot summarize", never guessed as `Success`.
    Unknown,
}

/// Which git operation a [`ProcessObservationDetail::VcsOperation`] observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VcsOperation {
    Commit,
    Push,
}

/// What git reported for a [`ProcessObservationDetail::VcsOperation`],
/// parsed from the real `git` stdout/stderr text Claude Code's `tool_response`
/// carries for a `git commit`/`git push` Bash invocation — never fabricated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VcsOutcome {
    Created,
    NothingToCommit,
    RefUpdated,
    UpToDate,
    Rejected,
}

/// Not yet produced by any sensor — see [`ExitCodePayload`]'s doc comment
/// for why these are typed ahead of a producer existing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptExcerptPayload {
    pub text: String,
}

/// Validate that `payload` matches the canonical typed shape for `kind`
/// (FORNX-158 required test: canonical fields reject wrong types, not just
/// accept anything). Returns the specific `serde_json` type mismatch on
/// failure; never panics.
pub fn validate_canonical_payload(
    kind: EvidenceKind,
    payload: &serde_json::Value,
) -> Result<(), String> {
    fn check<T: for<'de> Deserialize<'de>>(payload: &serde_json::Value) -> Result<(), String> {
        serde_json::from_value::<T>(payload.clone())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    match kind {
        EvidenceKind::ExitCode => check::<ExitCodePayload>(payload),
        EvidenceKind::ToolResult => check::<ToolResultPayload>(payload),
        EvidenceKind::FileDiff => check::<FileDiffPayload>(payload),
        EvidenceKind::ProcessObservation => check::<ProcessObservationPayload>(payload),
        EvidenceKind::TranscriptExcerpt => check::<TranscriptExcerptPayload>(payload),
    }
}

/// The five-state verdict vocabulary (HVDL-15 / FORNX-20). Never collapsed
/// to a boolean or a score in v0.0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Verified,
    Unverified,
    Contradicted,
    Review,
    Unavailable,
}

/// Output of `Claim + Evidence[] + RuntimeCapabilities -> Finding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub claim_id: Uuid,
    pub verdict: Verdict,
    pub evidence_ids: Vec<Uuid>,
    pub verifier_name: String,
    pub rationale: String,
    pub computed_at: String,
}

/// One line of the newline-delimited JSON protocol adapters speak to the
/// daemon over the Unix Domain Socket (FORNX-25). Adapters stay thin: they
/// translate provider payloads into these messages and nothing else — claim
/// extraction/verification happens daemon-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
// `Evidence` (via `EvidenceSource`'s FORNX-159 provenance fields) is now
// meaningfully larger than the other variants. Boxing it would touch ~13
// construction/match sites across both adapter crates and the daemon for a
// stack-size optimization with no behavior change; `IngestMessage` values
// are short-lived (constructed, sent over one UDS message, dropped), so the
// extra stack space per unused-variant slot is not worth that churn.
#[allow(clippy::large_enum_variant)]
pub enum IngestMessage {
    Event(AgentEvent),
    Claim(Claim),
    Evidence(Evidence),
    /// A signed policy bundle envelope (FORNX-119), imported via `fornax
    /// policy import <path>`. `envelope` is the raw envelope JSON text
    /// (`policy::SignedPolicyBundle`, base64 payload + signatures) exactly
    /// as read from the file — parsing/verification happens daemon-side via
    /// `fornax_store::Store::submit_policy_bundle`. Fire-and-forget over
    /// the existing UDS, same as every other `IngestMessage` variant — no
    /// new HTTP POST route (the localhost HTTP surface is GET-only,
    /// deliberately, since it is browser-reachable).
    PolicyBundle {
        envelope: String,
    },
    /// A signed policy revocation list envelope (FORNX-123), imported via
    /// `fornax policy import <path>` (which dispatches on the artifact's own
    /// top-level shape -- see that command's doc). `envelope` is the raw
    /// envelope JSON text (`policy::SignedRevocationList`) exactly as read
    /// from the file. Same fire-and-forget UDS path as `PolicyBundle`.
    PolicyRevocation {
        envelope: String,
    },
    /// Adapter announces what its runtime can observe, once per connection.
    Capabilities(RuntimeCapabilities),
}

// `RuntimeCapabilities` and its supporting taxonomy (`SignalClass`,
// `SignalAvailability`, `CapabilitySignal`, `CapabilityProbe`) live in
// `capabilities.rs` (FORNX-155) and are re-exported above.

#[cfg(test)]
mod evidence_schema_tests {
    use super::*;

    fn evidence_with(kind: EvidenceKind, payload: serde_json::Value) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload,
            provenance: "test".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        }
    }

    // --- Required test: canonical fields reject wrong types (test #4) ----

    #[test]
    fn exit_code_payload_with_wrong_type_is_rejected() {
        let bad = serde_json::json!({"command": [], "exit_code": "zero"});
        let err = validate_canonical_payload(EvidenceKind::ExitCode, &bad).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn exit_code_payload_missing_required_field_is_rejected() {
        let bad = serde_json::json!({"command": []});
        assert!(validate_canonical_payload(EvidenceKind::ExitCode, &bad).is_err());
    }

    #[test]
    fn exit_code_payload_with_unknown_extra_field_is_rejected() {
        // Canonical payloads are strongly typed and closed (`deny_unknown_fields`)
        // — unlike the extension envelope's flatten/tolerate behavior, an
        // unrecognized field on a *canonical* shape is a validation failure,
        // not something to preserve-and-ignore. Tolerance is reserved for the
        // extension envelope (see `extension` module docs).
        let bad = serde_json::json!({"command": [], "exit_code": 0, "surprise": true});
        assert!(validate_canonical_payload(EvidenceKind::ExitCode, &bad).is_err());
    }

    #[test]
    fn well_typed_exit_code_payload_validates() {
        let good = serde_json::json!({"command": ["pytest"], "exit_code": 0, "heuristic": false});
        assert!(validate_canonical_payload(EvidenceKind::ExitCode, &good).is_ok());
    }

    #[test]
    fn well_typed_exit_code_payload_without_optional_heuristic_field_validates() {
        let good = serde_json::json!({"command": ["pytest"], "exit_code": 1});
        assert!(validate_canonical_payload(EvidenceKind::ExitCode, &good).is_ok());
    }

    #[test]
    fn not_yet_produced_kinds_still_validate_their_typed_shape() {
        assert!(validate_canonical_payload(
            EvidenceKind::ToolResult,
            &serde_json::json!({"summary": "ok"})
        )
        .is_ok());
        assert!(validate_canonical_payload(
            EvidenceKind::ToolResult,
            &serde_json::json!({"summary": 1})
        )
        .is_err());
        assert!(validate_canonical_payload(
            EvidenceKind::FileDiff,
            &serde_json::json!({"path": "a.rs", "diff": "+x"})
        )
        .is_ok());
        assert!(validate_canonical_payload(
            EvidenceKind::ProcessObservation,
            &serde_json::json!({"description": "ran"})
        )
        .is_ok());
        assert!(validate_canonical_payload(
            EvidenceKind::TranscriptExcerpt,
            &serde_json::json!({"text": "hello"})
        )
        .is_ok());
    }

    // --- FORNX-14: ProcessObservationPayload.observation widening ---------

    #[test]
    fn process_observation_payload_with_vcs_operation_observation_validates() {
        let good = serde_json::json!({
            "description": "git commit created",
            "observation": {
                "observation_kind": "vcs_operation",
                "operation": "commit",
                "outcome": "created",
                "commit_sha": "abc1234",
                "branch": "main"
            }
        });
        assert!(validate_canonical_payload(EvidenceKind::ProcessObservation, &good).is_ok());
    }

    #[test]
    fn process_observation_payload_observation_with_unknown_field_is_rejected() {
        let bad = serde_json::json!({
            "description": "git commit created",
            "observation": {
                "observation_kind": "vcs_operation",
                "operation": "commit",
                "outcome": "created",
                "surprise": true
            }
        });
        assert!(validate_canonical_payload(EvidenceKind::ProcessObservation, &bad).is_err());
    }

    // --- Evidence::extension is optional and independent of `payload` ----

    #[test]
    fn evidence_extension_defaults_to_none_and_round_trips_when_absent() {
        let json = r#"{
            "id": "00000000-0000-0000-0000-000000000001",
            "session_id": "s1",
            "source_event_id": "00000000-0000-0000-0000-000000000002",
            "kind": "exit_code",
            "observed_at": "2026-01-01T00:00:00Z",
            "payload": {"command": [], "exit_code": 0},
            "provenance": "test"
        }"#;
        let ev: Evidence = serde_json::from_str(json).unwrap();
        assert!(ev.extension.is_none());
        let reser = serde_json::to_value(&ev).unwrap();
        assert!(reser.get("extension").is_none());
    }

    #[test]
    fn evidence_with_extension_round_trips() {
        let mut ev = evidence_with(
            EvidenceKind::ExitCode,
            serde_json::json!({"command": [], "exit_code": 0}),
        );
        ev.extension = Some(extension::ExtensionEnvelope::new(
            Provider::Codex,
            "codex-adapter-0.1.0",
            extension::ContentClass::ToolTelemetry,
            serde_json::json!({"extra": "detail"}),
        ));
        let json = serde_json::to_string(&ev).unwrap();
        let back: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev.extension, back.extension);
    }
}

/// Direct unit coverage for the core domain types (FORNX-11): construction
/// and serde round-trip for `AgentEvent`/`Claim`/`Evidence`/`Finding`/
/// `IngestMessage`, plus the five-state `Verdict` vocabulary. Schema
/// versioning/evolution itself is FORNX-158's `extension` module (see
/// `docs/adr/0005-schema-evolution.md`) — this module only closes the gap
/// that `fornax-types`' other domain types had no direct tests of their own.
#[cfg(test)]
mod domain_type_tests {
    use super::*;

    fn sample_event() -> AgentEvent {
        AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: "2026-01-01T00:00:00Z".into(),
            tool_name: Some("Bash".into()),
            tool_input: Some(serde_json::json!({"command": "pytest"})),
            tool_response: Some(serde_json::json!({"exit_code": 0})),
            raw: serde_json::json!({"hook_event_name": "PostToolUse"}),
        }
    }

    fn sample_claim() -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "All tests passed".into(),
            subject: "test_result".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn sample_finding(verdict: Verdict) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            claim_id: Uuid::new_v4(),
            verdict,
            evidence_ids: vec![Uuid::new_v4()],
            verifier_name: "exit_code_verifier".into(),
            rationale: "exit code was 0".into(),
            computed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    // --- AgentEvent ---------------------------------------------------

    #[test]
    fn agent_event_round_trips_through_json() {
        let event = sample_event();
        let json = serde_json::to_string(&event).unwrap();
        let back: AgentEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.id, back.id);
        assert_eq!(event.session_id, back.session_id);
        assert_eq!(event.provider, back.provider);
        assert_eq!(event.kind, back.kind);
        assert_eq!(event.tool_name, back.tool_name);
        assert_eq!(event.tool_input, back.tool_input);
        assert_eq!(event.tool_response, back.tool_response);
        assert_eq!(event.raw, back.raw);
    }

    #[test]
    fn agent_event_allows_absent_tool_fields() {
        let mut event = sample_event();
        event.tool_name = None;
        event.tool_input = None;
        event.tool_response = None;
        let json = serde_json::to_string(&event).unwrap();
        let back: AgentEvent = serde_json::from_str(&json).unwrap();
        assert!(back.tool_name.is_none());
        assert!(back.tool_input.is_none());
        assert!(back.tool_response.is_none());
    }

    // --- Claim ----------------------------------------------------------

    #[test]
    fn claim_round_trips_through_json() {
        let claim = sample_claim();
        let json = serde_json::to_string(&claim).unwrap();
        let back: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim.id, back.id);
        assert_eq!(claim.session_id, back.session_id);
        assert_eq!(claim.source_event_id, back.source_event_id);
        assert_eq!(claim.text, back.text);
        assert_eq!(claim.subject, back.subject);
        assert_eq!(claim.claimed_at, back.claimed_at);
    }

    // --- Finding ----------------------------------------------------------

    #[test]
    fn finding_round_trips_through_json() {
        let finding = sample_finding(Verdict::Verified);
        let json = serde_json::to_string(&finding).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(finding.id, back.id);
        assert_eq!(finding.claim_id, back.claim_id);
        assert_eq!(finding.verdict, back.verdict);
        assert_eq!(finding.evidence_ids, back.evidence_ids);
        assert_eq!(finding.verifier_name, back.verifier_name);
        assert_eq!(finding.rationale, back.rationale);
        assert_eq!(finding.computed_at, back.computed_at);
    }

    // --- Verdict: the five-state vocabulary must never collapse ----------

    /// Exhaustive match with no wildcard arm: if a `Verdict` variant is ever
    /// added, removed, or renamed, this fails to compile rather than
    /// silently passing (HVDL-15 / FORNX-20: "never collapsed to a boolean
    /// or a score").
    #[test]
    fn verdict_has_exactly_five_states_with_stable_wire_names() {
        let cases = [
            (Verdict::Verified, "verified"),
            (Verdict::Unverified, "unverified"),
            (Verdict::Contradicted, "contradicted"),
            (Verdict::Review, "review"),
            (Verdict::Unavailable, "unavailable"),
        ];
        for (verdict, expected_wire_name) in cases {
            // Exhaustiveness check: every variant must be named here.
            match verdict {
                Verdict::Verified
                | Verdict::Unverified
                | Verdict::Contradicted
                | Verdict::Review
                | Verdict::Unavailable => {}
            }
            let json = serde_json::to_value(verdict).unwrap();
            assert_eq!(json, serde_json::json!(expected_wire_name));
            let back: Verdict = serde_json::from_value(json).unwrap();
            assert_eq!(verdict, back);
        }
    }

    // --- IngestMessage ----------------------------------------------------

    #[test]
    fn ingest_message_event_variant_round_trips_and_tags_type() {
        let msg = IngestMessage::Event(sample_event());
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("event"));
        let back: IngestMessage = serde_json::from_value(json).unwrap();
        assert!(matches!(back, IngestMessage::Event(_)));
    }

    #[test]
    fn ingest_message_claim_variant_round_trips_and_tags_type() {
        let msg = IngestMessage::Claim(sample_claim());
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("claim"));
        let back: IngestMessage = serde_json::from_value(json).unwrap();
        assert!(matches!(back, IngestMessage::Claim(_)));
    }

    #[test]
    fn ingest_message_evidence_variant_round_trips_and_tags_type() {
        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".into(),
            payload: serde_json::json!({"command": [], "exit_code": 0}),
            provenance: "test".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        };
        let msg = IngestMessage::Evidence(evidence);
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json.get("type").and_then(|v| v.as_str()), Some("evidence"));
        let back: IngestMessage = serde_json::from_value(json).unwrap();
        assert!(matches!(back, IngestMessage::Evidence(_)));
    }
}
