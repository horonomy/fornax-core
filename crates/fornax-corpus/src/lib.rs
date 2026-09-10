//! Integrity Corpus Factory (FORNX-341, Stage 8 / Active Evidence
//! Intelligence, epic FORNX-340).
//!
//! Turns real Fornax sessions into candidate integrity cases without
//! centralizing protected raw evidence or letting a synthetic fixture be
//! mistaken for real human-adjudicated ground truth. This crate does not
//! introduce a parallel schema for that: a [`candidate::CandidateCase`] is a
//! `fornax_replay::ReplayManifest` (FORNX-98 — already frozen, versioned,
//! self-contained) plus mining/withholding metadata. Persistence and
//! deletion propagation reuse the FORNX-106 lineage mechanism in
//! `fornax-store` unchanged (see `RetentionClass::SanitizedCandidate`); this
//! crate has no `fornax-store` dependency of its own — it hands back plain
//! values for `fornax-store`/`fornax-cli` to persist and query.
//!
//! # Boundary
//!
//! - No automatic ground-truth labeling: [`candidate::CandidateCase`] has no
//!   `adjudicated_expected_outcome` field at all. Only
//!   [`promote::promote_to_labeled_trajectory`] can produce a
//!   `fornax_bench::dataset::LabeledTrajectory`, and it requires the caller
//!   to supply a real `labeled_by`/`labeled_at` — there is no code path from
//!   a mined candidate to a labeled trajectory that skips that.
//! - No centralized raw-telemetry lake: mining reads one session's local
//!   store data and produces one local artifact; nothing in this crate opens
//!   a network connection.
//! - Redaction/classification is a per-[`fornax_types::EvidenceKind`]
//!   allowlist, not a new redactor — see [`candidate::sanitize`].

pub mod adjudication;
pub mod candidate;
pub mod feedback;
pub mod manifest;
pub mod mining;
pub mod promote;
pub mod sampling;

pub use candidate::{
    sanitize, CandidateCase, WithheldEvidence, WithheldReason, CANDIDATE_SCHEMA_VERSION,
    EXPORTABLE_EVIDENCE_KINDS, MAX_CANDIDATE_PAYLOAD_BYTES,
};
pub use feedback::{
    FeedbackAuthor, FeedbackBinding, FeedbackDisposition, ReviewFeedback, FEEDBACK_SCHEMA_VERSION,
};
pub use manifest::{
    build_corpus_manifest, CandidateCorpusManifest, CorpusError, CORPUS_MANIFEST_SCHEMA_VERSION,
};
pub use mining::{evaluate, MiningInput, MiningStrategy};
pub use promote::promote_to_labeled_trajectory;
pub use sampling::{
    derived_verdict_agreement, signals_for_case, CaseSignals, DeferralReason, DeferredCase,
    DeterministicSamplingPolicy, PatternKey, ReviewBudget, SamplingPlan, SamplingPolicy,
    SamplingSignal, SelectedCase, VerdictAgreement, DEFAULT_MAX_PER_PATTERN,
    SAMPLING_POLICY_VERSION,
};
