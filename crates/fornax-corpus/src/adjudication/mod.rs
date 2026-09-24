//! Corpus adjudication (FORNX-342): converts sanitized
//! [`crate::candidate::CandidateCase`]s into a human-adjudicated gold
//! corpus with explicit uncertainty, disagreement and provenance.
//!
//! **The most important data rule: do not fabricate the real corpus.** This
//! module makes fabrication a structural impossibility rather than a policy
//! to remember:
//!
//! - [`review::ReviewerKind::Human`] requires an explicit `attested_by`
//!   string at registration ([`review::ReviewerRef::new`]).
//! - [`gold::promote_gold_label`] selects `LabelingProvenance::HumanAdjudicated`
//!   only when every contributing reviewer is `Human` -- any other mix,
//!   including a single `MechanismTestFixture` reviewer anywhere in the
//!   chain, exports as `SyntheticMechanismTest`.
//! - [`state::AdjudicationState`] is derived, never stored -- there is no
//!   mutable state column a write path could use to silently overwrite
//!   disagreement.
//! - [`agreement::cohens_kappa`] and [`agreement::AgreementStat`] never
//!   return a fabricated number below a real minimum sample size or on a
//!   degenerate input.
//!
//! Every mechanism here is exercised end-to-end in this crate's own tests
//! using `ReviewerKind::MechanismTestFixture` reviewers -- see each module's
//! tests. No test in this repository registers a `Human` reviewer or
//! reports a real inter-rater agreement figure; doing so requires a real
//! person actually using `fornax adjudicate`. See
//! `docs/adr/0014-corpus-adjudication.md` for the full list of claims this
//! mechanism does and does not establish.

pub mod agreement;
pub mod blind;
pub mod gold;
pub mod review;
pub mod state;
pub mod taxonomy;

pub use agreement::{
    cohens_kappa, label_distribution, raw_agreement, AgreementStat, DisagreementReason,
    MIN_KAPPA_CASES,
};
pub use blind::{blind, BlindedCase, BLINDED_CASE_SCHEMA_VERSION};
pub use gold::{
    next_revision, promote_gold_label, GoldLabelRejection, GoldLabelRevision, RelabelReason,
};
pub use review::{
    ReviewError, ReviewOutcome, ReviewRecord, ReviewerError, ReviewerKind, ReviewerRef,
    ReviewerRole,
};
pub use state::{derive_state, AdjudicationState, QueueEntry, ResolutionBasis};
pub use taxonomy::{validate_failure_metadata, CaseLabel, Confidence, FailureClass, TaxonomyError};
