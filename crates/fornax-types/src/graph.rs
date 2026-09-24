//! Evidence graph: typed claim-to-evidence linkage and explicit
//! missing-evidence markers (FORNX-89, parent epic FORNX-66).
//!
//! Stage 1-3 evidence is flat: a `Claim` exists, `Evidence` rows exist per
//! session, and a `Finding` names which `evidence_ids` a verifier used — but
//! there is no persisted record of *how* a given piece of evidence relates
//! to a claim (supports it? contradicts it?), and a claim with zero linked
//! evidence looks identical to a claim whose expected evidence genuinely
//! could not be collected. This module adds that missing layer, additively:
//!
//! - [`EvidenceLink`]: a typed edge from a `Claim` to a piece of `Evidence`
//!   ([`EvidenceRelation::Supports`]/[`EvidenceRelation::Contradicts`]/
//!   [`EvidenceRelation::Neutral`]). No confidence/weight/fusion here —
//!   combining multiple links into an uncertainty-aware verdict is FORNX-93's
//!   job (epic FORNX-66's "Evidence first, score second" invariant: a score
//!   is a compression of inspectable evidence, computed downstream of it,
//!   never folded back into the evidence layer itself).
//! - [`MissingEvidence`]: a claim's explicit note that evidence of a given
//!   [`crate::SignalClass`] was expected but is
//!   [`crate::SignalAvailability::Unavailable`]/`Unsupported`/
//!   `CollectionFailed`, reusing FORNX-155's existing taxonomy rather than
//!   inventing a parallel one. This is the "missing evidence is explicitly
//!   modeled rather than inferred from empty arrays" AC — "no evidence
//!   found" and "evidence could not exist" must stay distinguishable.
//! - [`EvidenceGraph`]: a read-side aggregate (not itself persisted) bundling
//!   one claim's links and missing-evidence notes for callers like
//!   `fornax-store::Store::evidence_graph_for_claim`.
//!
//! Both `EvidenceLink` and `MissingEvidence` are pure additions alongside
//! `Evidence`/`Claim` — see `docs/adr/0001-architecture-invariants.md`'s D3
//! ("immutable observation before interpretation"): this module never
//! mutates or reinterprets a stored `Evidence`/`Claim` row, it only records
//! new relationship facts about them.
//!
//! # Out of scope (FORNX-89 AC / epic non-goals)
//!
//! - Fusion/uncertainty scoring across links (FORNX-93).
//! - A read-facing API/UI for the graph (FORNX-90, "Evidence Explorer").
//! - New sensor types or signal classes (FORNX-91) — this module only
//!   consumes the existing [`crate::SignalClass`]/[`crate::SignalAvailability`]
//!   taxonomy, it does not extend it.
//!
//! # Evidence quality metadata (FORNX-92, parent epic FORNX-66)
//!
//! FORNX-92 adds two more per-claim-evidence-quality facts alongside the
//! FORNX-89 types above, additively:
//!
//! - [`StalenessAssessment`] / [`staleness_of`]: whether one piece of
//!   evidence is too old, relative to a claim's timestamp, to vouch for it —
//!   AC: "Stale evidence cannot silently support a time-sensitive claim."
//!   Kept per-[`crate::EvidenceKind`] ([`FreshnessWindow`],
//!   [`crate::EvidenceKind::default_freshness_window`]) rather than a single
//!   global TTL, and kept a pure, clock-free comparison of two already-stored
//!   timestamps (never `Utc::now()`) so it stays deterministic and replayable
//!   (AC5) — re-running it against the same stored data always yields the
//!   same answer. An unparseable timestamp or `observed_at` after
//!   `claimed_at` is [`StalenessAssessment::Indeterminate`], never silently
//!   treated as fresh.
//! - [`EvidenceConflict`] / [`EvidenceGraph::conflict`]: surfaces that a
//!   claim has both a `Supports` and a `Contradicts` link as one inspectable
//!   fact, without choosing how to resolve it (AC: "Conflicts remain
//!   inspectable in Evidence Explorer" — resolution is FORNX-93's job, per
//!   the "out of scope" list above, which still applies).
//!
//! Correlation groups and derived-evidence trust inheritance (the AC1/AC5
//! "quality metadata inheritance" items) live on `sensor::EvidenceSource`
//! instead — see that module's "Evidence quality metadata" doc section.
//! "External independent vs. same-process/self-reported" (AC3) is already
//! satisfied by the pre-existing `sensor::TrustClass` taxonomy; nothing new
//! is added for it here.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Claim, Evidence, EvidenceKind, SignalAvailability, SignalClass};

/// How one piece of evidence relates to a claim (FORNX-89). Deliberately
/// closed and confidence-free — see module docs for why fusion/weighting is
/// out of scope here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRelation {
    /// This evidence is consistent with the claim being true.
    Supports,
    /// This evidence is inconsistent with the claim being true.
    Contradicts,
    /// This evidence is related to the claim but neither supports nor
    /// contradicts it on its own (e.g. context evidence a verifier consulted
    /// without it moving the verdict either way).
    Neutral,
}

/// A typed edge from a [`crate::Claim`] to a piece of [`crate::Evidence`]
/// (FORNX-89). Additive linkage layer — recording this edge does not change
/// how either the claim or the evidence row is stored or interpreted by
/// existing verifiers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceLink {
    pub id: Uuid,
    pub session_id: String,
    pub claim_id: Uuid,
    pub evidence_id: Uuid,
    pub relation: EvidenceRelation,
    /// RFC3339 timestamp this linkage was recorded (not when the underlying
    /// evidence was observed — see [`crate::Evidence::observed_at`] for
    /// that).
    pub linked_at: String,
}

/// A claim's explicit note that evidence of a given [`SignalClass`] was
/// expected but could not be collected/observed (FORNX-89). Reuses
/// [`SignalClass`]/[`SignalAvailability`] from FORNX-155/157 rather than a
/// parallel taxonomy — see module docs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MissingEvidence {
    pub id: Uuid,
    pub session_id: String,
    pub claim_id: Uuid,
    pub signal_class: SignalClass,
    /// Why it's missing — expected to be one of `Unavailable`/`Unsupported`/
    /// `CollectionFailed`/`Redacted`, though this type does not itself
    /// enforce that subset (it stores whatever `SignalAvailability` the
    /// caller determined, same tolerance the rest of that enum's consumers
    /// already have).
    pub availability: SignalAvailability,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// RFC3339 timestamp this absence was noted.
    pub noted_at: String,
}

/// Read-side aggregate for one claim's evidence graph (FORNX-89): everything
/// known to support/contradict/relate to it, plus everything explicitly
/// noted absent. Not itself a persisted row — computed on demand by
/// `fornax-store::Store::evidence_graph_for_claim`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceGraph {
    pub links: Vec<EvidenceLink>,
    pub missing: Vec<MissingEvidence>,
}

/// Both sides of a real, unresolved conflict on one claim (FORNX-92): at
/// least one [`EvidenceRelation::Supports`] link and at least one
/// [`EvidenceRelation::Contradicts`] link on the same claim. See
/// [`EvidenceGraph::conflict`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceConflict {
    pub supports: Vec<EvidenceLink>,
    pub contradicts: Vec<EvidenceLink>,
}

impl EvidenceGraph {
    /// This claim's conflict, if it has one — see [`EvidenceConflict`].
    /// `None` when the links agree (all `Supports`, all `Contradicts`, all
    /// `Neutral`, or no links at all). This only detects and exposes the
    /// conflict; resolving it is FORNX-93's job (module docs).
    pub fn conflict(&self) -> Option<EvidenceConflict> {
        let supports: Vec<EvidenceLink> = self
            .links
            .iter()
            .filter(|l| l.relation == EvidenceRelation::Supports)
            .cloned()
            .collect();
        let contradicts: Vec<EvidenceLink> = self
            .links
            .iter()
            .filter(|l| l.relation == EvidenceRelation::Contradicts)
            .cloned()
            .collect();
        if supports.is_empty() || contradicts.is_empty() {
            None
        } else {
            Some(EvidenceConflict {
                supports,
                contradicts,
            })
        }
    }
}

/// How a given [`crate::EvidenceKind`] can go stale over time relative to a
/// claim timestamp (FORNX-92) — see [`crate::EvidenceKind::default_freshness_window`].
/// Deliberately per-kind, not a single global TTL: a git-commit fact
/// ([`crate::EvidenceKind::ProcessObservation`]'s `VcsOperation` detail)
/// doesn't go stale the way a live process exit code
/// ([`crate::EvidenceKind::ExitCode`]) might.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessWindow {
    /// This evidence kind records a fact that does not change once
    /// observed (e.g. a git commit SHA, a file diff, a transcript excerpt)
    /// — elapsed time alone never makes it stale.
    Durable,
    /// This evidence kind records point-in-time runtime/process state that
    /// can go stale once more than `max_age_seconds` have elapsed between
    /// when it was observed and when the claim referencing it was made.
    Perishable { max_age_seconds: i64 },
}

/// Conservative default freshness window for [`crate::EvidenceKind::ExitCode`]
/// (FORNX-92): a documented placeholder, not a measured value. FORNX-93's
/// fusion engine may pass a different window per claim to [`staleness_of`]
/// directly — nothing requires a caller to use this default.
pub const DEFAULT_EXIT_CODE_FRESHNESS_SECONDS: i64 = 3600;

impl EvidenceKind {
    /// Default freshness window for this evidence kind (FORNX-92). See
    /// [`FreshnessWindow`]. Exhaustive by construction — a new
    /// `EvidenceKind` variant must extend this match, not fall through a
    /// wildcard arm.
    pub fn default_freshness_window(&self) -> FreshnessWindow {
        match self {
            EvidenceKind::ExitCode => FreshnessWindow::Perishable {
                max_age_seconds: DEFAULT_EXIT_CODE_FRESHNESS_SECONDS,
            },
            EvidenceKind::ToolResult
            | EvidenceKind::FileDiff
            | EvidenceKind::ProcessObservation
            | EvidenceKind::TranscriptExcerpt => FreshnessWindow::Durable,
        }
    }
}

/// Result of comparing one piece of evidence's `observed_at` against a
/// claim's `claimed_at` under a [`FreshnessWindow`] (FORNX-92). Resolving
/// what a verdict *does* with a `Stale`/`Indeterminate` result is FORNX-93's
/// job; this type only makes the fact inspectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalenessAssessment {
    /// This evidence kind's window is [`FreshnessWindow::Durable`] — age
    /// alone never makes it stale.
    NotTimeSensitive,
    /// Within the window.
    Fresh { age_seconds: i64 },
    /// Outside the window.
    Stale { age_seconds: i64 },
    /// `observed_at`/`claimed_at` could not be parsed as RFC3339, or
    /// evidence was observed *after* the claim was made (a negative age) —
    /// both are "cannot vouch for freshness", never silently coerced to
    /// `Fresh`. Note that a claim and its supporting evidence commonly land
    /// within the same event (e.g. an `ExitCode` claim/evidence pair from one
    /// `PostToolUse`), so sub-second clock ordering can be the difference
    /// between `Fresh { age_seconds: 0 }` and this variant — that is this
    /// function's deliberate, conservative choice, not a bug; FORNX-93 may
    /// reasonably choose to treat "observed slightly after the claim" as
    /// fresh for a specific claim kind rather than indeterminate.
    Indeterminate { reason: &'static str },
}

/// Compare one piece of evidence's timestamp against a claim's under an
/// explicit [`FreshnessWindow`] (FORNX-92). Pure and clock-free — compares
/// two already-stored timestamps, never reads the current time — so it stays
/// deterministic and replayable (AC5) no matter when it's called.
pub fn staleness_of(
    evidence: &Evidence,
    claim: &Claim,
    window: FreshnessWindow,
) -> StalenessAssessment {
    let max_age_seconds = match window {
        FreshnessWindow::Durable => return StalenessAssessment::NotTimeSensitive,
        FreshnessWindow::Perishable { max_age_seconds } => max_age_seconds,
    };
    let observed_at = match chrono::DateTime::parse_from_rfc3339(&evidence.observed_at) {
        Ok(t) => t,
        Err(_) => {
            return StalenessAssessment::Indeterminate {
                reason: "evidence.observed_at is not valid RFC3339",
            }
        }
    };
    let claimed_at = match chrono::DateTime::parse_from_rfc3339(&claim.claimed_at) {
        Ok(t) => t,
        Err(_) => {
            return StalenessAssessment::Indeterminate {
                reason: "claim.claimed_at is not valid RFC3339",
            }
        }
    };
    let age_seconds = (claimed_at - observed_at).num_seconds();
    if age_seconds < 0 {
        return StalenessAssessment::Indeterminate {
            reason: "evidence.observed_at is after claim.claimed_at",
        };
    }
    if age_seconds > max_age_seconds {
        StalenessAssessment::Stale { age_seconds }
    } else {
        StalenessAssessment::Fresh { age_seconds }
    }
}

/// Convenience wrapper over [`staleness_of`] using
/// [`EvidenceKind::default_freshness_window`] (FORNX-92). Prefer
/// [`staleness_of`] with an explicit window when a caller (e.g. FORNX-93)
/// has a better one for its claim.
pub fn staleness_of_default(evidence: &Evidence, claim: &Claim) -> StalenessAssessment {
    staleness_of(evidence, claim, evidence.kind.default_freshness_window())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_link(relation: EvidenceRelation) -> EvidenceLink {
        EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id: Uuid::new_v4(),
            evidence_id: Uuid::new_v4(),
            relation,
            linked_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn sample_missing() -> MissingEvidence {
        MissingEvidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id: Uuid::new_v4(),
            signal_class: SignalClass::ProcessResult,
            availability: SignalAvailability::Unavailable,
            detail: Some("no exit code sensor ran for this claim".into()),
            noted_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    // --- EvidenceRelation: closed three-state vocabulary -----------------

    #[test]
    fn evidence_relation_has_exactly_three_states_with_stable_wire_names() {
        let cases = [
            (EvidenceRelation::Supports, "supports"),
            (EvidenceRelation::Contradicts, "contradicts"),
            (EvidenceRelation::Neutral, "neutral"),
        ];
        for (relation, expected_wire_name) in cases {
            // Exhaustiveness check: every variant must be named here.
            match relation {
                EvidenceRelation::Supports
                | EvidenceRelation::Contradicts
                | EvidenceRelation::Neutral => {}
            }
            let json = serde_json::to_value(relation).unwrap();
            assert_eq!(json, serde_json::json!(expected_wire_name));
            let back: EvidenceRelation = serde_json::from_value(json).unwrap();
            assert_eq!(relation, back);
        }
    }

    // --- EvidenceLink round trip ------------------------------------------

    #[test]
    fn evidence_link_round_trips_through_json() {
        let link = sample_link(EvidenceRelation::Supports);
        let json = serde_json::to_string(&link).unwrap();
        let back: EvidenceLink = serde_json::from_str(&json).unwrap();
        assert_eq!(link, back);
    }

    // --- MissingEvidence round trip --------------------------------------

    #[test]
    fn missing_evidence_round_trips_through_json() {
        let missing = sample_missing();
        let json = serde_json::to_string(&missing).unwrap();
        let back: MissingEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(missing, back);
    }

    #[test]
    fn missing_evidence_detail_is_optional_and_omitted_when_absent() {
        let mut missing = sample_missing();
        missing.detail = None;
        let json = serde_json::to_value(&missing).unwrap();
        assert!(json.get("detail").is_none());
        let back: MissingEvidence = serde_json::from_value(json).unwrap();
        assert_eq!(back.detail, None);
    }

    // --- EvidenceGraph aggregate -------------------------------------------

    #[test]
    fn evidence_graph_bundles_links_and_missing_independently() {
        let graph = EvidenceGraph {
            links: vec![
                sample_link(EvidenceRelation::Supports),
                sample_link(EvidenceRelation::Supports),
                sample_link(EvidenceRelation::Contradicts),
            ],
            missing: vec![sample_missing()],
        };
        assert_eq!(graph.links.len(), 3);
        assert_eq!(graph.missing.len(), 1);
        assert_eq!(
            graph
                .links
                .iter()
                .filter(|l| l.relation == EvidenceRelation::Supports)
                .count(),
            2
        );
    }

    #[test]
    fn empty_evidence_graph_is_distinguishable_from_a_graph_with_only_missing_notes() {
        // The core product invariant this ticket exists for: zero links plus
        // zero missing notes ("nobody has looked") must remain distinct in
        // principle from zero links plus a non-empty missing list ("we
        // looked, evidence could not be collected"). Both are representable
        // by this type; nothing here collapses one into the other.
        let nobody_looked = EvidenceGraph::default();
        let looked_but_absent = EvidenceGraph {
            links: vec![],
            missing: vec![sample_missing()],
        };
        assert!(nobody_looked.links.is_empty() && nobody_looked.missing.is_empty());
        assert!(looked_but_absent.links.is_empty() && !looked_but_absent.missing.is_empty());
        assert_ne!(nobody_looked, looked_but_absent);
    }

    // --- EvidenceGraph::conflict (FORNX-92) --------------------------------

    #[test]
    fn conflict_surfaces_when_both_supports_and_contradicts_links_exist() {
        let supports = sample_link(EvidenceRelation::Supports);
        let contradicts = sample_link(EvidenceRelation::Contradicts);
        let graph = EvidenceGraph {
            links: vec![supports.clone(), contradicts.clone()],
            missing: vec![],
        };
        let conflict = graph
            .conflict()
            .expect("supports + contradicts must conflict");
        assert_eq!(conflict.supports, vec![supports]);
        assert_eq!(conflict.contradicts, vec![contradicts]);
    }

    #[test]
    fn no_conflict_when_links_agree_or_are_absent() {
        assert!(EvidenceGraph::default().conflict().is_none());
        let all_supports = EvidenceGraph {
            links: vec![
                sample_link(EvidenceRelation::Supports),
                sample_link(EvidenceRelation::Supports),
            ],
            missing: vec![],
        };
        assert!(all_supports.conflict().is_none());
        let neutral_only = EvidenceGraph {
            links: vec![sample_link(EvidenceRelation::Neutral)],
            missing: vec![],
        };
        assert!(neutral_only.conflict().is_none());
    }

    // --- staleness_of (FORNX-92) --------------------------------------------

    fn claim_at(claimed_at: &str) -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: claimed_at.into(),
        }
    }

    fn evidence_at(kind: EvidenceKind, observed_at: &str) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind,
            observed_at: observed_at.into(),
            payload: serde_json::json!({}),
            provenance: "test".into(),
            source: None,
            extension: None,
        }
    }

    #[test]
    fn durable_evidence_kind_is_never_time_sensitive_regardless_of_age() {
        // A file diff observed a year before the claim: a durable kind
        // never goes stale from elapsed time alone.
        let evidence = evidence_at(EvidenceKind::FileDiff, "2025-01-01T00:00:00Z");
        let claim = claim_at("2026-01-01T00:00:00Z");
        assert_eq!(
            staleness_of_default(&evidence, &claim),
            StalenessAssessment::NotTimeSensitive
        );
    }

    #[test]
    fn perishable_evidence_kind_is_stale_once_past_its_window() {
        let evidence = evidence_at(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let fresh_claim = claim_at("2026-01-01T00:30:00Z"); // 30 min later
        let stale_claim = claim_at("2026-01-01T02:00:00Z"); // 2 hours later
        assert_eq!(
            staleness_of_default(&evidence, &fresh_claim),
            StalenessAssessment::Fresh { age_seconds: 1800 }
        );
        assert_eq!(
            staleness_of_default(&evidence, &stale_claim),
            StalenessAssessment::Stale { age_seconds: 7200 }
        );
    }

    #[test]
    fn unparseable_timestamp_is_indeterminate_never_silently_fresh() {
        let evidence = evidence_at(EvidenceKind::ExitCode, "not-a-timestamp");
        let claim = claim_at("2026-01-01T00:30:00Z");
        assert!(matches!(
            staleness_of_default(&evidence, &claim),
            StalenessAssessment::Indeterminate { .. }
        ));
    }

    #[test]
    fn evidence_observed_after_the_claim_is_indeterminate_not_fresh() {
        let evidence = evidence_at(EvidenceKind::ExitCode, "2026-01-01T01:00:00Z");
        let claim = claim_at("2026-01-01T00:00:00Z");
        assert!(matches!(
            staleness_of_default(&evidence, &claim),
            StalenessAssessment::Indeterminate { .. }
        ));
    }
}
