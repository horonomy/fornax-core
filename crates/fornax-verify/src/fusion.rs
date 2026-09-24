//! Deterministic evidence-fusion engine (FORNX-93, parent epic FORNX-66).
//!
//! Today, one claim gets exactly one [`fornax_types::Finding`] from one
//! [`crate::Verifier`], each carrying zero or one evidence id. FORNX-89's
//! evidence graph ([`fornax_types::EvidenceGraph`]) is the richer read-side
//! model this engine actually consumes — a claim's full set of
//! [`fornax_types::EvidenceLink`]s and [`fornax_types::MissingEvidence`]
//! notes — but nothing on the live claim path writes graph rows yet. This
//! module therefore works against either:
//!
//! - a real, persisted [`fornax_types::EvidenceGraph`] (once FORNX-90/a
//!   future ticket wires collection into it), or
//! - an **in-memory projection** ([`project_graph`]) built from today's
//!   existing `Finding`s, so this engine has something real to run against
//!   and be tested against right now.
//!
//! # Scope
//!
//! [`FusionPolicy`] combines a claim's evidence graph into one
//! [`FusedFinding`]: a [`fornax_types::Verdict`] (the same five-state
//! vocabulary verifiers already use, never widened), an [`UncertaintyBand`]
//! (explicitly *not* a confidence percentage — see that type's doc comment),
//! and a full [`RationaleEntry`] trail naming every rule that counted,
//! discounted, or merely noted a piece of evidence. [`BaselineFusionPolicy`]
//! is the first, deterministic implementation of that trait.
//!
//! `FusedFinding` is a **new** type, not an extension of
//! [`fornax_types::Finding`] — `Finding` is a persisted row with fixed DB
//! columns rendered by the existing daemon/CLI; extending it would violate
//! this ticket's AC that fusion be "replaceable/benchmarked without changing
//! collector/storage/UI contracts."
//!
//! # Out of scope for this ticket (real follow-ups, not gaps)
//!
//! - Persisting projected links from the live claim path, or wiring
//!   [`FusionPolicy::fuse`] into `fornax-daemon`/`fornax-cli` at all — both
//!   need a migration and a render surface, exactly the storage/UI contract
//!   this ticket must stay decoupled from.
//! - FORNX-94 (a semantic/LLM-judge evidence source), FORNX-95
//!   (calibration/benchmarking of a trust-weighted policy), FORNX-96
//!   (decision UX). [`BaselineFusionPolicy`] does **not** weight by
//!   [`fornax_types::TrustClass`] — it records each counted link's trust
//!   class in its rationale detail text, but never lets it change a
//!   verdict; calibrating that is explicitly FORNX-95's job.
//!
//! # Known divergence from `EvidenceGraph::conflict()`
//!
//! [`fornax_types::EvidenceGraph::conflict`] (FORNX-92) reports a conflict
//! whenever *raw* `Supports` and `Contradicts` links both exist on a claim,
//! with no regard for whether either link would actually survive fusion's
//! rules. `BaselineFusionPolicy::fuse`'s `unresolved_conflict` field only
//! agrees with it when neither side is filtered out downstream — a
//! `Supports` link demoted by [`FusionRule::StaleSupportDemoted`] (R4),
//! for example, leaves `conflict()` reporting `Some` (it still sees the raw
//! link) while `fuse` reports no conflict at all (that link never counted).
//! This is intentional, not a bug: `conflict()` is a raw-link inspection
//! tool — `fuse`'s `unresolved_conflict` is specifically about the votes
//! that survived fusion. See
//! `fusion_tests::stale_support_demotion_diverges_from_raw_graph_conflict`.
//!
//! # Why `fuse` is pure and sync
//!
//! [`FusionPolicy::fuse`] takes no `&self` mutable state, does no I/O, and
//! is not `async`. This is deliberate, not an oversight: a future
//! LLM-judge-derived evidence source (FORNX-94) enters as an ordinary
//! [`fornax_types::EvidenceLink`] *upstream* of this trait — collected,
//! scored, and linked before fusion ever runs — never as something this
//! trait calls out to mid-fusion. Keeping `fuse` pure is what makes
//! [`FusedFinding::computed_at`] (passed in, never read from the clock
//! inside `fuse`) a real replay guarantee: the same frozen evidence,
//! replayed through the same pinned policy/version, must produce
//! byte-identical output.

use std::collections::{BTreeMap, HashSet};

use fornax_types::{
    staleness_of_default, Claim, Evidence, EvidenceGraph, EvidenceLink, EvidenceRelation, Finding,
    MissingEvidence, SignalAvailability, SignalClass, StalenessAssessment, Verdict,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Fusion's input contract (FORNX-93 AC: "fusion input contract over claim +
/// evidence graph + capability/quality metadata"). Deliberately narrow:
///
/// - No `RuntimeCapabilities` parameter — availability already reaches
///   fusion via [`MissingEvidence::availability`]; a claim's graph already
///   encodes what the runtime could/couldn't observe.
/// - No freshness-override parameter — [`fornax_types::staleness_of_default`]
///   is used; a future calibration policy can add its own window logic
///   behind [`FusionPolicy`] without changing this struct.
/// - No separate quality-metadata parameter — correlation/trust/derivation
///   already live on `Evidence::source: Option<EvidenceSource>` (FORNX-92),
///   reachable via `evidence`.
pub struct FusionInput<'a> {
    pub claim: &'a Claim,
    pub graph: &'a EvidenceGraph,
    /// Every [`Evidence`] the graph's links may reference. A link whose
    /// `evidence_id` has no matching entry here is unresolvable — recorded
    /// as a caveat via [`FusionRule::EvidenceUnresolved`], never dropped
    /// silently and never counted.
    pub evidence: &'a [Evidence],
}

/// How much uncertainty a [`FusedFinding`] carries, fully reconstructible
/// from its `rationale`. **Carries no calibration claim whatsoever** — this
/// is an ordinal band describing *why* a verdict might be shakier or
/// sturdier, not a probability. It must never be rendered as a percentage,
/// compared numerically, or averaged/interpolated across policy versions —
/// two different [`FusionPolicy`] implementations (or two versions of the
/// same one) may bucket the same evidence into different bands for reasons
/// specific to that policy's rules. See FORNX-93 AC: "No 'honesty
/// percentage' is shown without documented calibration semantics" — this
/// type is the documented alternative, not a stand-in for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyBand {
    /// At least one counted link, nothing discounted, no missing expected
    /// signal, no unresolved conflict, and every counted vote came from a
    /// distinct correlation group (never `correlation_group: None`, never a
    /// collapsed duplicate). **Unreachable on real traffic today**: no
    /// shipped sensor stamps `EvidenceSource::correlation_group` yet
    /// (FORNX-92), so every real counted vote currently carries `None` and
    /// therefore an `IndependenceUnverified` caveat, landing in `Qualified`
    /// instead. This band exists for the day a sensor does record
    /// correlation groups; see `fusion_tests::two_supports_in_distinct_correlation_groups_are_corroborated`
    /// for the only path that reaches it today.
    Corroborated,
    /// Rests on real evidence, but at least one caveat fired: a stale
    /// contradiction was retained, a freshness check was indeterminate, a
    /// correlation group collapsed duplicate votes, a counted vote had no
    /// recorded correlation group at all, a derived-evidence caveat fired,
    /// or some link was discounted outright.
    Qualified,
    /// No supporting or contradicting vote survived fusion at all — either
    /// an expected signal is explicitly missing, or the only links present
    /// were `Neutral`/discounted.
    Undetermined,
    /// Both `Supports` and `Contradicts` were counted and neither
    /// dominates; genuinely unresolved.
    Conflicted,
}

/// Closed vocabulary of every rule [`BaselineFusionPolicy`] can fire. Stable
/// snake_case wire names — this is a persisted-adjacent, inspectable
/// vocabulary (FORNX-93 AC: "user can inspect the evidence/rules that drove
/// a result"), not internal-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FusionRule {
    /// R1: a link's `evidence_id` has no matching entry in
    /// [`FusionInput::evidence`] — discounted, never treated as a
    /// contradiction.
    EvidenceUnresolved,
    /// R2: a `Neutral` link never votes either way.
    NeutralNotCounted,
    /// R3a: this link's evidence is `derived_from` the evidence of another
    /// counted link on the same claim — discounted to prevent a derived
    /// fact from double-corroborating its own source.
    DerivedFromCountedParent,
    /// R3b: this link's evidence is derived from something, but that
    /// something isn't itself a link on this claim — counts, with a
    /// caveat.
    DerivedEvidence,
    /// R4: stale evidence must never silently support a time-sensitive
    /// claim — demoted, does not count.
    StaleSupportDemoted,
    /// R4: a stale *contradiction* is retained — discarding it would be the
    /// unsafe direction.
    StaleContradictionRetained,
    /// R4: freshness could not be determined — counts, never silently
    /// coerced to fresh.
    FreshnessIndeterminate,
    /// R5: two or more counted links shared a correlation group and the
    /// same relation — collapsed to one effective vote.
    CorrelationCollapsed,
    /// R5: a counted link's evidence carries no recorded correlation group.
    /// `None` means "no correlation recorded", not "proven independent".
    IndependenceUnverified,
    /// R6: links existed on this claim, but none survived as a counted
    /// vote (unresolved, neutral, or discounted) — `Unverified`, never
    /// `Contradicted`.
    AllSupportDiscounted,
    /// R6: the final verdict decision, summarizing the counted votes (or
    /// their absence) that produced it.
    VerdictDecided,
}

/// What a [`RationaleEntry`] did to the links/missing-evidence it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Contributed to the final `Supports`/`Contradicts` vote tally.
    Counted,
    /// Excluded from the vote tally entirely.
    Discounted,
    /// Counted, but with a caveat attached (or otherwise informational —
    /// see [`FusionRule::NeutralNotCounted`]).
    Caveat,
    /// The final verdict decision itself.
    Decided,
}

/// One inspectable step of fusion (FORNX-93 AC: "user can inspect the
/// evidence/rules that drove a result"). Every `Uuid` appearing in
/// `link_ids`, `missing_evidence_ids`, or `evidence_ids` is guaranteed, by
/// construction, to exist in the [`FusionInput`] that produced it —
/// `detail` must never fabricate an id that doesn't actually belong to
/// something in those three vectors or the input. `detail` may also name a
/// correlation-group id (a distinct id namespace from links/evidence/missing
/// entries, see [`FusionRule::CorrelationCollapsed`]) that is real (drawn
/// from the input evidence's `correlation_group`) but deliberately not
/// tracked in a dedicated vector on this struct.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RationaleEntry {
    pub rule: FusionRule,
    pub effect: RuleEffect,
    pub link_ids: Vec<Uuid>,
    pub missing_evidence_ids: Vec<Uuid>,
    pub evidence_ids: Vec<Uuid>,
    pub detail: String,
}

/// Output of `FusionPolicy::fuse` — a new type, not an extension of
/// [`fornax_types::Finding`] (see module docs). Reuses
/// [`fornax_types::Verdict`] verbatim; never invents a sixth state.
///
/// **No float/numeric confidence score anywhere on this type or its
/// serialization** — see `fusion_tests::fused_finding_json_carries_no_numeric_confidence_field`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FusedFinding {
    pub claim_id: Uuid,
    pub verdict: Verdict,
    pub uncertainty: UncertaintyBand,
    pub rationale: Vec<RationaleEntry>,
    pub counted_link_ids: Vec<Uuid>,
    pub discounted_link_ids: Vec<Uuid>,
    pub missing_evidence_ids: Vec<Uuid>,
    pub unresolved_conflict: bool,
    pub policy_name: String,
    pub policy_version: u32,
    /// RFC3339 timestamp, passed in by the caller — `fuse` never calls
    /// `Utc::now()` itself. See the module docs' "why `fuse` is pure and
    /// sync" section.
    pub computed_at: String,
}

/// Swap/benchmark boundary for fusion (FORNX-93 AC: "fusion implementation
/// can be replaced/benchmarked without changing collector/storage/UI
/// contracts"). Mirrors [`crate::Verifier`]'s shape for consistency.
/// Deliberately no `applies_to` — fusion consumes a graph, not claim text,
/// so it is claim-subject-agnostic, unlike a `Verifier`.
pub trait FusionPolicy {
    /// Stable identity, recorded on every [`FusedFinding::policy_name`] this
    /// policy produces.
    fn name(&self) -> &'static str;

    /// This policy's own version — bump whenever its rules change in a way
    /// that could change output for the same input, so a replay can pin an
    /// exact version (FORNX-93 AC: "same frozen evidence produces
    /// reproducible fusion output for a pinned policy/version").
    fn policy_version(&self) -> u32;

    /// Pure and sync — see the module docs' "why `fuse` is pure and sync"
    /// section. `computed_at` is stamped onto the output verbatim.
    fn fuse(&self, input: &FusionInput<'_>, computed_at: &str) -> FusedFinding;
}

fn is_concerning_availability(a: &SignalAvailability) -> bool {
    matches!(
        a,
        SignalAvailability::Unsupported
            | SignalAvailability::Unavailable
            | SignalAvailability::CollectionFailed
            | SignalAvailability::Redacted
            | SignalAvailability::Disabled
    )
}

/// The first, deterministic [`FusionPolicy`] implementation (FORNX-93).
/// Never weights by [`fornax_types::TrustClass`] — see module docs.
pub struct BaselineFusionPolicy;

/// One candidate link surviving to a given phase, paired with its resolved
/// [`Evidence`].
struct Candidate<'a> {
    link: &'a EvidenceLink,
    evidence: &'a Evidence,
}

impl FusionPolicy for BaselineFusionPolicy {
    fn name(&self) -> &'static str {
        "deterministic_baseline_v1"
    }

    fn policy_version(&self) -> u32 {
        1
    }

    fn fuse(&self, input: &FusionInput<'_>, computed_at: &str) -> FusedFinding {
        let claim = input.claim;
        let graph = input.graph;

        // R0: canonical ordering — sort by id before evaluating and before
        // emitting output id vectors, so replay is byte-identical
        // regardless of DB/caller row order.
        let mut links: Vec<&EvidenceLink> = graph.links.iter().collect();
        links.sort_by_key(|l| l.id);
        let mut missing: Vec<&MissingEvidence> = graph.missing.iter().collect();
        missing.sort_by_key(|m| m.id);

        let evidence_by_id: BTreeMap<Uuid, &Evidence> =
            input.evidence.iter().map(|e| (e.id, e)).collect();

        let mut rationale: Vec<RationaleEntry> = Vec::new();
        let mut discounted_link_ids: Vec<Uuid> = Vec::new();

        // --- R1 (unresolvable) / R2 (neutral) -----------------------------
        let mut candidates: Vec<Candidate<'_>> = Vec::new();
        for l in &links {
            let Some(ev) = evidence_by_id.get(&l.evidence_id) else {
                discounted_link_ids.push(l.id);
                rationale.push(RationaleEntry {
                    rule: FusionRule::EvidenceUnresolved,
                    effect: RuleEffect::Discounted,
                    link_ids: vec![l.id],
                    missing_evidence_ids: vec![],
                    evidence_ids: vec![],
                    detail: format!(
                        "link {} references evidence {} not present in the fusion input; \
                         treated as unresolvable, never counted, never treated as a contradiction",
                        l.id, l.evidence_id
                    ),
                });
                continue;
            };
            if l.relation == EvidenceRelation::Neutral {
                rationale.push(RationaleEntry {
                    rule: FusionRule::NeutralNotCounted,
                    effect: RuleEffect::Caveat,
                    link_ids: vec![l.id],
                    missing_evidence_ids: vec![],
                    evidence_ids: vec![l.evidence_id],
                    detail: format!("link {} is Neutral; it never votes either way", l.id),
                });
                continue;
            }
            candidates.push(Candidate {
                link: l,
                evidence: ev,
            });
        }

        // --- R3: derived-evidence double-count exclusion -------------------
        let candidate_evidence_ids: HashSet<Uuid> =
            candidates.iter().map(|c| c.link.evidence_id).collect();
        let mut after_r3: Vec<Candidate<'_>> = Vec::new();
        for c in candidates {
            let derived_from = c
                .evidence
                .source
                .as_ref()
                .map(|s| s.derived_from.as_slice())
                .unwrap_or(&[]);
            if derived_from.is_empty() {
                after_r3.push(c);
                continue;
            }
            let parent_hits: Vec<Uuid> = derived_from
                .iter()
                .filter(|p| **p != c.link.evidence_id && candidate_evidence_ids.contains(p))
                .cloned()
                .collect();
            if parent_hits.is_empty() {
                rationale.push(RationaleEntry {
                    rule: FusionRule::DerivedEvidence,
                    effect: RuleEffect::Caveat,
                    link_ids: vec![c.link.id],
                    missing_evidence_ids: vec![],
                    evidence_ids: vec![c.link.evidence_id],
                    detail: format!(
                        "link {}'s evidence is derived from other evidence not itself linked \
                         on this claim; counted, with a derived-evidence caveat",
                        c.link.id
                    ),
                });
                after_r3.push(c);
            } else {
                discounted_link_ids.push(c.link.id);
                rationale.push(RationaleEntry {
                    rule: FusionRule::DerivedFromCountedParent,
                    effect: RuleEffect::Discounted,
                    link_ids: vec![c.link.id],
                    missing_evidence_ids: vec![],
                    evidence_ids: {
                        let mut ids = vec![c.link.evidence_id];
                        ids.extend(parent_hits.iter().cloned());
                        ids
                    },
                    detail: format!(
                        "link {}'s evidence is derived from evidence {:?}, which already has \
                         its own counted link on this claim; discounted to avoid a derived \
                         fact double-corroborating its own source",
                        c.link.id, parent_hits
                    ),
                });
            }
        }

        // --- R4: staleness (asymmetric) ------------------------------------
        let mut after_r4: Vec<Candidate<'_>> = Vec::new();
        for c in after_r3 {
            match staleness_of_default(c.evidence, claim) {
                StalenessAssessment::NotTimeSensitive | StalenessAssessment::Fresh { .. } => {
                    after_r4.push(c);
                }
                StalenessAssessment::Stale { age_seconds } => {
                    if c.link.relation == EvidenceRelation::Supports {
                        discounted_link_ids.push(c.link.id);
                        rationale.push(RationaleEntry {
                            rule: FusionRule::StaleSupportDemoted,
                            effect: RuleEffect::Discounted,
                            link_ids: vec![c.link.id],
                            missing_evidence_ids: vec![],
                            evidence_ids: vec![c.link.evidence_id],
                            detail: format!(
                                "link {} supports the claim with evidence {age_seconds}s stale; \
                                 stale evidence must never silently support a time-sensitive \
                                 claim, so it does not count",
                                c.link.id
                            ),
                        });
                    } else {
                        rationale.push(RationaleEntry {
                            rule: FusionRule::StaleContradictionRetained,
                            effect: RuleEffect::Caveat,
                            link_ids: vec![c.link.id],
                            missing_evidence_ids: vec![],
                            evidence_ids: vec![c.link.evidence_id],
                            detail: format!(
                                "link {} contradicts the claim with evidence {age_seconds}s \
                                 stale; retained -- discarding a stale contradiction is the \
                                 unsafe direction",
                                c.link.id
                            ),
                        });
                        after_r4.push(c);
                    }
                }
                StalenessAssessment::Indeterminate { reason } => {
                    rationale.push(RationaleEntry {
                        rule: FusionRule::FreshnessIndeterminate,
                        effect: RuleEffect::Caveat,
                        link_ids: vec![c.link.id],
                        missing_evidence_ids: vec![],
                        evidence_ids: vec![c.link.evidence_id],
                        detail: format!(
                            "link {}'s freshness could not be determined ({reason}); counted, \
                             never silently coerced to fresh",
                            c.link.id
                        ),
                    });
                    after_r4.push(c);
                }
            }
        }

        // --- R5: correlation dedup -------------------------------------------
        let mut grouped: BTreeMap<(u8, Uuid), Vec<Candidate<'_>>> = BTreeMap::new();
        let mut ungrouped: Vec<Candidate<'_>> = Vec::new();
        for c in after_r4 {
            match c.evidence.source.as_ref().and_then(|s| s.correlation_group) {
                Some(group) => grouped
                    .entry((relation_key(c.link.relation), group))
                    .or_default()
                    .push(c),
                None => ungrouped.push(c),
            }
        }

        let mut final_counted: Vec<Candidate<'_>> = Vec::new();
        for ((_, group), mut bucket) in grouped {
            bucket.sort_by_key(|c| c.link.id);
            let representative_idx = 0;
            if bucket.len() > 1 {
                let representative_id = bucket[representative_idx].link.id;
                let sibling_ids: Vec<Uuid> = bucket[1..].iter().map(|c| c.link.id).collect();
                for sibling in bucket.iter().skip(1) {
                    discounted_link_ids.push(sibling.link.id);
                }
                // `link_ids` names every link this rule concerns, not only
                // the ones it discounted -- the representative (still
                // counted) is included alongside the discounted siblings so
                // the entry is self-contained for inspection.
                let mut entry_link_ids = sibling_ids.clone();
                entry_link_ids.push(representative_id);
                entry_link_ids.sort();
                rationale.push(RationaleEntry {
                    rule: FusionRule::CorrelationCollapsed,
                    effect: RuleEffect::Discounted,
                    link_ids: entry_link_ids,
                    missing_evidence_ids: vec![],
                    evidence_ids: bucket.iter().map(|c| c.link.evidence_id).collect(),
                    detail: format!(
                        "links {sibling_ids:?} share correlation group {group} and relation \
                         with link {representative_id}; collapsed to one effective vote \
                         (representative: link {representative_id})"
                    ),
                });
            }
            final_counted.push(bucket.into_iter().next().unwrap());
        }
        for c in ungrouped {
            rationale.push(RationaleEntry {
                rule: FusionRule::IndependenceUnverified,
                effect: RuleEffect::Caveat,
                link_ids: vec![c.link.id],
                missing_evidence_ids: vec![],
                evidence_ids: vec![c.link.evidence_id],
                detail: format!(
                    "link {}'s evidence carries no recorded correlation group; counted as an \
                     independent vote, but 'no group recorded' is not the same as 'proven \
                     independent'",
                    c.link.id
                ),
            });
            final_counted.push(c);
        }

        let s = final_counted
            .iter()
            .filter(|c| c.link.relation == EvidenceRelation::Supports)
            .count();
        let c_count = final_counted
            .iter()
            .filter(|c| c.link.relation == EvidenceRelation::Contradicts)
            .count();

        let mut counted_link_ids: Vec<Uuid> = final_counted.iter().map(|c| c.link.id).collect();
        counted_link_ids.sort();
        discounted_link_ids.sort();
        let missing_evidence_ids: Vec<Uuid> = missing.iter().map(|m| m.id).collect();

        // --- R6: verdict decision --------------------------------------------
        let unresolved_conflict = s > 0 && c_count > 0;
        let (verdict, decision_rule, decision_detail, decision_missing_ids, decision_link_ids) =
            if unresolved_conflict {
                (
                    Verdict::Review,
                    FusionRule::VerdictDecided,
                    format!(
                        "{s} distinct supporting vote(s) and {c_count} distinct contradicting \
                         vote(s) survived fusion; unresolved conflict, not auto-resolved"
                    ),
                    vec![],
                    counted_link_ids.clone(),
                )
            } else if c_count > 0 {
                (
                    Verdict::Contradicted,
                    FusionRule::VerdictDecided,
                    format!(
                        "{c_count} distinct contradicting vote(s) survived fusion, no \
                         supporting votes"
                    ),
                    vec![],
                    counted_link_ids.clone(),
                )
            } else if s > 0 {
                (
                    Verdict::Verified,
                    FusionRule::VerdictDecided,
                    format!(
                        "{s} distinct supporting vote(s) survived fusion, no contradicting votes"
                    ),
                    vec![],
                    counted_link_ids.clone(),
                )
            } else {
                let concerning_missing: Vec<Uuid> = missing
                    .iter()
                    .filter(|m| is_concerning_availability(&m.availability))
                    .map(|m| m.id)
                    .collect();
                if !concerning_missing.is_empty() {
                    (
                        Verdict::Unavailable,
                        FusionRule::VerdictDecided,
                        format!(
                            "no supporting or contradicting evidence survived fusion; {} \
                             expected signal(s) explicitly noted missing/unavailable",
                            concerning_missing.len()
                        ),
                        concerning_missing,
                        vec![],
                    )
                } else if !missing.is_empty() {
                    (
                        Verdict::Unverified,
                        FusionRule::VerdictDecided,
                        format!(
                            "no supporting or contradicting evidence survived fusion; {} \
                             missing-evidence note(s) present but only Unknown/Unrecognized \
                             availability, not treated as a confirmed absence",
                            missing.len()
                        ),
                        missing_evidence_ids.clone(),
                        vec![],
                    )
                } else if !links.is_empty() {
                    (
                        Verdict::Unverified,
                        FusionRule::AllSupportDiscounted,
                        format!(
                            "{} link(s) existed on this claim but none survived fusion as a \
                             counted vote (unresolved, neutral, or discounted); not treated as \
                             a contradiction",
                            links.len()
                        ),
                        vec![],
                        links.iter().map(|l| l.id).collect(),
                    )
                } else {
                    (
                        Verdict::Unverified,
                        FusionRule::VerdictDecided,
                        "no evidence links and no missing-evidence notes recorded for this \
                         claim -- nobody has looked yet, distinct from evidence having been \
                         sought and found absent"
                            .to_string(),
                        vec![],
                        vec![],
                    )
                }
            };

        rationale.push(RationaleEntry {
            rule: decision_rule,
            effect: RuleEffect::Decided,
            link_ids: decision_link_ids,
            missing_evidence_ids: decision_missing_ids,
            evidence_ids: vec![],
            detail: decision_detail,
        });

        let banding_caveat = rationale.iter().any(|r| {
            matches!(
                r.rule,
                FusionRule::DerivedEvidence
                    | FusionRule::StaleContradictionRetained
                    | FusionRule::FreshnessIndeterminate
                    | FusionRule::IndependenceUnverified
            )
        });
        let uncertainty = if unresolved_conflict {
            UncertaintyBand::Conflicted
        } else if s == 0 && c_count == 0 {
            UncertaintyBand::Undetermined
        } else if banding_caveat || !discounted_link_ids.is_empty() || !missing.is_empty() {
            UncertaintyBand::Qualified
        } else {
            UncertaintyBand::Corroborated
        };

        FusedFinding {
            claim_id: claim.id,
            verdict,
            uncertainty,
            rationale,
            counted_link_ids,
            discounted_link_ids,
            missing_evidence_ids,
            unresolved_conflict,
            policy_name: self.name().to_string(),
            policy_version: self.policy_version(),
            computed_at: computed_at.to_string(),
        }
    }
}

fn relation_key(r: EvidenceRelation) -> u8 {
    match r {
        EvidenceRelation::Supports => 0,
        EvidenceRelation::Contradicts => 1,
        EvidenceRelation::Neutral => 2,
    }
}

/// This verifier's declared expected [`SignalClass`]es, read from its own
/// real capability gate in `crate` (see each verifier's `verify()` — this
/// mirrors those checks rather than guessing). Falls back to the
/// `ToolTrace`/`FinalResponse` pair (the majority case) for any verifier
/// name this function doesn't recognize, so a future verifier this module
/// doesn't yet know about still gets a reasonable, honestly-labeled
/// approximation rather than a panic.
///
/// Deliberately a private helper matching on `Finding::verifier_name`
/// rather than an addition to the `Verifier` trait itself — this keeps
/// FORNX-93 additive to `fornax-verify` alone, with no change to the
/// existing trait's shape or its five implementors.
fn expected_signal_classes_for_verifier(verifier_name: &str) -> &'static [SignalClass] {
    match verifier_name {
        "file_modified_verifier_v1" | "git_operation_verifier_v1" => {
            &[SignalClass::ToolTrace, SignalClass::ToolResultPayload]
        }
        _ => &[SignalClass::ToolTrace, SignalClass::FinalResponse],
    }
}

/// Namespace for [`project_graph`]'s deterministic id derivation — an
/// arbitrary fixed UUID, not a real evidence/link id, used only as the
/// `Uuid::new_v5` namespace argument.
const PROJECTION_NAMESPACE: Uuid = Uuid::from_bytes([
    0x8f, 0x1a, 0x4b, 0x93, 0x2c, 0x6e, 0x4d, 0x71, 0x9a, 0x0e, 0x53, 0x1c, 0xaf, 0x2b, 0x77, 0xd4,
]);

/// Deterministic id for a link/missing-evidence entry `project_graph`
/// derives from `finding` -- keeps `project_graph` a pure function of its
/// inputs (same `findings`/`evidence`, called twice, produces byte-identical
/// output), rather than a fresh random id every call.
fn projected_id(finding_id: Uuid, tag: &str) -> Uuid {
    Uuid::new_v5(
        &PROJECTION_NAMESPACE,
        format!("{finding_id}:{tag}").as_bytes(),
    )
}

/// Build an in-memory [`EvidenceGraph`] projection from today's existing
/// `Finding`s (FORNX-93) — pure, never persisted. This is what makes
/// [`BaselineFusionPolicy`] testable against real verifier output today,
/// ahead of FORNX-89's graph actually being populated on the live claim
/// path. `findings` not belonging to `claim` are ignored.
///
/// Mapping (deliberate, see module docs for the `Review` fidelity gap):
/// - `Verified` -> one `Supports` link per `finding.evidence_ids` entry.
/// - `Contradicted` -> one `Contradicts` link per `finding.evidence_ids`
///   entry.
/// - `Unavailable` -> one [`MissingEvidence`] per
///   [`expected_signal_classes_for_verifier`], `availability: Unavailable`,
///   `detail` carrying the verifier's own rationale.
/// - `Unverified` -> nothing (this is the FORNX-89 "nobody looked" case
///   only when *no* finding at all exists for a claim; an explicit
///   `Unverified` finding already recorded that nothing matched, which
///   projects to no graph entries, and `fuse` still reaches `Unverified`
///   via its own "no links, no missing" branch).
/// - `Review` -> one `Neutral` link per `finding.evidence_ids` entry (or a
///   single entry with no evidence id represented, for a `Review` finding
///   with none). This is a **known, deliberate fidelity gap**: a
///   hypothetical `Review -> MissingEvidence` projection was considered and
///   rejected, to avoid leaking per-verifier `Review` semantics into this
///   projection. See `fusion_tests::review_finding_projects_to_neutral_and_refuses_to_re_promote`
///   for the resulting, documented `Review -> Unverified` re-fusion
///   behavior.
pub fn project_graph(claim: &Claim, findings: &[Finding]) -> EvidenceGraph {
    let mut links = Vec::new();
    let mut missing = Vec::new();

    for finding in findings.iter().filter(|f| f.claim_id == claim.id) {
        match finding.verdict {
            Verdict::Verified => {
                for eid in &finding.evidence_ids {
                    links.push(EvidenceLink {
                        id: projected_id(finding.id, &format!("supports:{eid}")),
                        session_id: claim.session_id.clone(),
                        claim_id: claim.id,
                        evidence_id: *eid,
                        relation: EvidenceRelation::Supports,
                        linked_at: finding.computed_at.clone(),
                    });
                }
            }
            Verdict::Contradicted => {
                for eid in &finding.evidence_ids {
                    links.push(EvidenceLink {
                        id: projected_id(finding.id, &format!("contradicts:{eid}")),
                        session_id: claim.session_id.clone(),
                        claim_id: claim.id,
                        evidence_id: *eid,
                        relation: EvidenceRelation::Contradicts,
                        linked_at: finding.computed_at.clone(),
                    });
                }
            }
            Verdict::Review => {
                for eid in &finding.evidence_ids {
                    links.push(EvidenceLink {
                        id: projected_id(finding.id, &format!("neutral:{eid}")),
                        session_id: claim.session_id.clone(),
                        claim_id: claim.id,
                        evidence_id: *eid,
                        relation: EvidenceRelation::Neutral,
                        linked_at: finding.computed_at.clone(),
                    });
                }
            }
            Verdict::Unverified => {}
            Verdict::Unavailable => {
                for class in expected_signal_classes_for_verifier(&finding.verifier_name) {
                    missing.push(MissingEvidence {
                        id: projected_id(finding.id, &format!("missing:{class:?}")),
                        session_id: claim.session_id.clone(),
                        claim_id: claim.id,
                        signal_class: class.clone(),
                        availability: SignalAvailability::Unavailable,
                        detail: Some(finding.rationale.clone()),
                        noted_at: finding.computed_at.clone(),
                    });
                }
            }
        }
    }

    EvidenceGraph { links, missing }
}

#[cfg(test)]
mod fusion_tests {
    use super::*;
    use fornax_types::{ClockSource, CollectionMethod, EvidenceKind, EvidenceSource, TrustClass};

    fn claim() -> Claim {
        Claim {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            text: "the command exited successfully".into(),
            subject: "command_succeeded".into(),
            claimed_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn evidence(kind: EvidenceKind, observed_at: &str) -> Evidence {
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

    fn link(claim_id: Uuid, evidence_id: Uuid, relation: EvidenceRelation) -> EvidenceLink {
        EvidenceLink {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id,
            evidence_id,
            relation,
            linked_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn missing(claim_id: Uuid, availability: SignalAvailability) -> MissingEvidence {
        MissingEvidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            claim_id,
            signal_class: SignalClass::ProcessResult,
            availability,
            detail: None,
            noted_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn source_with_group(group: Uuid) -> EvidenceSource {
        EvidenceSource {
            sensor_name: "test_sensor".into(),
            trust_class: TrustClass::AgentAdjacent,
            collected_at: "2026-01-01T00:00:00Z".into(),
            provider: None,
            collection_method: CollectionMethod::HookCallback,
            collector_version: None,
            freshness: fornax_types::Freshness {
                clock_source: ClockSource::HostClock,
                caveat: None,
            },
            tamper_boundary: Default::default(),
            correlation_group: Some(group),
            derived_from: vec![],
        }
    }

    // --- 1. Determinism / replay -----------------------------------------

    #[test]
    fn fuse_is_deterministic_across_shuffled_link_order() {
        let c = claim();
        let ev1 = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let ev2 = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let ev3 = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let l1 = link(c.id, ev1.id, EvidenceRelation::Supports);
        let l2 = link(c.id, ev2.id, EvidenceRelation::Supports);
        let l3 = link(c.id, ev3.id, EvidenceRelation::Contradicts);
        let evidence_pool = vec![ev1, ev2, ev3];

        let graph_a = EvidenceGraph {
            links: vec![l1.clone(), l2.clone(), l3.clone()],
            missing: vec![],
        };
        let graph_b = EvidenceGraph {
            links: vec![l3, l1, l2],
            missing: vec![],
        };

        let policy = BaselineFusionPolicy;
        let input_a = FusionInput {
            claim: &c,
            graph: &graph_a,
            evidence: &evidence_pool,
        };
        let input_b = FusionInput {
            claim: &c,
            graph: &graph_b,
            evidence: &evidence_pool,
        };
        let out_a = policy.fuse(&input_a, "2026-01-02T00:00:00Z");
        let out_b = policy.fuse(&input_b, "2026-01-02T00:00:00Z");
        assert_eq!(out_a, out_b);

        // Calling twice on the identical input is also byte-identical.
        let out_a_again = policy.fuse(&input_a, "2026-01-02T00:00:00Z");
        assert_eq!(out_a, out_a_again);
    }

    // --- 2/3. Missing-only vs empty graph ---------------------------------

    #[test]
    fn missing_only_graph_is_unavailable_never_contradicted() {
        let c = claim();
        let m = missing(c.id, SignalAvailability::Unavailable);
        let graph = EvidenceGraph {
            links: vec![],
            missing: vec![m.clone()],
        };
        let policy = BaselineFusionPolicy;
        let input = FusionInput {
            claim: &c,
            graph: &graph,
            evidence: &[],
        };
        let out = policy.fuse(&input, "2026-01-02T00:00:00Z");
        assert_eq!(out.verdict, Verdict::Unavailable);
        assert_ne!(out.verdict, Verdict::Contradicted);
        assert_eq!(out.missing_evidence_ids, vec![m.id]);
        assert!(out
            .rationale
            .iter()
            .any(|r| r.missing_evidence_ids.contains(&m.id)));
    }

    #[test]
    fn empty_graph_differs_from_missing_only_graph() {
        let c = claim();
        let empty_graph = EvidenceGraph::default();
        let missing_graph = EvidenceGraph {
            links: vec![],
            missing: vec![missing(c.id, SignalAvailability::Unavailable)],
        };
        let policy = BaselineFusionPolicy;

        let empty_out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &empty_graph,
                evidence: &[],
            },
            "2026-01-02T00:00:00Z",
        );
        let missing_out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &missing_graph,
                evidence: &[],
            },
            "2026-01-02T00:00:00Z",
        );

        assert_eq!(empty_out.verdict, Verdict::Unverified);
        assert_eq!(missing_out.verdict, Verdict::Unavailable);
        assert_ne!(empty_out.verdict, missing_out.verdict);
    }

    // --- 4. Conflict agrees with EvidenceGraph::conflict -------------------

    #[test]
    fn supports_and_contradicts_produce_review_and_agree_with_graph_conflict() {
        let c = claim();
        let ev_s = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let ev_c = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let l_s = link(c.id, ev_s.id, EvidenceRelation::Supports);
        let l_c = link(c.id, ev_c.id, EvidenceRelation::Contradicts);
        let graph = EvidenceGraph {
            links: vec![l_s, l_c],
            missing: vec![],
        };
        assert!(graph.conflict().is_some());

        let policy = BaselineFusionPolicy;
        let input = FusionInput {
            claim: &c,
            graph: &graph,
            evidence: &[ev_s, ev_c],
        };
        let out = policy.fuse(&input, "2026-01-02T00:00:00Z");
        assert_eq!(out.verdict, Verdict::Review);
        assert!(out.unresolved_conflict);
        assert_eq!(out.uncertainty, UncertaintyBand::Conflicted);
    }

    // --- 5. Correlation collapse: 3-supports and 3-vs-1 conflict ----------

    #[test]
    fn three_correlated_supports_collapse_to_one_counted_vote() {
        let c = claim();
        let group = Uuid::new_v4();
        let evs: Vec<Evidence> = (0..3)
            .map(|_| {
                let mut e = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
                e.source = Some(source_with_group(group));
                e
            })
            .collect();
        let links: Vec<EvidenceLink> = evs
            .iter()
            .map(|e| link(c.id, e.id, EvidenceRelation::Supports))
            .collect();
        let graph = EvidenceGraph {
            links,
            missing: vec![],
        };
        let policy = BaselineFusionPolicy;
        let input = FusionInput {
            claim: &c,
            graph: &graph,
            evidence: &evs,
        };
        let out = policy.fuse(&input, "2026-01-02T00:00:00Z");
        assert_eq!(out.verdict, Verdict::Verified);
        assert_eq!(out.counted_link_ids.len(), 1);
        assert_eq!(out.discounted_link_ids.len(), 2);
        assert!(out
            .rationale
            .iter()
            .any(|r| r.rule == FusionRule::CorrelationCollapsed));
    }

    #[test]
    fn three_supports_vs_one_contradict_in_one_group_still_resolves_to_review() {
        let c = claim();
        let group = Uuid::new_v4();
        let support_evs: Vec<Evidence> = (0..3)
            .map(|_| {
                let mut e = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
                e.source = Some(source_with_group(group));
                e
            })
            .collect();
        let mut contradict_ev = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        contradict_ev.source = Some(source_with_group(group));

        let mut links: Vec<EvidenceLink> = support_evs
            .iter()
            .map(|e| link(c.id, e.id, EvidenceRelation::Supports))
            .collect();
        links.push(link(c.id, contradict_ev.id, EvidenceRelation::Contradicts));

        let mut all_evs = support_evs;
        all_evs.push(contradict_ev);

        let graph = EvidenceGraph {
            links,
            missing: vec![],
        };
        let policy = BaselineFusionPolicy;
        let input = FusionInput {
            claim: &c,
            graph: &graph,
            evidence: &all_evs,
        };
        let out = policy.fuse(&input, "2026-01-02T00:00:00Z");
        // NOT "supports wins 3-1" -- the group collapses to one vote per
        // relation, leaving exactly one Supports vote vs one Contradicts
        // vote, i.e. a genuine conflict.
        assert_eq!(out.verdict, Verdict::Review);
        assert!(out.unresolved_conflict);
        assert_eq!(out.counted_link_ids.len(), 2);
    }

    // --- 6. Uncorrelated supports each count independently -----------------

    #[test]
    fn three_uncorrelated_supports_each_count_with_independence_unverified_caveat() {
        let c = claim();
        let evs: Vec<Evidence> = (0..3)
            .map(|_| evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z"))
            .collect();
        let links: Vec<EvidenceLink> = evs
            .iter()
            .map(|e| link(c.id, e.id, EvidenceRelation::Supports))
            .collect();
        let graph = EvidenceGraph {
            links,
            missing: vec![],
        };
        let policy = BaselineFusionPolicy;
        let input = FusionInput {
            claim: &c,
            graph: &graph,
            evidence: &evs,
        };
        let out = policy.fuse(&input, "2026-01-02T00:00:00Z");
        assert_eq!(out.verdict, Verdict::Verified);
        assert_eq!(out.counted_link_ids.len(), 3);
        assert!(out.discounted_link_ids.is_empty());
        let independence_caveats = out
            .rationale
            .iter()
            .filter(|r| r.rule == FusionRule::IndependenceUnverified)
            .count();
        assert_eq!(independence_caveats, 3);
        assert_eq!(out.uncertainty, UncertaintyBand::Qualified);
    }

    /// [`UncertaintyBand::Corroborated`] requires every counted vote to
    /// carry its *own* recorded correlation group -- distinct from every
    /// other counted vote's group, never `None` (which fires
    /// `IndependenceUnverified` -> `Qualified`, see the test above) and
    /// never collapsed with a sibling (`CorrelationCollapsed` -> also
    /// implies a non-empty `discounted_link_ids`, which alone forces
    /// `Qualified`). No sensor stamps a correlation group today (FORNX-92),
    /// so this band is unreachable on real traffic until one does --
    /// documented on the type itself, pinned here against direct
    /// `FusionInput` construction so a real future sensor path is exercised
    /// the moment it exists.
    #[test]
    fn two_supports_in_distinct_correlation_groups_are_corroborated() {
        let c = claim();
        let mut ev_a = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        ev_a.source = Some(source_with_group(Uuid::new_v4()));
        let mut ev_b = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        ev_b.source = Some(source_with_group(Uuid::new_v4()));
        let links = vec![
            link(c.id, ev_a.id, EvidenceRelation::Supports),
            link(c.id, ev_b.id, EvidenceRelation::Supports),
        ];
        let evs = vec![ev_a, ev_b];
        let graph = EvidenceGraph {
            links,
            missing: vec![],
        };
        let policy = BaselineFusionPolicy;
        let out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &evs,
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(out.verdict, Verdict::Verified);
        assert_eq!(out.counted_link_ids.len(), 2);
        assert!(out.discounted_link_ids.is_empty());
        assert!(out.missing_evidence_ids.is_empty());
        assert_eq!(out.uncertainty, UncertaintyBand::Corroborated);
    }

    // --- 7. Derived-from-counted-parent exclusion --------------------------

    #[test]
    fn evidence_derived_from_another_counted_links_evidence_is_discounted() {
        let c = claim();
        let parent_ev = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let mut derived_ev = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        derived_ev.source = Some(EvidenceSource::derived(
            "duration_sensor",
            TrustClass::AgentAdjacent,
            None,
            None,
            vec![parent_ev.id],
        ));

        let parent_link = link(c.id, parent_ev.id, EvidenceRelation::Supports);
        let derived_link = link(c.id, derived_ev.id, EvidenceRelation::Supports);
        let graph = EvidenceGraph {
            links: vec![parent_link.clone(), derived_link.clone()],
            missing: vec![],
        };
        let evs = vec![parent_ev, derived_ev];
        let policy = BaselineFusionPolicy;
        let input = FusionInput {
            claim: &c,
            graph: &graph,
            evidence: &evs,
        };
        let out = policy.fuse(&input, "2026-01-02T00:00:00Z");
        assert_eq!(out.counted_link_ids, vec![parent_link.id]);
        assert_eq!(out.discounted_link_ids, vec![derived_link.id]);
        assert!(out
            .rationale
            .iter()
            .any(|r| r.rule == FusionRule::DerivedFromCountedParent
                && r.link_ids == vec![derived_link.id]));
    }

    // --- 8. Staleness asymmetry ---------------------------------------------

    #[test]
    fn stale_support_does_not_count_but_stale_contradiction_does() {
        let c = Claim {
            claimed_at: "2026-01-01T02:00:00Z".into(), // 2h after evidence
            ..claim()
        };
        let stale_ev = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let support_link = link(c.id, stale_ev.id, EvidenceRelation::Supports);
        let graph = EvidenceGraph {
            links: vec![support_link],
            missing: vec![],
        };
        let policy = BaselineFusionPolicy;
        let out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: std::slice::from_ref(&stale_ev),
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(out.verdict, Verdict::Unverified);
        assert!(out.counted_link_ids.is_empty());
        assert!(out
            .rationale
            .iter()
            .any(|r| r.rule == FusionRule::StaleSupportDemoted));

        let contradict_link = link(c.id, stale_ev.id, EvidenceRelation::Contradicts);
        let graph2 = EvidenceGraph {
            links: vec![contradict_link],
            missing: vec![],
        };
        let out2 = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph2,
                evidence: &[stale_ev],
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(out2.verdict, Verdict::Contradicted);
        assert_eq!(out2.counted_link_ids.len(), 1);
        assert!(out2
            .rationale
            .iter()
            .any(|r| r.rule == FusionRule::StaleContradictionRetained));
    }

    /// Pins the documented divergence between `fuse`'s `unresolved_conflict`
    /// and [`fornax_types::EvidenceGraph::conflict`] (module docs, "Known
    /// divergence" section): a raw `Supports` + `Contradicts` pair on the
    /// same claim is a `conflict()` per FORNX-92, but once the `Supports`
    /// side is demoted by R4 staleness, `fuse` sees only one surviving
    /// vote and reports no conflict at all.
    #[test]
    fn stale_support_demotion_diverges_from_raw_graph_conflict() {
        let c = Claim {
            claimed_at: "2026-01-01T02:00:00Z".into(), // 2h after evidence
            ..claim()
        };
        let stale_support_ev = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let fresh_contradict_ev = evidence(EvidenceKind::ExitCode, "2026-01-01T02:00:00Z");
        let support_link = link(c.id, stale_support_ev.id, EvidenceRelation::Supports);
        let contradict_link = link(c.id, fresh_contradict_ev.id, EvidenceRelation::Contradicts);
        let graph = EvidenceGraph {
            links: vec![support_link, contradict_link],
            missing: vec![],
        };
        // The raw graph genuinely has both relations present.
        assert!(graph.conflict().is_some());

        let evs = vec![stale_support_ev, fresh_contradict_ev];
        let policy = BaselineFusionPolicy;
        let out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &evs,
            },
            "2026-01-02T00:00:00Z",
        );
        // But fusion's stale-support demotion leaves only the contradiction
        // counted -- no conflict from fuse's point of view.
        assert_eq!(out.verdict, Verdict::Contradicted);
        assert!(!out.unresolved_conflict);
    }

    // --- 9. Indeterminate freshness ------------------------------------------

    #[test]
    fn indeterminate_freshness_counts_with_caveat_never_silently_fresh() {
        let c = claim();
        let bad_ev = evidence(EvidenceKind::ExitCode, "not-a-timestamp");
        let l = link(c.id, bad_ev.id, EvidenceRelation::Supports);
        let graph = EvidenceGraph {
            links: vec![l.clone()],
            missing: vec![],
        };
        let policy = BaselineFusionPolicy;
        let out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &[bad_ev],
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(out.verdict, Verdict::Verified);
        assert_eq!(out.counted_link_ids, vec![l.id]);
        assert!(out
            .rationale
            .iter()
            .any(|r| r.rule == FusionRule::FreshnessIndeterminate));
        assert_eq!(out.uncertainty, UncertaintyBand::Qualified);
    }

    // --- 10. Rationale integrity ---------------------------------------------

    #[test]
    fn every_id_in_every_rationale_entry_exists_in_the_input() {
        let c = claim();
        let ev_s = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let ev_c = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let unresolved_id = Uuid::new_v4();
        let l_s = link(c.id, ev_s.id, EvidenceRelation::Supports);
        let l_c = link(c.id, ev_c.id, EvidenceRelation::Contradicts);
        let l_bad = link(c.id, unresolved_id, EvidenceRelation::Supports);
        let m = missing(c.id, SignalAvailability::Unavailable);
        let graph = EvidenceGraph {
            links: vec![l_s.clone(), l_c.clone(), l_bad.clone()],
            missing: vec![m.clone()],
        };
        let evs = vec![ev_s.clone(), ev_c.clone()];
        let policy = BaselineFusionPolicy;
        let out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &evs,
            },
            "2026-01-02T00:00:00Z",
        );

        let valid_link_ids: HashSet<Uuid> = [l_s.id, l_c.id, l_bad.id].into_iter().collect();
        let valid_missing_ids: HashSet<Uuid> = [m.id].into_iter().collect();
        let valid_evidence_ids: HashSet<Uuid> = [ev_s.id, ev_c.id].into_iter().collect();

        for entry in &out.rationale {
            for id in &entry.link_ids {
                assert!(
                    valid_link_ids.contains(id),
                    "rationale referenced unknown link id {id}"
                );
            }
            for id in &entry.missing_evidence_ids {
                assert!(
                    valid_missing_ids.contains(id),
                    "rationale referenced unknown missing-evidence id {id}"
                );
            }
            for id in &entry.evidence_ids {
                assert!(
                    valid_evidence_ids.contains(id),
                    "rationale referenced unknown evidence id {id}"
                );
            }
        }
    }

    // --- 12. No numeric confidence field -------------------------------------

    #[test]
    fn fused_finding_json_carries_no_numeric_confidence_field() {
        let c = claim();
        let graph = EvidenceGraph::default();
        let policy = BaselineFusionPolicy;
        let out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &[],
            },
            "2026-01-02T00:00:00Z",
        );
        let json = serde_json::to_value(&out).unwrap();
        fn assert_no_numeric_confidence(v: &serde_json::Value, path: String) {
            match v {
                serde_json::Value::Object(map) => {
                    for (k, val) in map {
                        let lower = k.to_lowercase();
                        assert!(
                            !(lower.contains("confidence") || lower.contains("score"))
                                || !val.is_number(),
                            "found a numeric confidence-shaped field at {path}.{k}"
                        );
                        assert_no_numeric_confidence(val, format!("{path}.{k}"));
                    }
                }
                serde_json::Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        assert_no_numeric_confidence(item, format!("{path}[{i}]"));
                    }
                }
                _ => {}
            }
        }
        assert_no_numeric_confidence(&json, "$".to_string());
    }

    // --- project_graph ---------------------------------------------------

    fn finding(
        claim_id: Uuid,
        verdict: Verdict,
        evidence_ids: Vec<Uuid>,
        verifier_name: &str,
    ) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            claim_id,
            verdict,
            evidence_ids,
            verifier_name: verifier_name.to_string(),
            rationale: "test rationale".to_string(),
            computed_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn project_graph_maps_verified_and_contradicted_to_supports_and_contradicts() {
        let c = claim();
        let ev = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let f_verified = finding(
            c.id,
            Verdict::Verified,
            vec![ev.id],
            "test_result_verifier_v1",
        );
        let graph = project_graph(&c, &[f_verified]);
        assert_eq!(graph.links.len(), 1);
        assert_eq!(graph.links[0].relation, EvidenceRelation::Supports);

        let f_contradicted = finding(
            c.id,
            Verdict::Contradicted,
            vec![ev.id],
            "test_result_verifier_v1",
        );
        let graph2 = project_graph(&c, &[f_contradicted]);
        assert_eq!(graph2.links[0].relation, EvidenceRelation::Contradicts);
    }

    #[test]
    fn project_graph_maps_unavailable_to_missing_evidence_with_expected_signal_classes() {
        let c = claim();
        let f = finding(
            c.id,
            Verdict::Unavailable,
            vec![],
            "file_modified_verifier_v1",
        );
        let graph = project_graph(&c, &[f]);
        assert!(!graph.missing.is_empty());
        for m in &graph.missing {
            assert_eq!(m.availability, SignalAvailability::Unavailable);
            assert!(matches!(
                m.signal_class,
                SignalClass::ToolTrace | SignalClass::ToolResultPayload
            ));
        }
    }

    #[test]
    fn project_graph_maps_unverified_to_nothing() {
        let c = claim();
        let f = finding(c.id, Verdict::Unverified, vec![], "test_result_verifier_v1");
        let graph = project_graph(&c, &[f]);
        assert!(graph.links.is_empty());
        assert!(graph.missing.is_empty());
    }

    /// Pins `projected_id`'s doc claim: calling `project_graph` twice on
    /// identical `findings` produces a byte-identical graph, not a fresh
    /// random id per call.
    #[test]
    fn project_graph_is_deterministic_across_calls() {
        let c = claim();
        let ev = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let f = finding(
            c.id,
            Verdict::Verified,
            vec![ev.id],
            "test_result_verifier_v1",
        );
        let graph_a = project_graph(&c, std::slice::from_ref(&f));
        let graph_b = project_graph(&c, &[f]);
        assert_eq!(graph_a, graph_b);
    }

    /// Documented `Review -> Neutral` fidelity gap (module docs): a `Review`
    /// finding projects to a `Neutral` link, which never votes, so
    /// re-fusing it always reaches `Unverified` (via `AllSupportDiscounted`),
    /// never re-promoted back to `Review`. This is intentional, not a bug.
    #[test]
    fn review_finding_projects_to_neutral_and_refuses_to_re_promote() {
        let c = claim();
        let ev = evidence(EvidenceKind::ExitCode, "2026-01-01T00:00:00Z");
        let f = finding(
            c.id,
            Verdict::Review,
            vec![ev.id],
            "file_modified_verifier_v1",
        );
        let graph = project_graph(&c, &[f]);
        assert_eq!(graph.links[0].relation, EvidenceRelation::Neutral);

        let policy = BaselineFusionPolicy;
        let out = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &[ev],
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(out.verdict, Verdict::Unverified);
        assert!(out
            .rationale
            .iter()
            .any(|r| r.rule == FusionRule::AllSupportDiscounted));
    }

    // --- 11. Baseline equivalence with real verifiers -----------------------

    #[test]
    fn baseline_equivalence_test_result_verifier_verified() {
        use crate::{TestResultVerifier, Verifier};
        let v = TestResultVerifier;
        let c = crate::tests::claim_for("test_result", "All tests passed.");
        let ev = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({"command": ["pytest"], "exit_code": 0}),
            provenance: "codex:rollout:exec_command_end".into(),
            source: None,
            extension: None,
        };
        let caps = fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::Codex,
            signals: vec![fornax_types::CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: Default::default(),
        };
        let original = v.verify(&c, std::slice::from_ref(&ev), &caps);
        assert_eq!(original.verdict, Verdict::Verified);

        let graph = project_graph(&c, std::slice::from_ref(&original));
        let policy = BaselineFusionPolicy;
        let fused = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &[ev],
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(fused.verdict, Verdict::Verified);
    }

    #[test]
    fn baseline_equivalence_test_result_verifier_contradicted() {
        use crate::{TestResultVerifier, Verifier};
        let v = TestResultVerifier;
        let c = crate::tests::claim_for("test_result", "All tests passed.");
        let ev = Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".into(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: chrono::Utc::now().to_rfc3339(),
            payload: serde_json::json!({"command": ["pytest"], "exit_code": 1}),
            provenance: "codex:rollout:exec_command_end".into(),
            source: None,
            extension: None,
        };
        let caps = fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::Codex,
            signals: vec![fornax_types::CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: Default::default(),
        };
        let original = v.verify(&c, std::slice::from_ref(&ev), &caps);
        assert_eq!(original.verdict, Verdict::Contradicted);

        let graph = project_graph(&c, std::slice::from_ref(&original));
        let policy = BaselineFusionPolicy;
        let fused = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &[ev],
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(fused.verdict, Verdict::Contradicted);
    }

    #[test]
    fn baseline_equivalence_test_result_verifier_unavailable() {
        use crate::{TestResultVerifier, Verifier};
        let v = TestResultVerifier;
        let c = crate::tests::claim_for("test_result", "All tests passed.");
        let caps = fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::Codex,
            signals: vec![],
            notes: Default::default(),
        };
        let original = v.verify(&c, &[], &caps);
        assert_eq!(original.verdict, Verdict::Unavailable);

        let graph = project_graph(&c, std::slice::from_ref(&original));
        let policy = BaselineFusionPolicy;
        let fused = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &[],
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(fused.verdict, Verdict::Unavailable);
    }

    #[test]
    fn baseline_equivalence_git_operation_verifier_verified_and_contradicted() {
        use crate::{GitOperationVerifier, Verifier};

        fn vcs_evidence(observation: serde_json::Value) -> Evidence {
            Evidence {
                id: Uuid::new_v4(),
                session_id: "s1".into(),
                source_event_id: Uuid::new_v4(),
                kind: EvidenceKind::ProcessObservation,
                observed_at: chrono::Utc::now().to_rfc3339(),
                payload: serde_json::json!({
                    "description": "git observation",
                    "observation": observation,
                }),
                provenance: "claude_code:1.2.3:PostToolUse:Bash#tool_response:git_commit".into(),
                source: None,
                extension: None,
            }
        }

        let caps = fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::ClaudeCode,
            signals: vec![fornax_types::CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: Default::default(),
        };

        // Verified: a commit was created, no SHA literal in the claim to
        // mismatch against.
        let v = GitOperationVerifier;
        let c = crate::tests::claim_for("git_commit", "I committed the change.");
        let ev = vcs_evidence(serde_json::json!({
            "observation_kind": "vcs_operation",
            "operation": "commit",
            "outcome": "created",
            "commit_sha": "0e2fbd4",
            "branch": "main",
        }));
        let original = v.verify(&c, std::slice::from_ref(&ev), &caps);
        assert_eq!(original.verdict, Verdict::Verified);
        let graph = project_graph(&c, std::slice::from_ref(&original));
        let policy = BaselineFusionPolicy;
        let fused = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: std::slice::from_ref(&ev),
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(fused.verdict, Verdict::Verified);

        // Contradicted: git reported nothing to commit.
        let c2 = crate::tests::claim_for("git_commit", "I committed the change.");
        let ev2 = vcs_evidence(serde_json::json!({
            "observation_kind": "vcs_operation",
            "operation": "commit",
            "outcome": "nothing_to_commit",
            "commit_sha": null,
            "branch": null,
        }));
        let original2 = v.verify(&c2, std::slice::from_ref(&ev2), &caps);
        assert_eq!(original2.verdict, Verdict::Contradicted);
        let graph2 = project_graph(&c2, std::slice::from_ref(&original2));
        let fused2 = policy.fuse(
            &FusionInput {
                claim: &c2,
                graph: &graph2,
                evidence: std::slice::from_ref(&ev2),
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(fused2.verdict, Verdict::Contradicted);
    }

    /// Exercises `expected_signal_classes_for_verifier`'s
    /// `ToolTrace`/`ToolResultPayload` branch against a real
    /// `FileModifiedVerifier` finding, not a synthetic one.
    #[test]
    fn baseline_equivalence_file_modified_verifier_unavailable() {
        use crate::{FileModifiedVerifier, Verifier};
        let v = FileModifiedVerifier;
        let c = crate::tests::claim_for("file_written", "I updated `src/lib.rs`.");
        let no_caps = fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::ClaudeCode,
            signals: vec![],
            notes: Default::default(),
        };
        let original = v.verify(&c, &[], &no_caps);
        assert_eq!(original.verdict, Verdict::Unavailable);

        let graph = project_graph(&c, std::slice::from_ref(&original));
        assert!(graph.missing.iter().all(|m| matches!(
            m.signal_class,
            SignalClass::ToolTrace | SignalClass::ToolResultPayload
        )));

        let policy = BaselineFusionPolicy;
        let fused = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: &[],
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(fused.verdict, Verdict::Unavailable);
    }

    #[test]
    fn baseline_equivalence_command_executed_verifier_verified() {
        use crate::{CommandExecutedVerifier, Verifier};
        let v = CommandExecutedVerifier;
        let c = crate::tests::claim_for("command_executed", "I ran `npm install`.");
        let ev = crate::tests::evidence_for_command(&["npm", "install"], 0);
        let caps = fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::Codex,
            signals: vec![fornax_types::CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: Default::default(),
        };
        let original = v.verify(&c, std::slice::from_ref(&ev), &caps);
        assert_eq!(original.verdict, Verdict::Verified);

        let graph = project_graph(&c, std::slice::from_ref(&original));
        let policy = BaselineFusionPolicy;
        let fused = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: std::slice::from_ref(&ev),
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(fused.verdict, Verdict::Verified);
    }

    #[test]
    fn baseline_equivalence_command_success_verifier_contradicted() {
        use crate::{CommandSuccessVerifier, Verifier};
        let v = CommandSuccessVerifier;
        let c =
            crate::tests::claim_for("command_succeeded", "The command `npm install` succeeded.");
        let ev = crate::tests::evidence_for_command(&["npm", "install"], 1);
        let caps = fornax_types::RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::Codex,
            signals: vec![fornax_types::CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: Default::default(),
        };
        let original = v.verify(&c, std::slice::from_ref(&ev), &caps);
        assert_eq!(original.verdict, Verdict::Contradicted);

        let graph = project_graph(&c, std::slice::from_ref(&original));
        let policy = BaselineFusionPolicy;
        let fused = policy.fuse(
            &FusionInput {
                claim: &c,
                graph: &graph,
                evidence: std::slice::from_ref(&ev),
            },
            "2026-01-02T00:00:00Z",
        );
        assert_eq!(fused.verdict, Verdict::Contradicted);
    }
}
