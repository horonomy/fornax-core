//! Read-side source-family derivation over real, already-persisted
//! provenance (FORNX-347). Never persisted itself — mirrors
//! [`fornax_types::EvidenceGraph`]'s own "read-side aggregate" discipline —
//! and never a new writer: no adapter/sensor changes, no migration.
//!
//! # Why this exists (ground truth, not the ticket's own framing)
//!
//! FORNX-92's `EvidenceSource::correlation_group` has no real writer
//! anywhere in this workspace today — every shipped sensor calls
//! `EvidenceSource::now(..)`, which hardcodes `correlation_group: None`.
//! `FusionRule::CorrelationCollapsed` and `voi::Independence::SameSourceAsCounted`
//! are consequently unreachable on real traffic (ADR 0015 already concedes
//! this). The actual, *live*, on-real-traffic common-source amplification
//! runs through a column nobody was reading for this purpose:
//! `Evidence::source_event_id` — a `NOT NULL` column every sensor stamps.
//! `fornax-adapter-claude`'s `translate()` fans one `AgentEvent` out to
//! multiple sensors; a Bash `PostToolUse` on `git commit` produces both
//! `ClaudeBashExitCodeSensor` and `ClaudeGitOutcomeSensor` evidence, both
//! `TrustClass::AgentAdjacent`, both reading the same `tool_response`, both
//! stamped with the same `source_event_id`. Fusion counts those as two
//! independent supporting votes today. This module is the fix.
//!
//! # Union rules
//!
//! A union-find over evidence ids, built from three real relations (in
//! addition to FORNX-92's own `correlation_group`, honored when present):
//!
//! 1. Same `correlation_group` (FORNX-92, honored, never the only signal).
//! 2. `derived_from` ancestry, walked transitively (not just one level) --
//!    see [`ancestors_of`].
//! 3. Same `source_event_id` **and** both records on the agent-reported
//!    channel (`TrustClass::AgentAdjacent` or `ModelInternal`) -- *never*
//!    `HostObserved`/`IndependentExternal`/`HumanReviewed`. Two sensors
//!    independently measuring the *same event* from outside the agent's own
//!    report (e.g. a host-observed file-write confirmation and a
//!    host-observed git working-tree check on the same Edit event) are
//!    genuinely distinct observations, not one restated signal — collapsing
//!    them would under-count Fornax's most valuable evidence, which is the
//!    unsafe direction.
//!
//! `Evidence::source == None` is always its own singleton family
//! (`FamilyBasis::UnknownProvenance`) -- unknown provenance is never unioned
//! by rule 3, since `source_event_id` is populated even when `source` is
//! absent.
//!
//! # Determinism
//!
//! Evidence is processed in id-sorted order; only `BTreeMap`/`BTreeSet` are
//! used for anything that affects output shape (a `HashSet` is used only
//! for O(1) membership tests, never iterated for output). Family
//! membership is stable and reproducible for the same input, matching
//! `fusion.rs`'s own R0 discipline ("sort by id before evaluating").

use std::collections::{BTreeMap, BTreeSet, HashMap};

use fornax_types::sensor::TrustClass;
use fornax_types::Evidence;
use uuid::Uuid;

/// Why two evidence records were judged to share one source family. A
/// record can have more than one basis simultaneously in principle (this
/// type names the *strongest* one this module recorded for a given union),
/// but the family itself is the operative unit -- `bases` on
/// [`SourceFamily`] lists every distinct reason found across the family.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FamilyBasis {
    /// FORNX-92's explicit `correlation_group`, honored when a sensor
    /// actually stamps one -- see this module's docs for why that's rare on
    /// real traffic today.
    ExplicitCorrelationGroup(Uuid),
    /// One record is (transitively) in the other's `derived_from` ancestry.
    DerivationAncestry { parent: Uuid, child: Uuid },
    /// Both records share `source_event_id` and are on the agent-reported
    /// channel (`AgentAdjacent`/`ModelInternal`) -- the live, real case.
    SameAgentTurn { source_event_id: Uuid },
    /// This evidence has no recorded `source` at all -- an explicit
    /// singleton, never unioned with anything.
    UnknownProvenance,
}

/// One set of evidence ids judged to count as a single effective source,
/// plus every distinct reason recorded for the union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFamily {
    /// Sorted, so two families with the same membership always compare and
    /// serialize identically regardless of build order.
    pub evidence_ids: Vec<Uuid>,
    pub bases: Vec<FamilyBasis>,
}

/// Maps every evidence id in a pool to the [`SourceFamily`] it belongs to.
/// Built once per fusion/VoI computation over the full evidence pool (not
/// just links on one claim) -- ancestry can run through evidence not
/// directly linked to the claim being evaluated.
#[derive(Debug, Clone, Default)]
pub struct SourceFamilyMap {
    families: Vec<SourceFamily>,
    /// Index into `families` for each evidence id that has one.
    index: HashMap<Uuid, usize>,
}

impl SourceFamilyMap {
    /// Build the map. Deterministic: the same `evidence` slice (any order)
    /// always produces the same families, sorted the same way.
    pub fn build(evidence: &[Evidence]) -> Self {
        let mut sorted: Vec<&Evidence> = evidence.iter().collect();
        sorted.sort_by_key(|e| e.id);

        let by_id: BTreeMap<Uuid, &Evidence> = sorted.iter().map(|e| (e.id, *e)).collect();

        // Union-find over the sorted id list. Path compression is fine
        // internally -- the *root* id is never exposed as output; the
        // representative element of a rendered family is chosen separately
        // (fusion.rs's own R5 convention: minimum link/evidence id), so
        // union-find's compression-dependent root never leaks.
        let mut parent: BTreeMap<Uuid, Uuid> = sorted.iter().map(|e| (e.id, e.id)).collect();
        fn find(parent: &mut BTreeMap<Uuid, Uuid>, x: Uuid) -> Uuid {
            let p = parent[&x];
            if p == x {
                return x;
            }
            let root = find(parent, p);
            parent.insert(x, root);
            root
        }
        fn union(parent: &mut BTreeMap<Uuid, Uuid>, a: Uuid, b: Uuid) {
            let ra = find(parent, a);
            let rb = find(parent, b);
            if ra != rb {
                // Deterministic tie-break: smaller id becomes the root.
                if ra < rb {
                    parent.insert(rb, ra);
                } else {
                    parent.insert(ra, rb);
                }
            }
        }

        let mut bases_by_pair: BTreeSet<(Uuid, Uuid, FamilyBasisTag)> = BTreeSet::new();

        // Rule 1: explicit correlation_group.
        let mut by_group: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
        for e in &sorted {
            if let Some(group) = e.source.as_ref().and_then(|s| s.correlation_group) {
                by_group.entry(group).or_default().push(e.id);
            }
        }
        for (group, ids) in &by_group {
            for pair in ids.windows(2) {
                union(&mut parent, pair[0], pair[1]);
                bases_by_pair.insert((
                    pair[0].min(pair[1]),
                    pair[0].max(pair[1]),
                    FamilyBasisTag::ExplicitCorrelationGroup(*group),
                ));
            }
        }

        // Rule 2: derived_from ancestry, transitive.
        for e in &sorted {
            for ancestor in ancestors_of(e.id, evidence) {
                if by_id.contains_key(&ancestor) {
                    union(&mut parent, e.id, ancestor);
                    bases_by_pair.insert((
                        e.id.min(ancestor),
                        e.id.max(ancestor),
                        FamilyBasisTag::DerivationAncestry {
                            parent: ancestor,
                            child: e.id,
                        },
                    ));
                }
            }
        }

        // Rule 3: same source_event_id, agent-reported channel only.
        let mut by_event: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
        for e in &sorted {
            let on_agent_channel = e
                .source
                .as_ref()
                .map(|s| {
                    matches!(
                        s.trust_class,
                        TrustClass::AgentAdjacent | TrustClass::ModelInternal
                    )
                })
                .unwrap_or(false);
            if e.source.is_some() && on_agent_channel {
                by_event.entry(e.source_event_id).or_default().push(e.id);
            }
        }
        for (event_id, ids) in &by_event {
            for pair in ids.windows(2) {
                union(&mut parent, pair[0], pair[1]);
                bases_by_pair.insert((
                    pair[0].min(pair[1]),
                    pair[0].max(pair[1]),
                    FamilyBasisTag::SameAgentTurn(*event_id),
                ));
            }
        }

        // Assemble families from the final union-find state.
        let mut members_by_root: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
        for e in &sorted {
            if e.source.is_none() {
                // Unknown provenance is always its own singleton, never
                // unioned -- assign it its own "root" (itself) regardless
                // of what union-find computed (it was never unioned with
                // anything for this id, so this is a no-op in practice,
                // stated explicitly for clarity and defense-in-depth).
                members_by_root.entry(e.id).or_default().push(e.id);
                continue;
            }
            let root = find(&mut parent, e.id);
            members_by_root.entry(root).or_default().push(e.id);
        }

        let mut families = Vec::new();
        for (_, mut ids) in members_by_root {
            ids.sort();
            ids.dedup();
            let mut bases: BTreeSet<FamilyBasisTag> = BTreeSet::new();
            if ids.len() == 1
                && evidence
                    .iter()
                    .find(|e| e.id == ids[0])
                    .map(|e| e.source.is_none())
                    .unwrap_or(false)
            {
                bases.insert(FamilyBasisTag::UnknownProvenance);
            }
            for (a, b, tag) in &bases_by_pair {
                if ids.contains(a) && ids.contains(b) {
                    bases.insert(tag.clone());
                }
            }
            families.push(SourceFamily {
                evidence_ids: ids,
                bases: bases.into_iter().map(FamilyBasisTag::into_basis).collect(),
            });
        }
        // Sort families by their minimum evidence id so any exposed family
        // index is deterministic and independent of union-find internals.
        families.sort_by_key(|f| f.evidence_ids.first().copied());
        // Rebuild the index against the now-sorted family order.
        let mut index = HashMap::new();
        for (i, f) in families.iter().enumerate() {
            for id in &f.evidence_ids {
                index.insert(*id, i);
            }
        }

        Self { families, index }
    }

    /// The [`SourceFamily`] `evidence_id` belongs to, if it's in this map's
    /// pool at all.
    pub fn family_of(&self, evidence_id: Uuid) -> Option<&SourceFamily> {
        self.index.get(&evidence_id).map(|&i| &self.families[i])
    }

    /// Every distinct family represented among `ids`, in family-index
    /// order (deterministic).
    pub fn families_among(&self, ids: &[Uuid]) -> Vec<&SourceFamily> {
        let mut seen: BTreeSet<usize> = BTreeSet::new();
        for id in ids {
            if let Some(&i) = self.index.get(id) {
                seen.insert(i);
            }
        }
        seen.into_iter().map(|i| &self.families[i]).collect()
    }

    /// All families this map computed, in deterministic order.
    pub fn all_families(&self) -> &[SourceFamily] {
        &self.families
    }
}

/// Internal-only ordered tag mirroring [`FamilyBasis`], used purely to
/// dedupe/sort bases in a `BTreeSet` before converting to the public,
/// non-`Ord` type (`FamilyBasis` deliberately isn't `Ord`-derived beyond
/// what it already needs -- this tag exists so the public type doesn't
/// have to carry ordering machinery it has no other use for).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum FamilyBasisTag {
    ExplicitCorrelationGroup(Uuid),
    DerivationAncestry { parent: Uuid, child: Uuid },
    SameAgentTurn(Uuid),
    UnknownProvenance,
}

impl FamilyBasisTag {
    fn into_basis(self) -> FamilyBasis {
        match self {
            Self::ExplicitCorrelationGroup(g) => FamilyBasis::ExplicitCorrelationGroup(g),
            Self::DerivationAncestry { parent, child } => {
                FamilyBasis::DerivationAncestry { parent, child }
            }
            Self::SameAgentTurn(id) => FamilyBasis::SameAgentTurn {
                source_event_id: id,
            },
            Self::UnknownProvenance => FamilyBasis::UnknownProvenance,
        }
    }
}

/// Every ancestor of `evidence_id` reachable by transitively following
/// `EvidenceSource::derived_from`, resolved only against ids present in
/// `evidence` (an unresolved parent id is silently absent from the result,
/// not an error -- this mirrors R3's own existing "not present" handling).
/// Cycle-safe: a `visited` set prevents infinite recursion if `derived_from`
/// ever forms a cycle (should never happen in practice, but this must not
/// hang or panic on hostile/malformed input).
pub fn ancestors_of(evidence_id: Uuid, evidence: &[Evidence]) -> BTreeSet<Uuid> {
    let by_id: BTreeMap<Uuid, &Evidence> = evidence.iter().map(|e| (e.id, e)).collect();
    let mut result = BTreeSet::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![evidence_id];
    while let Some(current) = stack.pop() {
        if !visited.insert(current) {
            continue;
        }
        let Some(ev) = by_id.get(&current) else {
            continue;
        };
        let parents = ev
            .source
            .as_ref()
            .map(|s| s.derived_from.as_slice())
            .unwrap_or(&[]);
        for &parent in parents {
            if parent != evidence_id && by_id.contains_key(&parent) {
                result.insert(parent);
                stack.push(parent);
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::sensor::{
        ClockSource, CollectionMethod, EvidenceSource, Freshness, TamperBoundary,
    };
    use fornax_types::EvidenceKind;

    fn evidence_with_source(
        trust: TrustClass,
        source_event_id: Uuid,
        correlation_group: Option<Uuid>,
        derived_from: Vec<Uuid>,
    ) -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id,
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            payload: serde_json::json!({}),
            provenance: "test".to_string(),
            source: Some(EvidenceSource {
                sensor_name: "test_sensor".to_string(),
                trust_class: trust,
                collected_at: "2026-01-01T00:00:00Z".to_string(),
                provider: None,
                collection_method: CollectionMethod::HookCallback,
                collector_version: None,
                freshness: Freshness {
                    clock_source: ClockSource::HostClock,
                    caveat: None,
                },
                tamper_boundary: TamperBoundary::default(),
                correlation_group,
                derived_from,
            }),
            extension: None,
            evidence_purged: false,
        }
    }

    fn evidence_no_source() -> Evidence {
        Evidence {
            id: Uuid::new_v4(),
            session_id: "s1".to_string(),
            source_event_id: Uuid::new_v4(),
            kind: EvidenceKind::ExitCode,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            payload: serde_json::json!({}),
            provenance: "test".to_string(),
            source: None,
            extension: None,
            evidence_purged: false,
        }
    }

    #[test]
    fn two_agent_adjacent_records_on_the_same_event_are_one_family() {
        let event = Uuid::new_v4();
        let a = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let b = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let map = SourceFamilyMap::build(&[a.clone(), b.clone()]);
        assert_eq!(map.family_of(a.id), map.family_of(b.id));
        assert_eq!(map.family_of(a.id).unwrap().evidence_ids.len(), 2);
    }

    /// The load-bearing safety property: two independently-observing
    /// host sensors on the SAME event must never collapse into one family
    /// -- that would under-count Fornax's most valuable evidence.
    #[test]
    fn two_host_observed_records_on_the_same_event_stay_distinct() {
        let event = Uuid::new_v4();
        let a = evidence_with_source(TrustClass::HostObserved, event, None, vec![]);
        let b = evidence_with_source(TrustClass::HostObserved, event, None, vec![]);
        let map = SourceFamilyMap::build(&[a.clone(), b.clone()]);
        assert_ne!(map.family_of(a.id), map.family_of(b.id));
    }

    #[test]
    fn a_host_observed_and_agent_adjacent_pair_on_the_same_event_stay_distinct() {
        let event = Uuid::new_v4();
        let a = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let b = evidence_with_source(TrustClass::HostObserved, event, None, vec![]);
        let map = SourceFamilyMap::build(&[a.clone(), b.clone()]);
        assert_ne!(map.family_of(a.id), map.family_of(b.id));
    }

    #[test]
    fn transitive_derivation_through_an_intermediate_is_one_family() {
        let root = evidence_with_source(TrustClass::HostObserved, Uuid::new_v4(), None, vec![]);
        let mid = evidence_with_source(
            TrustClass::HostObserved,
            Uuid::new_v4(),
            None,
            vec![root.id],
        );
        let leaf =
            evidence_with_source(TrustClass::HostObserved, Uuid::new_v4(), None, vec![mid.id]);
        let pool = vec![root.clone(), mid.clone(), leaf.clone()];
        let ancestors = ancestors_of(leaf.id, &pool);
        assert!(ancestors.contains(&root.id));
        assert!(ancestors.contains(&mid.id));

        let map = SourceFamilyMap::build(&pool);
        assert_eq!(map.family_of(root.id), map.family_of(leaf.id));
    }

    #[test]
    fn a_derivation_cycle_never_hangs_or_panics() {
        let a_id = Uuid::new_v4();
        let b_id = Uuid::new_v4();
        let mut a =
            evidence_with_source(TrustClass::HostObserved, Uuid::new_v4(), None, vec![b_id]);
        a.id = a_id;
        let mut b =
            evidence_with_source(TrustClass::HostObserved, Uuid::new_v4(), None, vec![a_id]);
        b.id = b_id;
        let pool = vec![a, b];
        let ancestors = ancestors_of(a_id, &pool);
        assert!(ancestors.contains(&b_id));
    }

    #[test]
    fn evidence_with_no_source_is_always_its_own_singleton() {
        let no_source = evidence_no_source();
        let event = no_source.source_event_id;
        let agent = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let pool = vec![no_source.clone(), agent.clone()];
        let map = SourceFamilyMap::build(&pool);
        assert_ne!(map.family_of(no_source.id), map.family_of(agent.id));
        assert_eq!(
            map.family_of(no_source.id).unwrap().bases,
            vec![FamilyBasis::UnknownProvenance]
        );
    }

    #[test]
    fn explicit_correlation_group_unions_regardless_of_trust_class_or_event() {
        let group = Uuid::new_v4();
        let a = evidence_with_source(
            TrustClass::HostObserved,
            Uuid::new_v4(),
            Some(group),
            vec![],
        );
        let b = evidence_with_source(
            TrustClass::IndependentExternal,
            Uuid::new_v4(),
            Some(group),
            vec![],
        );
        let map = SourceFamilyMap::build(&[a.clone(), b.clone()]);
        assert_eq!(map.family_of(a.id), map.family_of(b.id));
    }

    /// An explicit correlation group can never *prevent* an event-based
    /// union either -- unions are purely additive.
    #[test]
    fn explicit_correlation_group_never_prevents_an_event_union() {
        let event = Uuid::new_v4();
        let group_a = Uuid::new_v4();
        let group_b = Uuid::new_v4();
        let a = evidence_with_source(TrustClass::AgentAdjacent, event, Some(group_a), vec![]);
        let b = evidence_with_source(TrustClass::AgentAdjacent, event, Some(group_b), vec![]);
        let map = SourceFamilyMap::build(&[a.clone(), b.clone()]);
        assert_eq!(map.family_of(a.id), map.family_of(b.id));
    }

    #[test]
    fn building_twice_from_the_same_pool_is_identical() {
        let event = Uuid::new_v4();
        let a = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let b = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let pool = vec![a, b];
        let map1 = SourceFamilyMap::build(&pool);
        let map2 = SourceFamilyMap::build(&pool);
        assert_eq!(map1.all_families(), map2.all_families());
    }
}
