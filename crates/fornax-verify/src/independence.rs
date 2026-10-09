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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

        // FORNX-432 PR 2: first-occurrence `source.is_none()` per id, built
        // once instead of the `evidence.iter().find(...)` rescan every
        // singleton family previously did below (cost source E in the
        // FORNX-432 design doc). `.entry().or_insert()` preserves the same
        // "first match in `evidence`'s original order" semantics `.find()`
        // had, including when `evidence` contains a duplicate id.
        let mut is_no_source: HashMap<Uuid, bool> = HashMap::new();
        for e in evidence {
            is_no_source.entry(e.id).or_insert(e.source.is_none());
        }

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

        // Rule 2: derived_from ancestry, transitive. FORNX-432 PR 2: reuses
        // `by_id` (already built once above) via `ancestors_of_indexed`
        // instead of calling public `ancestors_of`, which rebuilt the same
        // index from scratch on every one of these `sorted.len()` calls --
        // this was cost source A in the FORNX-432 design doc, the dominant
        // cost even on a `flat` pool with zero `derived_from` edges at all.
        for e in &sorted {
            for ancestor in ancestors_of_indexed(e.id, &by_id) {
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

        // Assemble families from the final union-find state. FORNX-432 PR 2:
        // `value_to_keys` is computed once per occurrence here and reused
        // for both grouping steps below, replacing two scans that were
        // previously O(families * n) and O(families * bases_by_pair.len())
        // (cost sources D and E in the design doc) -- `evidence.iter().find(...)`
        // per singleton family, and `ids.contains(a) && ids.contains(b)`
        // tested against every family for every recorded pair.
        //
        // This maps each id *value* to the SET of family keys it landed in
        // -- not a single key -- because `evidence` can legitimately
        // contain more than one record sharing the same id value, with
        // different `source.is_none()` outcomes: the input's pool is never
        // deduplicated before this pass (only each resulting family's own
        // `ids` list is, below), so the same id value can end up a member
        // of two *different* families simultaneously (one occurrence's
        // "no-source -- own singleton" override landing it in its own key,
        // another occurrence of the identical id value unioned by `find`
        // into someone else's key). A single id-to-key map would silently
        // collapse that into whichever occurrence was processed last;
        // `prop_build_matches_reference_oracle` below is what caught this.
        let mut members_by_root: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
        let mut value_to_keys: HashMap<Uuid, std::collections::HashSet<Uuid>> = HashMap::new();
        for e in &sorted {
            let key = if e.source.is_none() {
                // Unknown provenance is always its own singleton, never
                // unioned -- assign it its own "root" (itself) regardless
                // of what union-find computed (it was never unioned with
                // anything for this id, so this is a no-op in practice,
                // stated explicitly for clarity and defense-in-depth).
                e.id
            } else {
                find(&mut parent, e.id)
            };
            members_by_root.entry(key).or_default().push(e.id);
            value_to_keys.entry(e.id).or_default().insert(key);
        }

        // For each recorded pair, add its tag to every family whose
        // `ids` list genuinely contains both endpoint values -- i.e. every
        // key common to both endpoints' key-sets -- reproducing the
        // original `ids.contains(a) && ids.contains(b)` membership test
        // exactly (including the duplicate-id case above), without
        // rescanning every family per pair. In the overwhelmingly common
        // case (no duplicate ids) each key-set has exactly one element, so
        // this is still an O(1) intersection per pair.
        let mut bases_by_family: BTreeMap<Uuid, BTreeSet<FamilyBasisTag>> = BTreeMap::new();
        for (a, b, tag) in &bases_by_pair {
            if let (Some(keys_a), Some(keys_b)) = (value_to_keys.get(a), value_to_keys.get(b)) {
                for &key in keys_a.intersection(keys_b) {
                    bases_by_family.entry(key).or_default().insert(tag.clone());
                }
            }
        }

        let mut families = Vec::new();
        for (key, mut ids) in members_by_root {
            ids.sort();
            ids.dedup();
            let mut bases: BTreeSet<FamilyBasisTag> = BTreeSet::new();
            if ids.len() == 1 && is_no_source.get(&ids[0]).copied().unwrap_or(false) {
                bases.insert(FamilyBasisTag::UnknownProvenance);
            }
            if let Some(pair_bases) = bases_by_family.get(&key) {
                bases.extend(pair_bases.iter().cloned());
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

    /// Bounded variant of [`Self::build`] (FORNX-432 PR 3, AC2/AC3): aborts
    /// with [`BudgetExceeded`] instead of completing on a pool whose
    /// `derived_from` structure would make Rule 2's ancestry walk and the
    /// resulting `bases_by_pair`/`bases_by_family` bookkeeping exceed
    /// `budget`. The real cost driver on an adversarial pool is Rule 2 (a
    /// dense or deeply-rejoining `derived_from` graph) -- see
    /// `docs/research/fornx-432-independence-capacity.md`'s `adversarial_dense`/
    /// `rejoining_dag`/`deep_chain` rows, which stay expensive even after PR
    /// 2's speed-ups because their cost is genuinely large OUTPUT (the
    /// `bases` list), not an algorithmic inefficiency. Rules 1 and 3 are
    /// bounded by construction (each is at most one pass grouping by an
    /// already-bounded key), so only Rule 2 and the final family-assembly
    /// bookkeeping are counted.
    ///
    /// One work unit = one `derived_from` edge visited during Rule 2's
    /// traversal, counted inside [`ancestors_of_indexed`] via a shared
    /// counter, PLUS one `bases_by_pair` entry recorded. Checked AFTER each
    /// increment (never before), so the abort path itself never allocates
    /// unboundedly past the limit. On abort, returns `Err` with only counts
    /// -- never an evidence id or payload (AC3's "bounded diagnostic"
    /// requirement) -- and never a partial/truncated `SourceFamilyMap`:
    /// under-unioning would make genuinely correlated evidence look
    /// independent, which is the unsafe direction, so this aborts fully
    /// rather than returning anything partial.
    pub fn try_build(evidence: &[Evidence], budget: &FamilyBudget) -> Result<Self, BudgetExceeded> {
        let mut sorted: Vec<&Evidence> = evidence.iter().collect();
        sorted.sort_by_key(|e| e.id);

        let by_id: BTreeMap<Uuid, &Evidence> = sorted.iter().map(|e| (e.id, *e)).collect();

        let mut is_no_source: HashMap<Uuid, bool> = HashMap::new();
        for e in evidence {
            is_no_source.entry(e.id).or_insert(e.source.is_none());
        }

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
                if ra < rb {
                    parent.insert(rb, ra);
                } else {
                    parent.insert(ra, rb);
                }
            }
        }

        let mut bases_by_pair: BTreeSet<(Uuid, Uuid, FamilyBasisTag)> = BTreeSet::new();
        let mut work_units: u64 = 0;
        macro_rules! charge {
            ($n:expr) => {
                work_units = work_units.saturating_add($n);
                if work_units > budget.max_work_units {
                    return Err(BudgetExceeded {
                        evidence_count: evidence.len(),
                        work_units_at_abort: work_units,
                        limit: budget.max_work_units,
                    });
                }
            };
        }

        // Rule 1: explicit correlation_group -- bounded by construction
        // (one pass, grouped by an id already present on the record), not
        // charged against the budget.
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

        // Rule 2: derived_from ancestry, transitive -- the real cost driver.
        // Charged per ancestor edge visited (via `ancestors_of_indexed_counted`)
        // plus one unit per `bases_by_pair` entry recorded.
        for e in &sorted {
            let ancestors = ancestors_of_indexed_counted(e.id, &by_id, &mut work_units);
            if work_units > budget.max_work_units {
                return Err(BudgetExceeded {
                    evidence_count: evidence.len(),
                    work_units_at_abort: work_units,
                    limit: budget.max_work_units,
                });
            }
            for ancestor in ancestors {
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
                    charge!(1);
                }
            }
        }

        // Rule 3: same source_event_id, agent-reported channel only --
        // bounded by construction (grouped by an already-bounded key), not
        // charged.
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

        let mut members_by_root: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
        let mut value_to_keys: HashMap<Uuid, std::collections::HashSet<Uuid>> = HashMap::new();
        for e in &sorted {
            let key = if e.source.is_none() {
                e.id
            } else {
                find(&mut parent, e.id)
            };
            members_by_root.entry(key).or_default().push(e.id);
            value_to_keys.entry(e.id).or_default().insert(key);
        }

        let mut bases_by_family: BTreeMap<Uuid, BTreeSet<FamilyBasisTag>> = BTreeMap::new();
        for (a, b, tag) in &bases_by_pair {
            if let (Some(keys_a), Some(keys_b)) = (value_to_keys.get(a), value_to_keys.get(b)) {
                for &key in keys_a.intersection(keys_b) {
                    bases_by_family.entry(key).or_default().insert(tag.clone());
                }
            }
        }

        let mut families = Vec::new();
        for (key, mut ids) in members_by_root {
            ids.sort();
            ids.dedup();
            let mut bases: BTreeSet<FamilyBasisTag> = BTreeSet::new();
            if ids.len() == 1 && is_no_source.get(&ids[0]).copied().unwrap_or(false) {
                bases.insert(FamilyBasisTag::UnknownProvenance);
            }
            if let Some(pair_bases) = bases_by_family.get(&key) {
                bases.extend(pair_bases.iter().cloned());
            }
            families.push(SourceFamily {
                evidence_ids: ids,
                bases: bases.into_iter().map(FamilyBasisTag::into_basis).collect(),
            });
        }
        families.sort_by_key(|f| f.evidence_ids.first().copied());
        let mut index = HashMap::new();
        for (i, f) in families.iter().enumerate() {
            for id in &f.evidence_ids {
                index.insert(*id, i);
            }
        }

        Ok(Self { families, index })
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
    ancestors_of_indexed(evidence_id, &by_id)
}

/// FORNX-432 PR 2: the same traversal [`ancestors_of`] does, but taking an
/// already-built id index instead of rebuilding one from the full evidence
/// slice -- the fix for cost source A in the FORNX-432 design doc, where
/// `build`'s own Rule 2 called public `ancestors_of` once per evidence
/// record, rebuilding the identical index `sorted.len()` times over
/// (dominant even on a `flat` pool with zero edges). `pub(crate)` so
/// `fusion.rs`'s R3 loop can build its own index once before its candidate
/// loop, for the same reason.
pub(crate) fn ancestors_of_indexed(
    evidence_id: Uuid,
    by_id: &BTreeMap<Uuid, &Evidence>,
) -> BTreeSet<Uuid> {
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

/// FORNX-432 PR 3: a deterministic work-budget for [`SourceFamilyMap::try_build`].
/// A work unit is one `derived_from` edge visited during Rule 2's ancestry
/// walk plus one recorded `bases_by_pair` entry -- see `try_build`'s doc
/// comment for why those two are the real cost driver on an adversarial
/// pool. Not time-based and not a pool-size cap: this module must stay
/// pure/deterministic/synchronous (verdict replay depends on it), and a
/// size-only cap would be wrong too -- after PR 2's speed-ups, a large
/// `flat`/`agent_turn_fanout`/`wide_derived_fanout` pool is cheap, while a
/// much smaller `adversarial_dense` pool is not; the cost is about graph
/// shape, not evidence count.
#[derive(Debug, Clone, Copy)]
pub struct FamilyBudget {
    pub max_work_units: u64,
}

impl FamilyBudget {
    /// Calibrated against the real measured numbers in
    /// `docs/research/fornx-432-independence-capacity.md` (PR 1/PR 2 "after"
    /// columns): `adversarial_dense` crosses 100ms between n=300 (203ms) and
    /// n=1000 (8.9s) wall-time, with `bases_by_pair`/ancestor-edge growth
    /// roughly tracking `alloc_count`, which sits at ~86,847 for n=300 and
    /// ~881,502 for n=1000 in that row. A limit of 100,000 work units sits
    /// just above the n=300 cost (clearing it with real traffic's much
    /// sparser graphs) and well below the n=1000 cost (aborting before an
    /// adversarial pool reaches multi-second/sub-second-but-still-abusive
    /// territory), while every cheap shape (`flat`/`agent_turn_fanout`/
    /// `wide_derived_fanout`) stays several orders of magnitude under this
    /// even at n=10,000 (those shapes do zero or near-zero Rule-2 work by
    /// construction). Expressed as a named constant, not inlined, so a
    /// future recalibration has one place to change.
    pub const DEFAULT_MAX_WORK_UNITS: u64 = 100_000;

    pub fn default_budget() -> Self {
        Self {
            max_work_units: Self::DEFAULT_MAX_WORK_UNITS,
        }
    }
}

/// Why [`SourceFamilyMap::try_build`] aborted. Carries only counts -- never
/// an evidence id, a payload, or anything else drawn from the pool content
/// itself (FORNX-432 AC3's "bounded diagnostic" requirement: a poisoned
/// pool's own content must never leak into the error a caller logs or
/// returns to a client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExceeded {
    pub evidence_count: usize,
    pub work_units_at_abort: u64,
    pub limit: u64,
}

impl std::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "source-family construction over {} evidence record(s) exceeded its work budget \
             ({} work unit(s) at abort, limit {}); aborted rather than returning a partial map",
            self.evidence_count, self.work_units_at_abort, self.limit
        )
    }
}

impl std::error::Error for BudgetExceeded {}

/// Same traversal as [`ancestors_of_indexed`], but increments `*work_units`
/// by one per edge visited (an edge that resolves to a present record in
/// `by_id`, mirroring what `try_build`'s caller then charges a second unit
/// for when it records the resulting `bases_by_pair` entry -- this function
/// only charges the traversal half). Does NOT check the budget itself --
/// the caller checks after each call, consistent with every other charge
/// point in `try_build`.
fn ancestors_of_indexed_counted(
    evidence_id: Uuid,
    by_id: &BTreeMap<Uuid, &Evidence>,
    work_units: &mut u64,
) -> BTreeSet<Uuid> {
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
                *work_units = work_units.saturating_add(1);
                result.insert(parent);
                stack.push(parent);
            }
        }
    }
    result
}

/// FORNX-432 PR 1: byte-for-byte historical copy of [`ancestors_of`], kept
/// behind the `bench-reference` feature so a future optimization pass over
/// `ancestors_of` still has a stable correctness oracle to property-test
/// against, and `fornax-bench`'s capacity harness has a reproducible
/// "before" baseline that survives that pass landing. **Not called by any
/// production code path** -- only `fornax-bench`, and only when built with
/// `--features fornax-verify/bench-reference`. Keep this in sync with
/// [`ancestors_of`] ONLY by never modifying it -- if `ancestors_of` is ever
/// intentionally changed, this function must NOT be changed to match; that
/// divergence is the whole point.
#[cfg(feature = "bench-reference")]
pub fn ancestors_of_reference(evidence_id: Uuid, evidence: &[Evidence]) -> BTreeSet<Uuid> {
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

/// FORNX-432 PR 1: byte-for-byte historical copy of
/// [`SourceFamilyMap::build`] (the only difference is calling
/// [`ancestors_of_reference`] instead of [`ancestors_of`] for Rule 2, so
/// this stays the stable "before" oracle even after a future optimization
/// pass changes the real `build`). Same non-production-path caveat as
/// [`ancestors_of_reference`] -- never call this outside a benchmark/test.
#[cfg(feature = "bench-reference")]
pub fn build_reference(evidence: &[Evidence]) -> SourceFamilyMap {
    let mut sorted: Vec<&Evidence> = evidence.iter().collect();
    sorted.sort_by_key(|e| e.id);

    let by_id: BTreeMap<Uuid, &Evidence> = sorted.iter().map(|e| (e.id, *e)).collect();

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
            if ra < rb {
                parent.insert(rb, ra);
            } else {
                parent.insert(ra, rb);
            }
        }
    }

    let mut bases_by_pair: BTreeSet<(Uuid, Uuid, FamilyBasisTag)> = BTreeSet::new();

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

    for e in &sorted {
        for ancestor in ancestors_of_reference(e.id, evidence) {
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

    let mut members_by_root: BTreeMap<Uuid, Vec<Uuid>> = BTreeMap::new();
    for e in &sorted {
        if e.source.is_none() {
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
    families.sort_by_key(|f| f.evidence_ids.first().copied());
    let mut index = HashMap::new();
    for (i, f) in families.iter().enumerate() {
        for id in &f.evidence_ids {
            index.insert(*id, i);
        }
    }

    SourceFamilyMap { families, index }
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

    // FORNX-432 PR 3: `try_build` under a generous budget must agree with
    // `build` exactly -- the bounded path is not a second, divergent
    // implementation of family construction.
    #[test]
    fn try_build_matches_build_when_under_budget() {
        let event = Uuid::new_v4();
        let a = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let b = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let pool = vec![a, b];
        let budget = FamilyBudget::default_budget();
        let bounded = SourceFamilyMap::try_build(&pool, &budget).expect("under budget");
        let unbounded = SourceFamilyMap::build(&pool);
        assert_eq!(bounded.all_families(), unbounded.all_families());
    }

    /// The real safety property: a budget too small for even one
    /// `derived_from` edge must abort, never silently return a partial map.
    #[test]
    fn try_build_aborts_on_a_too_small_budget_rather_than_returning_a_partial_map() {
        let root = evidence_with_source(TrustClass::HostObserved, Uuid::new_v4(), None, vec![]);
        let child = evidence_with_source(
            TrustClass::HostObserved,
            Uuid::new_v4(),
            None,
            vec![root.id],
        );
        let pool = vec![root, child];
        let budget = FamilyBudget { max_work_units: 0 };
        let err = SourceFamilyMap::try_build(&pool, &budget)
            .expect_err("a single derived_from edge must exceed a zero-unit budget");
        assert_eq!(err.evidence_count, 2);
        assert_eq!(err.limit, 0);
        assert!(err.work_units_at_abort > 0);
    }

    /// A pool with no `derived_from` edges at all costs zero Rule-2 work
    /// units (Rule 1/Rule 3 are bounded by construction and never
    /// charged), so even a zero-unit budget must succeed on it -- the
    /// budget bounds the real cost driver, not evidence count.
    #[test]
    fn try_build_succeeds_on_a_zero_unit_budget_when_there_is_no_derived_from_ancestry() {
        let event = Uuid::new_v4();
        let a = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let b = evidence_with_source(TrustClass::AgentAdjacent, event, None, vec![]);
        let pool = vec![a.clone(), b.clone()];
        let budget = FamilyBudget { max_work_units: 0 };
        let map = SourceFamilyMap::try_build(&pool, &budget).expect("no Rule-2 work at all");
        assert_eq!(map.family_of(a.id), map.family_of(b.id));
    }

    /// `BudgetExceeded`'s `Display` must carry only counts -- AC3's bounded
    /// diagnostic requirement, checked by never mentioning an id-shaped
    /// substring from the pool in the formatted error.
    #[test]
    fn budget_exceeded_display_never_leaks_an_evidence_id() {
        let a_id = Uuid::new_v4();
        let b_id = Uuid::new_v4();
        let root = {
            let mut e =
                evidence_with_source(TrustClass::HostObserved, Uuid::new_v4(), None, vec![]);
            e.id = a_id;
            e
        };
        let child = {
            let mut e =
                evidence_with_source(TrustClass::HostObserved, Uuid::new_v4(), None, vec![a_id]);
            e.id = b_id;
            e
        };
        let pool = vec![root, child];
        let err = SourceFamilyMap::try_build(&pool, &FamilyBudget { max_work_units: 0 })
            .expect_err("exceeds a zero-unit budget");
        let message = err.to_string();
        assert!(!message.contains(&a_id.to_string()));
        assert!(!message.contains(&b_id.to_string()));
    }

    // FORNX-432 PR 2: property-based proof that the speed-ups above
    // (`ancestors_of_indexed` reuse, `family_key`/`bases_by_family`
    // replacing the per-family `Vec::contains`/`evidence.iter().find`
    // rescans) produce byte-identical output to the PR-1 reference oracle
    // (`build_reference`/`ancestors_of_reference`, untouched copies of
    // what this module's real `build`/`ancestors_of` did before PR 2).
    // Only compiled with `--features bench-reference`, since the oracle
    // functions themselves are gated behind it.
    #[cfg(feature = "bench-reference")]
    mod speedup_equivalence {
        use super::*;
        use proptest::prelude::*;

        /// A small fixed id table, reused across all of a single generated
        /// pool's evidence records so ids/correlation-groups/event-ids can
        /// collide, derived_from can dangle (point at an id never assigned
        /// to any record in the pool) or cycle, and two records can share
        /// an id outright -- all real inputs `build`/`build_reference` must
        /// agree on. `Uuid::from_u128` keeps the table deterministic across
        /// runs, independent of any RNG seed.
        const ID_TABLE_LEN: u128 = 12;

        fn id_at(i: u128) -> Uuid {
            Uuid::from_u128(i)
        }

        fn arb_trust_class() -> impl Strategy<Value = TrustClass> {
            prop_oneof![
                Just(TrustClass::AgentAdjacent),
                Just(TrustClass::ModelInternal),
                Just(TrustClass::HostObserved),
                Just(TrustClass::IndependentExternal),
                Just(TrustClass::HumanReviewed),
            ]
        }

        /// One evidence record spec: an id-table index (0..ID_TABLE_LEN,
        /// duplicates across the generated pool allowed on purpose), an
        /// optional source (`None` ~20% of the time), a small
        /// correlation-group index, a small source_event_id index, and 0-3
        /// derived_from indices drawn from the SAME id-table range --
        /// including indices never used as any record's own id (dangling)
        /// and indices that point back at an earlier or later record in the
        /// same generated pool (can form a cycle once assembled).
        /// (id-table index, optional trust class, correlation-group index,
        /// source_event_id index, derived_from indices).
        type EvidenceSpec = (u128, Option<TrustClass>, u128, u128, Vec<u128>);

        fn arb_evidence_spec() -> impl Strategy<Value = EvidenceSpec> {
            (
                0..ID_TABLE_LEN,
                prop::option::weighted(0.8, arb_trust_class()),
                0..4u128,
                0..4u128,
                prop::collection::vec(0..ID_TABLE_LEN, 0..3),
            )
        }

        fn build_pool(specs: Vec<EvidenceSpec>) -> Vec<Evidence> {
            specs
                .into_iter()
                .map(|(id_idx, trust, group_idx, event_idx, derived_idx)| {
                    let id = id_at(id_idx);
                    let source_event_id = id_at(100 + event_idx);
                    let derived_from: Vec<Uuid> = derived_idx.into_iter().map(id_at).collect();
                    match trust {
                        None => Evidence {
                            id,
                            session_id: "prop".to_string(),
                            source_event_id,
                            kind: EvidenceKind::ExitCode,
                            observed_at: "2026-01-01T00:00:00Z".to_string(),
                            payload: serde_json::json!({}),
                            provenance: "prop".to_string(),
                            source: None,
                            extension: None,
                            evidence_purged: false,
                        },
                        Some(trust_class) => {
                            // Index 0 is reserved to mean "no correlation
                            // group" -- correlation_group is only ever
                            // Some(..) for indices 1..4, so the "no group"
                            // case is still well represented.
                            let correlation_group = if group_idx == 0 {
                                None
                            } else {
                                Some(id_at(200 + group_idx))
                            };
                            Evidence {
                                id,
                                session_id: "prop".to_string(),
                                source_event_id,
                                kind: EvidenceKind::ExitCode,
                                observed_at: "2026-01-01T00:00:00Z".to_string(),
                                payload: serde_json::json!({}),
                                provenance: "prop".to_string(),
                                source: Some(EvidenceSource {
                                    sensor_name: "prop_sensor".to_string(),
                                    trust_class,
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
                    }
                })
                .collect()
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// `build` and `build_reference` must agree on every generated
            /// pool -- the core correctness claim of PR 2's speed-ups.
            #[test]
            fn build_matches_reference_oracle(
                specs in prop::collection::vec(arb_evidence_spec(), 0..10)
            ) {
                let pool = build_pool(specs);
                let fast = SourceFamilyMap::build(&pool);
                let reference = build_reference(&pool);
                prop_assert_eq!(fast.all_families(), reference.all_families());

                // `family_of` must also agree for every distinct id in the
                // pool (a duplicate id in `pool` still only needs checking
                // once).
                let mut seen = std::collections::HashSet::new();
                for e in &pool {
                    if !seen.insert(e.id) {
                        continue;
                    }
                    prop_assert_eq!(
                        fast.family_of(e.id).cloned(),
                        reference.family_of(e.id).cloned()
                    );
                }
            }

            /// `ancestors_of` and `ancestors_of_reference` must agree for
            /// every id in a generated pool, including a dangling or
            /// self-cyclic `derived_from` entry.
            #[test]
            fn ancestors_of_matches_reference_oracle(
                specs in prop::collection::vec(arb_evidence_spec(), 0..10)
            ) {
                let pool = build_pool(specs);
                let mut seen = std::collections::HashSet::new();
                for e in &pool {
                    if !seen.insert(e.id) {
                        continue;
                    }
                    prop_assert_eq!(
                        ancestors_of(e.id, &pool),
                        ancestors_of_reference(e.id, &pool)
                    );
                }
            }

            /// FORNX-432 PR 3: under a budget generous enough for every
            /// generated pool (small by construction -- at most 10 records,
            /// each with at most 3 `derived_from` entries, so real work
            /// units stay far below any realistic budget), `try_build` must
            /// produce exactly what `build` does. The bounded path must
            /// never be a silently divergent second implementation.
            #[test]
            fn try_build_matches_build_under_a_generous_budget(
                specs in prop::collection::vec(arb_evidence_spec(), 0..10)
            ) {
                let pool = build_pool(specs);
                let generous = super::FamilyBudget { max_work_units: 1_000_000 };
                let bounded = SourceFamilyMap::try_build(&pool, &generous)
                    .expect("generous budget must never abort on a pool this small");
                let unbounded = SourceFamilyMap::build(&pool);
                prop_assert_eq!(bounded.all_families(), unbounded.all_families());
            }
        }
    }
}
