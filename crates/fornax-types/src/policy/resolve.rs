//! Precedence resolution (FORNX-116).
//!
//! `resolve()` never returns `Err` and never panics. A device that cannot
//! resolve gets baseline + loud diagnostics — the local critical path
//! (ADR-0001 D2) must not fail closed because a remote policy layer is
//! malformed or missing. Malformed *wire* input is rejected earlier, at
//! `TryFrom<PolicyRevisionWire>`/`BoundRevision::new` construction time —
//! `resolve()` only ever sees already-validated [`BoundRevision`]s.
//!
//! **Algorithm** (order-independent in the input slice — shuffling `bound`
//! produces byte-identical output):
//!
//! 1. **Select** — a binding applies if its scope and selector both match
//!    the [`DeviceContext`].
//! 2. **Group** applicable bindings by [`TargetLevel`].
//! 3. **Within-level meet** — for each level and field, if two or more
//!    bindings at that level set *differing* values, emit an Error
//!    `ConflictingBindingsAtLevel` and take the strictest value.
//! 4. **Across-level override**, `Org -> Team -> Project -> Device ->
//!    LocalUser`. More specific wins, except a field a more-general level
//!    pinned may only be tightened, never loosened, by a later level — a
//!    violation emits an Error `PinViolation` and keeps the floor value.
//! 5. **Baseline** — any field still unset takes [`PolicyContent::baseline`].
//! 6. An empty or non-matching `bound` emits an Info `NoApplicablePolicy`
//!    and returns baseline for everything.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::content::{
    signal_class_sort_key, union_signal_classes, ActionClass, EgressContentClass, EnforcementRule,
    PolicyContent, RedactionProfile, ResolvedValues, RiskClassSeconds, VerdictOutcomes,
};
use super::diagnostics::{DiagnosticCode, DiagnosticSeverity, PolicyDiagnostic};
use super::revision::PolicyRevisionRef;
use super::target::{BoundRevision, DeviceContext, TargetLevel};
use crate::SignalClass;

/// Identifies one field of [`PolicyContent`] for pin bookkeeping and
/// diagnostic/provenance attribution. Pays for itself twice: pin
/// membership, and the provenance attribution a policy-simulation view can
/// render directly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyFieldId {
    CollectionLongitudinalAggregationAllowed,
    EgressCloudSyncAllowed,
    EgressRedactionProfile,
    EgressAllowedContent,
    SensorsDisabled,
    SensorsRequiredSignals,
    EnforcementRules,
    CacheMaxAgeByRisk,
    CacheOfflineGraceSeconds,
    /// A pin naming a field id this binary doesn't recognize (published by
    /// a newer binary). Must stay last.
    #[serde(untagged)]
    Unrecognized(String),
}

impl PolicyFieldId {
    pub const ALL: [PolicyFieldId; 9] = [
        PolicyFieldId::CollectionLongitudinalAggregationAllowed,
        PolicyFieldId::EgressCloudSyncAllowed,
        PolicyFieldId::EgressRedactionProfile,
        PolicyFieldId::EgressAllowedContent,
        PolicyFieldId::SensorsDisabled,
        PolicyFieldId::SensorsRequiredSignals,
        PolicyFieldId::EnforcementRules,
        PolicyFieldId::CacheMaxAgeByRisk,
        PolicyFieldId::CacheOfflineGraceSeconds,
    ];
}

/// Internal representation of one field's value, independent of its home
/// struct — lets the precedence engine (`meet_field`/`is_at_least_as_strict`)
/// be written once, generically, over all 9 fields.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum FieldValue {
    Bool(bool),
    RedactionProfile(RedactionProfile),
    AllowedContent(std::collections::BTreeSet<EgressContentClass>),
    SensorsDisabled(std::collections::BTreeSet<String>),
    RequiredSignals(Vec<SignalClass>),
    EnforcementRules(Vec<EnforcementRule>),
    CacheMaxAgeByRisk(RiskClassSeconds),
    CacheOfflineGraceSeconds(u32),
}

/// Reads `field` off `content`, canonicalizing the two `SignalClass`-keyed
/// collections and sorting `enforcement.rules` by `action_class` on the way
/// out so comparisons never see spurious insertion-order differences.
pub(crate) fn get_field(content: &PolicyContent, field: PolicyFieldId) -> Option<FieldValue> {
    match field {
        PolicyFieldId::CollectionLongitudinalAggregationAllowed => content
            .collection
            .longitudinal_aggregation_allowed
            .map(FieldValue::Bool),
        PolicyFieldId::EgressCloudSyncAllowed => {
            content.egress.cloud_sync_allowed.map(FieldValue::Bool)
        }
        PolicyFieldId::EgressRedactionProfile => content
            .egress
            .redaction_profile
            .map(FieldValue::RedactionProfile),
        PolicyFieldId::EgressAllowedContent => content
            .egress
            .allowed_content
            .clone()
            .map(FieldValue::AllowedContent),
        PolicyFieldId::SensorsDisabled => content
            .sensors
            .disabled
            .clone()
            .map(FieldValue::SensorsDisabled),
        PolicyFieldId::SensorsRequiredSignals => {
            content.sensors.required_signals.clone().map(|mut v| {
                v.sort_by_key(signal_class_sort_key);
                v.dedup_by(|a, b| a == b);
                FieldValue::RequiredSignals(v)
            })
        }
        PolicyFieldId::EnforcementRules => content.enforcement.rules.clone().map(|mut v| {
            v.sort_by(|a, b| a.action_class.cmp(&b.action_class));
            FieldValue::EnforcementRules(v)
        }),
        PolicyFieldId::CacheMaxAgeByRisk => content
            .cache
            .max_age_seconds_by_risk
            .map(FieldValue::CacheMaxAgeByRisk),
        PolicyFieldId::CacheOfflineGraceSeconds => content
            .cache
            .offline_grace_seconds
            .map(FieldValue::CacheOfflineGraceSeconds),
        PolicyFieldId::Unrecognized(_) => None,
    }
}

fn apply_field_to_resolved(values: &mut ResolvedValues, field: &PolicyFieldId, value: FieldValue) {
    match (field, value) {
        (PolicyFieldId::CollectionLongitudinalAggregationAllowed, FieldValue::Bool(b)) => {
            values.longitudinal_aggregation_allowed = b;
        }
        (PolicyFieldId::EgressCloudSyncAllowed, FieldValue::Bool(b)) => {
            values.cloud_sync_allowed = b
        }
        (PolicyFieldId::EgressRedactionProfile, FieldValue::RedactionProfile(r)) => {
            values.redaction_profile = r;
        }
        (PolicyFieldId::EgressAllowedContent, FieldValue::AllowedContent(s)) => {
            values.allowed_content = s
        }
        (PolicyFieldId::SensorsDisabled, FieldValue::SensorsDisabled(s)) => {
            values.sensors_disabled = s
        }
        (PolicyFieldId::SensorsRequiredSignals, FieldValue::RequiredSignals(v)) => {
            values.sensors_required_signals = v;
        }
        (PolicyFieldId::EnforcementRules, FieldValue::EnforcementRules(v)) => {
            values.enforcement_rules = v
        }
        (PolicyFieldId::CacheMaxAgeByRisk, FieldValue::CacheMaxAgeByRisk(v)) => {
            values.cache_max_age_seconds_by_risk = v;
        }
        (PolicyFieldId::CacheOfflineGraceSeconds, FieldValue::CacheOfflineGraceSeconds(v)) => {
            values.cache_offline_grace_seconds = v;
        }
        _ => {
            // Field id / value shape mismatch cannot happen: `get_field`
            // only ever pairs a field id with its own value shape.
        }
    }
}

/// One exhaustive match over all 9 field ids — the strictness table from
/// `docs/adr/0006-policy-as-data.md`.
fn meet_field(field: &PolicyFieldId, a: FieldValue, b: FieldValue) -> FieldValue {
    match (field, a, b) {
        (
            PolicyFieldId::CollectionLongitudinalAggregationAllowed,
            FieldValue::Bool(a),
            FieldValue::Bool(b),
        ) => FieldValue::Bool(a && b),
        (PolicyFieldId::EgressCloudSyncAllowed, FieldValue::Bool(a), FieldValue::Bool(b)) => {
            FieldValue::Bool(a && b)
        }
        (
            PolicyFieldId::EgressRedactionProfile,
            FieldValue::RedactionProfile(a),
            FieldValue::RedactionProfile(b),
        ) => FieldValue::RedactionProfile(a.max(b)),
        (
            PolicyFieldId::EgressAllowedContent,
            FieldValue::AllowedContent(a),
            FieldValue::AllowedContent(b),
        ) => FieldValue::AllowedContent(a.intersection(&b).cloned().collect()),
        (
            PolicyFieldId::SensorsDisabled,
            FieldValue::SensorsDisabled(a),
            FieldValue::SensorsDisabled(b),
        ) => FieldValue::SensorsDisabled(a.union(&b).cloned().collect()),
        (
            PolicyFieldId::SensorsRequiredSignals,
            FieldValue::RequiredSignals(a),
            FieldValue::RequiredSignals(b),
        ) => FieldValue::RequiredSignals(union_signal_classes(a, b)),
        (
            PolicyFieldId::EnforcementRules,
            FieldValue::EnforcementRules(a),
            FieldValue::EnforcementRules(b),
        ) => FieldValue::EnforcementRules(meet_enforcement_rules(a, b)),
        (
            PolicyFieldId::CacheMaxAgeByRisk,
            FieldValue::CacheMaxAgeByRisk(a),
            FieldValue::CacheMaxAgeByRisk(b),
        ) => FieldValue::CacheMaxAgeByRisk(RiskClassSeconds::meet(a, b)),
        (
            PolicyFieldId::CacheOfflineGraceSeconds,
            FieldValue::CacheOfflineGraceSeconds(a),
            FieldValue::CacheOfflineGraceSeconds(b),
        ) => FieldValue::CacheOfflineGraceSeconds(a.min(b)),
        (_, a, _) => a, // unreachable: field id and value shape always agree
    }
}

fn meet_enforcement_rules(
    a: Vec<EnforcementRule>,
    b: Vec<EnforcementRule>,
) -> Vec<EnforcementRule> {
    let mut merged: BTreeMap<ActionClass, EnforcementRule> = BTreeMap::new();
    for rule in a.into_iter().chain(b) {
        merged
            .entry(rule.action_class.clone())
            .and_modify(|existing| {
                existing.risk_class = existing.risk_class.max(rule.risk_class);
                existing.outcomes = VerdictOutcomes::meet(existing.outcomes, rule.outcomes);
            })
            .or_insert(rule);
    }
    merged.into_values().collect()
}

/// Whether `candidate` is at least as strict as `floor` for `field` — the
/// pin-violation check. The direction mirrors `meet_field`'s strictness
/// table exactly.
fn is_at_least_as_strict(
    field: &PolicyFieldId,
    candidate: &FieldValue,
    floor: &FieldValue,
) -> bool {
    match (field, candidate, floor) {
        (
            PolicyFieldId::CollectionLongitudinalAggregationAllowed,
            FieldValue::Bool(c),
            FieldValue::Bool(f),
        ) => *f || !*c,
        (PolicyFieldId::EgressCloudSyncAllowed, FieldValue::Bool(c), FieldValue::Bool(f)) => {
            *f || !*c
        }
        (
            PolicyFieldId::EgressRedactionProfile,
            FieldValue::RedactionProfile(c),
            FieldValue::RedactionProfile(f),
        ) => c >= f,
        (
            PolicyFieldId::EgressAllowedContent,
            FieldValue::AllowedContent(c),
            FieldValue::AllowedContent(f),
        ) => c.is_subset(f),
        (
            PolicyFieldId::SensorsDisabled,
            FieldValue::SensorsDisabled(c),
            FieldValue::SensorsDisabled(f),
        ) => c.is_superset(f),
        (
            PolicyFieldId::SensorsRequiredSignals,
            FieldValue::RequiredSignals(c),
            FieldValue::RequiredSignals(f),
        ) => f.iter().all(|fs| c.iter().any(|cs| cs == fs)),
        (
            PolicyFieldId::EnforcementRules,
            FieldValue::EnforcementRules(c),
            FieldValue::EnforcementRules(f),
        ) => f.iter().all(|floor_rule| {
            c.iter()
                .find(|cr| cr.action_class == floor_rule.action_class)
                .map(|cr| {
                    cr.risk_class >= floor_rule.risk_class
                        && cr.outcomes.verified >= floor_rule.outcomes.verified
                        && cr.outcomes.unverified >= floor_rule.outcomes.unverified
                        && cr.outcomes.contradicted >= floor_rule.outcomes.contradicted
                        && cr.outcomes.review >= floor_rule.outcomes.review
                        && cr.outcomes.unavailable >= floor_rule.outcomes.unavailable
                })
                .unwrap_or(false)
        }),
        (
            PolicyFieldId::CacheMaxAgeByRisk,
            FieldValue::CacheMaxAgeByRisk(c),
            FieldValue::CacheMaxAgeByRisk(f),
        ) => {
            c.low <= f.low
                && c.elevated <= f.elevated
                && c.high <= f.high
                && c.critical <= f.critical
        }
        (
            PolicyFieldId::CacheOfflineGraceSeconds,
            FieldValue::CacheOfflineGraceSeconds(c),
            FieldValue::CacheOfflineGraceSeconds(f),
        ) => c <= f,
        _ => true, // unreachable: field id and value shape always agree
    }
}

/// Where a resolved field's value came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldProvenance {
    Baseline,
    Layer {
        level: TargetLevel,
        binding_id: Uuid,
        revision: PolicyRevisionRef,
    },
    Pinned {
        level: TargetLevel,
        binding_id: Uuid,
        revision: PolicyRevisionRef,
    },
}

/// The output of [`resolve`]: all-concrete values, per-field provenance, and
/// the set of revisions that actually contributed a non-baseline value (a
/// future reporting ticket surfaces these — refs only, never raw evidence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub values: ResolvedValues,
    pub provenance: BTreeMap<PolicyFieldId, FieldProvenance>,
    pub contributing: Vec<PolicyRevisionRef>,
}

/// Fields whose strictness meet (see `meet_field`) is naturally monotonic —
/// disabling a sensor or requiring a signal is a safety floor that
/// accumulates across every applicable level rather than being replaced by
/// a more specific layer's opinion, the same way a pin would force but
/// without needing one. Every other field (including `EnforcementRules`,
/// deliberately) is override-style: the most specific applicable level's
/// value replaces the previous levels' entirely (unless a pin forbids
/// loosening it) — this is what makes project/device exemptions
/// expressible, including an exemption from an org-wide enforcement rule
/// for one action class (see `docs/adr/0006-policy-as-data.md`).
fn is_accumulate_field(field: &PolicyFieldId) -> bool {
    matches!(
        field,
        PolicyFieldId::SensorsDisabled | PolicyFieldId::SensorsRequiredSignals
    )
}

fn provenance_level(provenance: &FieldProvenance) -> Option<TargetLevel> {
    match provenance {
        FieldProvenance::Baseline => None,
        FieldProvenance::Layer { level, .. } | FieldProvenance::Pinned { level, .. } => {
            Some(*level)
        }
    }
}

fn info_no_applicable_policy() -> PolicyDiagnostic {
    PolicyDiagnostic::new(
        DiagnosticCode::NoApplicablePolicy,
        DiagnosticSeverity::Info,
        "no policy binding applies to this device; using baseline defaults",
        "publish a binding that targets this org/team/project/device, or accept baseline defaults",
    )
}

/// See module docs for the full algorithm. Never returns `Err`, never
/// panics.
pub fn resolve(
    bound: &[BoundRevision],
    ctx: &DeviceContext,
) -> (ResolvedPolicy, Vec<PolicyDiagnostic>) {
    let mut diagnostics: Vec<PolicyDiagnostic> = Vec::new();

    let mut applicable: Vec<&BoundRevision> = Vec::new();
    for b in bound {
        if b.binding().matches(ctx, &mut diagnostics) {
            applicable.push(b);
        }
    }

    if applicable.is_empty() {
        diagnostics.push(info_no_applicable_policy());
        let baseline = PolicyContent::baseline();
        let provenance = PolicyFieldId::ALL
            .into_iter()
            .map(|f| (f, FieldProvenance::Baseline))
            .collect();
        return (
            ResolvedPolicy {
                values: baseline,
                provenance,
                contributing: Vec::new(),
            },
            diagnostics,
        );
    }

    let mut by_level: BTreeMap<TargetLevel, Vec<&BoundRevision>> = BTreeMap::new();
    for b in &applicable {
        by_level
            .entry(b.binding().scope.level())
            .or_default()
            .push(b);
    }

    let mut floors: BTreeMap<PolicyFieldId, (FieldValue, FieldProvenance)> = BTreeMap::new();
    let mut current: BTreeMap<PolicyFieldId, (FieldValue, FieldProvenance)> = BTreeMap::new();
    let mut contributing: Vec<PolicyRevisionRef> = Vec::new();

    let levels = [
        TargetLevel::Org,
        TargetLevel::Team,
        TargetLevel::Project,
        TargetLevel::Device,
        TargetLevel::LocalUser,
    ];

    for level in levels {
        let Some(bindings) = by_level.get(&level) else {
            continue;
        };

        for field in PolicyFieldId::ALL {
            let mut candidates: Vec<(FieldValue, Uuid, PolicyRevisionRef)> = Vec::new();
            for b in bindings {
                if let Some(v) = get_field(&b.revision().body().content, field.clone()) {
                    candidates.push((v, b.binding().binding_id, b.revision().reference()));
                }
            }
            if candidates.is_empty() {
                continue;
            }

            let first_value = candidates[0].0.clone();
            let differing = candidates.iter().any(|(v, _, _)| v != &first_value);

            let mut merged_value = candidates[0].0.clone();
            for (v, _, _) in candidates.iter().skip(1) {
                merged_value = meet_field(&field, merged_value, v.clone());
            }

            let mut representative_binding = candidates[0].1;
            let mut representative_ref = candidates[0].2.clone();
            for (_, bid, rref) in &candidates {
                if *bid < representative_binding {
                    representative_binding = *bid;
                    representative_ref = rref.clone();
                }
            }

            if differing {
                diagnostics.push(
                    PolicyDiagnostic::new(
                        DiagnosticCode::ConflictingBindingsAtLevel,
                        DiagnosticSeverity::Error,
                        format!("multiple bindings at {level:?} set {field:?} to differing values"),
                        "republish a single binding at this level for this field, or move the exception to a more specific level",
                    )
                    .with_field(field.clone())
                    .with_bindings(candidates.iter().map(|(_, id, _)| *id).collect())
                    .with_revisions(candidates.iter().map(|(_, _, r)| r.clone()).collect()),
                );
            }

            // Accumulate-style fields fold with whatever a less-specific
            // level already contributed instead of being replaced by it —
            // see `is_accumulate_field`.
            let level_value = if is_accumulate_field(&field) {
                if let Some((prev_value, _)) = current.get(&field) {
                    meet_field(&field, prev_value.clone(), merged_value)
                } else {
                    merged_value
                }
            } else {
                merged_value
            };

            let this_level_provenance = FieldProvenance::Layer {
                level,
                binding_id: representative_binding,
                revision: representative_ref.clone(),
            };

            let (accepted_value, accepted_provenance) = if let Some((
                floor_value,
                floor_provenance,
            )) = floors.get(&field)
            {
                if is_at_least_as_strict(&field, &level_value, floor_value) {
                    (level_value, this_level_provenance)
                } else {
                    let floor_level = provenance_level(floor_provenance);
                    diagnostics.push(
                            PolicyDiagnostic::new(
                                DiagnosticCode::PinViolation,
                                DiagnosticSeverity::Error,
                                format!("{field:?} pinned at {floor_level:?} cannot be loosened at {level:?}"),
                                "remove the conflicting override, or tighten it to at least the pinned value",
                            )
                            .with_field(field.clone())
                            .with_bindings(vec![representative_binding])
                            .with_revisions(vec![representative_ref.clone()]),
                        );
                    (floor_value.clone(), floor_provenance.clone())
                }
            } else {
                (level_value, this_level_provenance)
            };

            current.insert(field.clone(), (accepted_value.clone(), accepted_provenance));
            if !contributing.contains(&representative_ref) {
                contributing.push(representative_ref.clone());
            }

            for b in bindings {
                if b.revision().body().pinned_fields.contains(&field) {
                    let pin_provenance = FieldProvenance::Pinned {
                        level,
                        binding_id: b.binding().binding_id,
                        revision: b.revision().reference(),
                    };
                    floors.insert(
                        field.clone(),
                        (accepted_value.clone(), pin_provenance.clone()),
                    );
                    if let Some(entry) = current.get_mut(&field) {
                        entry.1 = pin_provenance;
                    }
                }
            }
        }
    }

    let mut values = PolicyContent::baseline();
    let mut provenance = BTreeMap::new();
    for field in PolicyFieldId::ALL {
        if let Some((value, prov)) = current.get(&field) {
            apply_field_to_resolved(&mut values, &field, value.clone());
            provenance.insert(field, prov.clone());
        } else {
            provenance.insert(field, FieldProvenance::Baseline);
        }
    }

    (
        ResolvedPolicy {
            values,
            provenance,
            contributing,
        },
        diagnostics,
    )
}
