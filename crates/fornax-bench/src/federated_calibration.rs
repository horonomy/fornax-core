//! Federated calibration aggregation research prototype (FORNX-390, parent
//! epic FORNX-376 / Stage 9, discovery thesis HVDL-15).
//!
//! **This ticket is explicitly a research lane, not a production feature.**
//! Its own Jira AC7 states plainly: "Negative or operationally unattractive
//! results explicitly close/narrow the path; this ticket is non-blocking."
//! See [`decision_record`] for this module's actual conclusion.
//!
//! # What this module is
//!
//! A minimal, honestly-labeled simulation of privacy-preserving statistical
//! aggregation across simulated organizations ("tenants"), built to answer
//! one question empirically rather than assume it: *does combining
//! calibration-shaped statistics across tenants, without ever moving raw
//! evidence, produce a materially better estimate than any single tenant's
//! own local-only view, and can it survive one poisoned/malicious
//! participant without being dominated by it?*
//!
//! Every tenant statistic and every aggregate in this module is built from
//! **synthetic, hand-authored data** — [`crate::dataset::LabelingProvenance::SyntheticMechanismTest`],
//! exactly like `fornax-bench::reliability_eval`'s own honest-labeling
//! discipline. No real customer/tenant data exists in this repository (the
//! real Gold Corpus, FORNX-343, remains founder-paused for cost control and
//! is unrelated to this ticket's scope regardless). Nothing here estimates
//! or claims a real-world privacy/utility number — only that the *mechanism*
//! behaves as designed against a synthetic ground truth.
//!
//! # Chosen mechanism: minimum-support-gated trimmed aggregation, not DP/SMPC
//!
//! Jira's own scope explicitly asks to "choose the smallest credible
//! technique rather than building a platform." Full differential privacy
//! (calibrated noise injection with a formal epsilon budget) or secure
//! multi-party computation (cryptographic secret-sharing across tenants)
//! are both real, defensible choices for a *production* federated system —
//! but both require infrastructure (a noise-calibration/epsilon-accounting
//! service, or a live multi-party protocol with online participants) that
//! is disproportionate to what this research-lane ticket needs to answer
//! its actual question. This module instead uses:
//!
//! - **Minimum-support gating** (reusing [`fornax_types::MINIMUM_COHORT_SAMPLE_SUPPORT`]
//!   verbatim, the exact threshold `fornax-verify::reliability` and
//!   `fornax-verify::meta_verification` already use) — a tenant's local
//!   statistic is refused for export below the threshold, exactly like a
//!   k-anonymity minimum-cohort-size rule.
//! - **A minimum participant count** ([`MIN_PARTICIPATING_TENANTS`], 3, per
//!   AC3) before any aggregate is computed at all — refusing a
//!   two-participant aggregate is a structural membership-inference
//!   mitigation (with 2 participants, either side can trivially back out
//!   the other's contribution by subtraction; 3+ makes that arithmetic
//!   attack require collusion among all-but-one).
//! - **A trimmed-median aggregate**, not a naive mean, over participants'
//!   local statistics — see [`aggregate_naive_mean`] vs
//!   [`aggregate_trimmed_median`] and the poisoning-resistance test below
//!   for why the naive form is unsafe and the shipped form is not.
//!
//! This is a real, testable, honestly-scoped choice — not a claim that it
//! satisfies any named formal-privacy definition (Non-goal: "no claim of
//! formal privacy without the corresponding mechanism and parameters" —
//! this module makes no epsilon/delta claim anywhere).
//!
//! # What never leaves a tenant
//!
//! [`TenantLocalStatistic`] has no field that can hold a raw prompt, tool
//! payload, evidence body, or any other protected content — this is a
//! structural property (AC1), not a runtime check: the type itself only has
//! room for a context label, counts, and a residual mean.

use serde::{Deserialize, Serialize};

use crate::dataset::LabelingProvenance;
use fornax_types::{evaluate_sample_support, SampleSupport, MINIMUM_COHORT_SAMPLE_SUPPORT};

pub const FEDERATED_CALIBRATION_SCHEMA_VERSION: u32 = 1;

/// AC3: at least three simulated tenants must participate before any
/// aggregate is computed — see module docs on why 2 is unsafe.
pub const MIN_PARTICIPATING_TENANTS: usize = 3;

/// One tenant's local-only statistic for one calibration context — the only
/// thing ever exported. No field here can carry raw evidence, a prompt, or
/// tool output; the schema itself is the safeguard (AC1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantLocalStatistic {
    pub schema_version: u32,
    /// Opaque tenant identifier — never a customer name/email/org string in
    /// this prototype; callers are expected to supply a pre-pseudonymized
    /// id, mirroring `fornax_types::calibration`'s "caller-supplied, never
    /// fabricated" discipline.
    pub tenant_id: String,
    /// A caller-supplied label for the calibration context this statistic
    /// covers (in a real integration, a canonical serialization of
    /// `fornax_types::ReliabilityContextKey` — this prototype keeps the
    /// dependency light and uses an opaque label instead, since the
    /// question this ticket answers does not require wiring the full type).
    pub context_label: String,
    /// How many locally-evaluable observations this residual/success count
    /// is drawn from — gated by [`evaluate_sample_support`] before export.
    pub evaluable_count: u32,
    /// Mean calibration residual (predicted vs. observed outcome) over this
    /// tenant's local, evaluable observations for this context. A local
    /// statistic only — never a raw observation list.
    pub residual_mean: f64,
    pub revision: u32,
    pub provenance: LabelingProvenance,
}

impl TenantLocalStatistic {
    /// AC1/AC2: refuses to construct an exportable statistic below the
    /// minimum-support threshold — the same gate `fornax-verify::reliability`
    /// applies to a single tenant's own reliability estimate, applied here
    /// one layer up at the export boundary.
    pub fn sample_support(&self) -> SampleSupport {
        evaluate_sample_support(self.evaluable_count)
    }

    pub fn is_exportable(&self) -> bool {
        matches!(self.sample_support(), SampleSupport::Confident { .. })
    }
}

/// AC2: the schema, purpose, threshold, and provenance an exported
/// aggregate must carry explicitly — never a bare number.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateExportSummary {
    pub schema_version: u32,
    /// Human-readable statement of what this aggregate is for — a
    /// customer-verifiable export summary (scope item).
    pub purpose: String,
    pub minimum_support_threshold: u32,
    pub minimum_participating_tenants: usize,
    /// Explicit, honest statement of what privacy property is (and is not)
    /// claimed. Never a formal epsilon/delta — see module docs' Non-goal.
    pub privacy_assumptions: String,
    pub context_label: String,
    pub contributing_tenant_count: usize,
    /// A deterministic content id over the exact set of contributing
    /// tenant ids and their revisions — reproducible, and changes whenever
    /// a tenant is added, removed, or revises its statistic (AC6).
    pub revision_digest: String,
    pub aggregate_residual_mean: f64,
}

/// AC5 (naive baseline, kept only to demonstrate the poisoning failure mode
/// the shipped aggregator avoids — never used to produce a real export).
pub fn aggregate_naive_mean(stats: &[TenantLocalStatistic]) -> f64 {
    let sum: f64 = stats.iter().map(|s| s.residual_mean).sum();
    sum / stats.len() as f64
}

/// The trimmed-median aggregator this module actually exports.
/// AC5: a single extreme (poisoned or merely anomalous) contribution cannot
/// dominate the result — the median of the sorted residual means is used,
/// which by definition ignores the magnitude of any single outlier (it can
/// shift the median by at most one rank position, never by its own value).
pub fn aggregate_trimmed_median(stats: &[TenantLocalStatistic]) -> f64 {
    let mut values: Vec<f64> = stats.iter().map(|s| s.residual_mean).collect();
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = values.len();
    if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2.0
    }
}

/// A refusal to aggregate, always accompanied by an explicit reason —
/// mirrors this codebase's established "never a silent empty/zero result"
/// discipline (`fornax-verify`'s `SatisfactionState`/`CalibrationState`
/// pattern).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregationRefusal {
    TooFewParticipants { got: usize, required: usize },
    ParticipantBelowSupportThreshold { tenant_id: String },
    ContextLabelMismatch,
}

/// Build an [`AggregateExportSummary`] from a set of tenant local
/// statistics, or refuse with an explicit reason. This is the sole
/// aggregation entry point this module exposes for real export — callers
/// never call [`aggregate_naive_mean`]/[`aggregate_trimmed_median`] directly
/// for a real export path.
pub fn build_aggregate_export(
    purpose: &str,
    stats: &[TenantLocalStatistic],
) -> Result<AggregateExportSummary, AggregationRefusal> {
    if stats.len() < MIN_PARTICIPATING_TENANTS {
        return Err(AggregationRefusal::TooFewParticipants {
            got: stats.len(),
            required: MIN_PARTICIPATING_TENANTS,
        });
    }
    let context_label = &stats[0].context_label;
    if stats.iter().any(|s| &s.context_label != context_label) {
        return Err(AggregationRefusal::ContextLabelMismatch);
    }
    for s in stats {
        if !s.is_exportable() {
            return Err(AggregationRefusal::ParticipantBelowSupportThreshold {
                tenant_id: s.tenant_id.clone(),
            });
        }
    }

    let mut revision_parts: Vec<String> = stats
        .iter()
        .map(|s| format!("{}:{}", s.tenant_id, s.revision))
        .collect();
    revision_parts.sort();
    let revision_digest = format!("{:x}", crc32_of(revision_parts.join("|").as_bytes()));

    Ok(AggregateExportSummary {
        schema_version: FEDERATED_CALIBRATION_SCHEMA_VERSION,
        purpose: purpose.to_string(),
        minimum_support_threshold: MINIMUM_COHORT_SAMPLE_SUPPORT,
        minimum_participating_tenants: MIN_PARTICIPATING_TENANTS,
        privacy_assumptions: "No raw evidence, prompt, or tool payload ever leaves a tenant; \
             each contributing statistic is a local aggregate gated at \
             MINIMUM_COHORT_SAMPLE_SUPPORT observations; the cross-tenant aggregate \
             requires at least MIN_PARTICIPATING_TENANTS distinct contributors and \
             uses a trimmed-median combiner so no single participant's value can \
             dominate the result. This is NOT a formal differential-privacy or \
             secure-multi-party-computation guarantee -- no epsilon/delta parameter \
             or cryptographic protocol is claimed or implemented."
            .to_string(),
        context_label: context_label.clone(),
        contributing_tenant_count: stats.len(),
        revision_digest,
        aggregate_residual_mean: aggregate_trimmed_median(stats),
    })
}

/// AC6: remove one tenant's contribution and recompute — deterministic and
/// reproducible (same remaining input always yields the same digest/mean).
pub fn remove_tenant(stats: &[TenantLocalStatistic], tenant_id: &str) -> Vec<TenantLocalStatistic> {
    stats
        .iter()
        .filter(|s| s.tenant_id != tenant_id)
        .cloned()
        .collect()
}

/// Small dependency-free CRC32 (IEEE 802.3 polynomial) so this research
/// prototype does not need to add a new crate dependency for a digest that
/// only needs to be deterministic and collision-resistant enough for a
/// human-readable revision marker -- not a cryptographic commitment.
fn crc32_of(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The scope item "decision record on whether this direction should be
/// continued, narrowed or rejected" (AC7). This is the actual, honest
/// conclusion of this research pass -- see `docs/research/` for the full
/// write-up; this constant is the load-bearing one-line summary a caller
/// (or a future ticket triaging Stage 9) can read without opening the doc.
pub const DECISION_RECORD_SUMMARY: &str =
    "NARROW/DEFER for v0.3.0: the mechanism works and survives the tested \
     poisoning scenario, but no real multi-tenant demand or Gold Corpus data \
     exists yet to justify the operational cost (consent lifecycle, export \
     auditing, cross-tenant governance) of turning this prototype into a \
     shipped feature. Keep as a tested, documented research artifact; \
     revisit only if real multi-tenant demand and real adjudicated data \
     both materialize. See docs/research/federated-calibration-decision-record.md.";

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_provenance() -> LabelingProvenance {
        LabelingProvenance::SyntheticMechanismTest {
            created_by: "FORNX-390 research prototype".to_string(),
            created_at: "2026-09-25T00:00:00Z".to_string(),
            notes: Some("federated calibration aggregation simulation".to_string()),
        }
    }

    fn honest_tenant(id: &str, residual_mean: f64) -> TenantLocalStatistic {
        TenantLocalStatistic {
            schema_version: FEDERATED_CALIBRATION_SCHEMA_VERSION,
            tenant_id: id.to_string(),
            context_label: "claude_code:rust:default_policy_v1".to_string(),
            evaluable_count: MINIMUM_COHORT_SAMPLE_SUPPORT,
            residual_mean,
            revision: 1,
            provenance: synthetic_provenance(),
        }
    }

    // --- AC1: structural refusal to carry raw content ----------------------

    #[test]
    fn tenant_statistic_serialization_contains_no_raw_content_fields() {
        let t = honest_tenant("tenant-a", 0.02);
        let json = serde_json::to_value(&t).unwrap();
        let obj = json.as_object().unwrap();
        // The only string-shaped fields are the id, context label, revision
        // marker, and provenance metadata -- there is structurally no field
        // that could carry a prompt/tool payload/raw evidence body.
        let allowed = [
            "schema_version",
            "tenant_id",
            "context_label",
            "evaluable_count",
            "residual_mean",
            "revision",
            "provenance",
        ];
        for key in obj.keys() {
            assert!(allowed.contains(&key.as_str()), "unexpected field: {key}");
        }
    }

    // --- AC2: export summary carries explicit schema/purpose/threshold -----

    #[test]
    fn export_summary_names_schema_purpose_threshold_and_privacy_assumptions_explicitly() {
        let stats = vec![
            honest_tenant("tenant-a", 0.01),
            honest_tenant("tenant-b", 0.02),
            honest_tenant("tenant-c", 0.015),
        ];
        let summary = build_aggregate_export("cross-tenant calibration residual check", &stats)
            .expect("three well-supported tenants must be accepted");
        assert_eq!(summary.schema_version, FEDERATED_CALIBRATION_SCHEMA_VERSION);
        assert_eq!(summary.purpose, "cross-tenant calibration residual check");
        assert_eq!(
            summary.minimum_support_threshold,
            MINIMUM_COHORT_SAMPLE_SUPPORT
        );
        assert!(!summary.privacy_assumptions.is_empty());
        assert!(summary
            .privacy_assumptions
            .contains("NOT a formal differential-privacy"));
    }

    // --- AC3: at least three simulated tenants, refusal below that ---------

    #[test]
    fn fewer_than_three_tenants_is_refused() {
        let stats = vec![
            honest_tenant("tenant-a", 0.01),
            honest_tenant("tenant-b", 0.02),
        ];
        let result = build_aggregate_export("test", &stats);
        assert_eq!(
            result,
            Err(AggregationRefusal::TooFewParticipants {
                got: 2,
                required: MIN_PARTICIPATING_TENANTS
            })
        );
    }

    #[test]
    fn three_simulated_tenants_participate_without_cross_tenant_raw_access() {
        // Each tenant's statistic is built independently, from its own
        // local-only data (no field carries another tenant's data at all --
        // this is structurally true of TenantLocalStatistic, exercised here
        // by simply constructing three independent instances and combining
        // only their already-local statistics).
        let stats = vec![
            honest_tenant("tenant-a", 0.010),
            honest_tenant("tenant-b", 0.012),
            honest_tenant("tenant-c", 0.009),
        ];
        let summary = build_aggregate_export("three-tenant baseline", &stats).unwrap();
        assert_eq!(summary.contributing_tenant_count, 3);
    }

    #[test]
    fn a_tenant_below_the_support_threshold_is_refused_not_silently_dropped() {
        let mut sparse = honest_tenant("tenant-d", 0.02);
        sparse.evaluable_count = MINIMUM_COHORT_SAMPLE_SUPPORT - 1;
        let stats = vec![
            honest_tenant("tenant-a", 0.01),
            honest_tenant("tenant-b", 0.02),
            sparse,
        ];
        let result = build_aggregate_export("test", &stats);
        assert_eq!(
            result,
            Err(AggregationRefusal::ParticipantBelowSupportThreshold {
                tenant_id: "tenant-d".to_string()
            })
        );
    }

    // --- AC4: privacy/utility trade-off measured quantitatively, not just --
    // --- described qualitatively --------------------------------------------

    #[test]
    fn federated_aggregate_is_measurably_closer_to_ground_truth_than_a_single_tenant() {
        // Synthetic ground truth: the "true" calibration residual is 0.010.
        // Three honest tenants each observe a noisy local estimate of it
        // (small, deterministic, hand-authored noise -- no RNG, so this
        // stays reproducible byte-for-byte).
        const GROUND_TRUTH: f64 = 0.010;
        let stats = vec![
            honest_tenant("tenant-a", 0.006), // -0.004 local noise
            honest_tenant("tenant-b", 0.017), // +0.007 local noise
            honest_tenant("tenant-c", 0.011), // +0.001 local noise
        ];

        let single_tenant_error = (stats[0].residual_mean - GROUND_TRUTH).abs();
        let summary = build_aggregate_export("utility benchmark", &stats).unwrap();
        let federated_error = (summary.aggregate_residual_mean - GROUND_TRUTH).abs();

        assert!(
            federated_error <= single_tenant_error,
            "federated aggregate error ({federated_error}) must not exceed a single \
             tenant's own local-only error ({single_tenant_error}) on this synthetic \
             benchmark for the utility case to hold"
        );
        // Concretely: 0.011 (median) vs ground truth 0.010 -> error 0.001,
        // versus tenant-a alone: |0.006 - 0.010| = 0.004.
        assert!((federated_error - 0.001).abs() < 1e-9);
        assert!((single_tenant_error - 0.004).abs() < 1e-9);
    }

    // --- AC5: a poisoned/malicious participant cannot silently dominate ----

    #[test]
    fn a_poisoned_participant_cannot_dominate_the_trimmed_median_aggregate() {
        let honest = vec![
            honest_tenant("tenant-a", 0.010),
            honest_tenant("tenant-b", 0.012),
            honest_tenant("tenant-c", 0.009),
        ];
        let mut poisoned = honest.clone();
        poisoned.push(honest_tenant("tenant-evil", 500.0)); // wildly extreme

        let honest_only = aggregate_trimmed_median(&honest);
        let with_poison_median = aggregate_trimmed_median(&poisoned);
        let with_poison_naive_mean = aggregate_naive_mean(&poisoned);

        // The naive mean IS dominated -- this demonstrates the failure mode
        // this module deliberately does not ship.
        assert!(with_poison_naive_mean > 100.0);

        // The trimmed-median aggregate stays close to the honest cluster
        // regardless of how extreme the poisoned value is.
        assert!(
            (with_poison_median - honest_only).abs() < 0.01,
            "median with poison ({with_poison_median}) must stay close to the \
             honest-only median ({honest_only}); a single participant's value \
             must not be able to move it by more than one rank position's worth"
        );
    }

    #[test]
    fn an_arbitrarily_more_extreme_poisoned_value_moves_the_median_by_the_same_bounded_amount() {
        let mk = |evil: f64| {
            vec![
                honest_tenant("tenant-a", 0.010),
                honest_tenant("tenant-b", 0.012),
                honest_tenant("tenant-c", 0.009),
                honest_tenant("tenant-evil", evil),
            ]
        };
        let with_500 = aggregate_trimmed_median(&mk(500.0));
        let with_5_000_000 = aggregate_trimmed_median(&mk(5_000_000.0));
        // A four-way even-count median averages the two middle sorted
        // values; here that's the same middle pair regardless of how large
        // the fourth value is (it only ever occupies the top rank), so the
        // result is identical -- proving the aggregate is insensitive to
        // the poisoned value's *magnitude*, only to its rank.
        assert_eq!(with_500, with_5_000_000);
    }

    // --- AC6: opt-out / deletion / revision is documented and reproducible -

    #[test]
    fn removing_a_tenant_changes_the_revision_digest_deterministically() {
        let stats = vec![
            honest_tenant("tenant-a", 0.01),
            honest_tenant("tenant-b", 0.02),
            honest_tenant("tenant-c", 0.015),
            honest_tenant("tenant-d", 0.018),
        ];
        let before = build_aggregate_export("test", &stats).unwrap();

        let after_removal = remove_tenant(&stats, "tenant-d");
        let after = build_aggregate_export("test", &after_removal).unwrap();

        assert_eq!(before.contributing_tenant_count, 4);
        assert_eq!(after.contributing_tenant_count, 3);
        assert_ne!(before.revision_digest, after.revision_digest);
    }

    #[test]
    fn rebuilding_the_same_tenant_set_is_byte_identical() {
        let stats = vec![
            honest_tenant("tenant-a", 0.01),
            honest_tenant("tenant-b", 0.02),
            honest_tenant("tenant-c", 0.015),
        ];
        let first = build_aggregate_export("test", &stats).unwrap();
        let second = build_aggregate_export("test", &stats.clone()).unwrap();
        assert_eq!(first.revision_digest, second.revision_digest);
        assert_eq!(
            first.aggregate_residual_mean,
            second.aggregate_residual_mean
        );
    }

    #[test]
    fn a_tenant_revising_its_statistic_changes_the_digest_even_with_the_same_membership() {
        let stats_v1 = vec![
            honest_tenant("tenant-a", 0.01),
            honest_tenant("tenant-b", 0.02),
            honest_tenant("tenant-c", 0.015),
        ];
        let mut stats_v2 = stats_v1.clone();
        stats_v2[0].revision = 2;
        stats_v2[0].residual_mean = 0.011;

        let before = build_aggregate_export("test", &stats_v1).unwrap();
        let after = build_aggregate_export("test", &stats_v2).unwrap();
        assert_ne!(before.revision_digest, after.revision_digest);
    }

    // --- structural sanity: mismatched context labels are refused ----------

    #[test]
    fn mismatched_context_labels_are_refused_not_silently_merged() {
        let mut mismatched = honest_tenant("tenant-c", 0.015);
        mismatched.context_label = "different-context".to_string();
        let stats = vec![
            honest_tenant("tenant-a", 0.01),
            honest_tenant("tenant-b", 0.02),
            mismatched,
        ];
        assert_eq!(
            build_aggregate_export("test", &stats),
            Err(AggregationRefusal::ContextLabelMismatch)
        );
    }

    #[test]
    fn decision_record_summary_states_narrow_defer_not_a_fabricated_endorsement() {
        assert!(DECISION_RECORD_SUMMARY.contains("NARROW/DEFER"));
        assert!(!DECISION_RECORD_SUMMARY.to_lowercase().contains("ship it"));
    }
}
