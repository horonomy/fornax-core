//! Context-conditioned reliability and drift computation (FORNX-104, parent
//! epic FORNX-20 / discovery thesis HVDL-15).
//!
//! FORNX-103 (`fornax_types::reliability_context`) defined the schema a
//! reliability observation must be keyed by ([`ReliabilityContextKey`]) and
//! the gate that refuses a confident-looking read from a sparse cohort
//! ([`SampleSupport`]/[`evaluate_sample_support`]). This module is the first
//! place that schema is actually turned into a statistic: given a set of
//! [`ReliabilityObservation`]s for one context, compute a calibrated
//! [`ReliabilitySignal`] and, given two comparable cohorts differing only in
//! `model_version`/`adapter_version`, an explicit [`DriftState`].
//!
//! # What a [`ReliabilityObservation`] is
//!
//! One adjudicated outcome for one claim, already aggregated into a cohort
//! by [`fornax_types::aggregate_context`] — "did this claim's counted
//! evidence turn out to match reality" is the outcome this module scores,
//! not the fusion verdict itself. **Nothing on the live claim path produces
//! these yet.** A future ticket wires `fornax-daemon`/an adjudication UI
//! (FORNX-105) into writing them; this ticket builds the computation that
//! consumes them and is tested against synthetic ones (see this crate's
//! tests and `fornax-bench::reliability_eval` for the honestly-labeled
//! mechanism-verification harness — no real dataset exists in this
//! repository yet).
//!
//! # Why three outcome states, not two
//!
//! An observation source can genuinely fail to resolve — evidence was
//! unavailable, or nobody looked — and that must never be laundered into
//! "unreliable" (which would make a context with poor observability look
//! untrustworthy) or "reliable" (which would hide the gap). This mirrors
//! `fornax-bench::metrics`'s three-bucket discipline exactly:
//! [`ObservationOutcome::NotEvaluable`] is excluded from both the numerator
//! and the denominator of the reliability estimate, and its count is
//! surfaced separately ([`ReliabilitySignal::not_evaluable_count`]) rather
//! than silently dropped. Critically, [`evaluate_sample_support`] is run
//! against the **evaluable** count, never the raw observation count — a
//! cohort of 30 observations of which 25 are `NotEvaluable` has 5 real data
//! points and must read `InsufficientSupport`, not `Confident`.
//!
//! # Why a numeric confidence interval, given `fusion.rs`'s explicit ban
//!
//! [`crate::fusion::FusedFinding`] carries no float/numeric confidence score
//! anywhere, and [`crate::fusion::UncertaintyBand`] "must never be rendered
//! as a percentage, compared numerically" — FORNX-93's AC was "no 'honesty
//! percentage' is shown without documented calibration semantics" for a
//! *single claim's verdict*. That ban is about an uncalibrated per-claim
//! score; it is not a ban on ever computing a rate. A cohort success rate
//! over `evaluable_count >= MINIMUM_COHORT_SAMPLE_SUPPORT` observations,
//! computed by a named estimator (Wilson score interval) with an explicit
//! interval and version, *is* the "documented calibration semantics" that
//! AC's precondition asked for. The hard boundary, enforced structurally,
//! not just by convention:
//!
//! - This number never enters a [`fornax_types::Verdict`] or an
//!   [`crate::fusion::UncertaintyBand`] — [`ReliabilitySignal`] is a
//!   distinct type on a distinct path, never merged into `FusedFinding`.
//! - There is no API in this module that takes a bare [`fornax_types::Provider`]
//!   (or any subset of context) and returns a number.
//!   [`compute_reliability`] takes a full [`ReliabilityContextKey`], which
//!   FORNX-103 already made impossible to construct from `provider` alone
//!   (see `reliability_context.rs`'s
//!   `context_key_cannot_be_constructed_from_provider_alone_via_deserialization`);
//!   this module adds nothing that could route around that gate. See this
//!   module's `reliability_signal_requires_a_full_context_key_never_provider_alone`
//!   test.
//! - Below `MINIMUM_COHORT_SAMPLE_SUPPORT`, [`ReliabilitySignal::reliability_estimate`]
//!   is `None` — never a numeric-looking guess (FORNX-104 AC 2, same
//!   discipline as FORNX-103's `SampleSupport::InsufficientSupport`).
//!
//! This is never a global "Claude = 93% trustworthy" score (the epic
//! guardrail `reliability_context.rs` names): every [`ReliabilitySignal`] is
//! scoped to one [`ReliabilityContextKey`], which pins provider, model,
//! task, toolset, repo class, policy/verifier/fusion versions, and
//! capability fingerprint all at once.
//!
//! # Out of scope for this ticket (real follow-ups, not gaps)
//!
//! - Writing real [`ReliabilityObservation`]s from the live claim path
//!   (needs an adjudication mechanism — human or automated ground truth —
//!   that does not exist yet).
//! - A UI surfacing [`ReliabilitySignal`]/[`DriftAssessment`] to a user
//!   (FORNX-105).
//! - Retention/deletion enforcement over stored reliability records
//!   (FORNX-106) — [`fornax_types::DatasetLineageTag`] already exists for a
//!   future enforcement mechanism to attach to; this module does not
//!   persist anything itself.
//!
//! # Privacy gate (FORNX-105 AC 5)
//!
//! Historical reliability aggregation is a purely local computation over
//! local observations — it is not a network egress concern, so gating it on
//! [`fornax_types::privacy::cloud_sync_allowed`] would be the wrong fit
//! (that flag controls whether data leaves the machine at all, and
//! inverting it here would mean "enable cloud sync to get local stats",
//! contradicting the local-first stance, ADR-0001 D2). Instead
//! [`ReliabilityAggregationConfig`] is a small additive `[reliability]`
//! table in `$FORNAX_HOME/config.toml`, modeled beat-for-beat on
//! [`crate::judge::SemanticJudgeConfig`] (same config file, same
//! load/from_toml_str/load_default contract, same "absent means default"
//! rule) — `historical_aggregation_enabled` defaults to `false`, so a user
//! who has never touched this config gets no historical aggregation at all
//! until they explicitly opt in.

use serde::{Deserialize, Serialize};

use fornax_types::{evaluate_sample_support, ReliabilityContextKey, SampleSupport};

/// `[reliability]` config table read from `$FORNAX_HOME/config.toml`
/// (FORNX-105 AC 5), mirroring [`crate::judge::SemanticJudgeConfig`]'s own
/// load pattern.
///
/// ```toml
/// [reliability]
/// historical_aggregation_enabled = true
/// ```
///
/// Absence of the file, absence of the `[reliability]` table, or absence of
/// the key all fall back to [`Self::default`] — `historical_aggregation_enabled:
/// false`. A user who has never touched this config gets historical
/// reliability aggregation off by default, matching this ADR's D2
/// local-first, opt-in stance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReliabilityAggregationConfig {
    pub historical_aggregation_enabled: bool,
}

/// Failure modes reading/parsing the `[reliability]` table. Mirrors
/// [`crate::judge::SemanticJudgeConfigError`]'s shape.
#[derive(Debug, thiserror::Error)]
pub enum ReliabilityConfigError {
    #[error("failed to read {path}: {source}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {path} as TOML: {source}")]
    Parse {
        path: std::path::PathBuf,
        #[source]
        source: toml_edit::TomlError,
    },
}

impl ReliabilityAggregationConfig {
    fn from_toml_str_with_path(
        contents: &str,
        path: &std::path::Path,
    ) -> Result<Self, ReliabilityConfigError> {
        let doc: toml_edit::DocumentMut =
            contents
                .parse()
                .map_err(|source| ReliabilityConfigError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;
        let default = Self::default();
        let Some(table) = doc.get("reliability") else {
            return Ok(default);
        };
        let historical_aggregation_enabled = table
            .get("historical_aggregation_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(default.historical_aggregation_enabled);
        Ok(Self {
            historical_aggregation_enabled,
        })
    }

    /// Parse an in-memory `config.toml` document (e.g. from a test).
    pub fn from_toml_str(contents: &str) -> Result<Self, ReliabilityConfigError> {
        Self::from_toml_str_with_path(contents, std::path::Path::new("<in-memory config.toml>"))
    }

    /// Read `<fornax_home>/config.toml`'s `[reliability]` table. A
    /// nonexistent file yields [`Self::default`] (disabled), not an error —
    /// same contract as [`crate::judge::SemanticJudgeConfig::load`].
    pub fn load(fornax_home: &std::path::Path) -> Result<Self, ReliabilityConfigError> {
        let path = fornax_home.join(fornax_types::sensor_config::SENSOR_CONFIG_FILE);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => return Err(ReliabilityConfigError::Io { path, source }),
        };
        Self::from_toml_str_with_path(&contents, &path)
    }

    /// [`Self::load`] against
    /// [`fornax_types::sensor_config::default_fornax_home`], collapsing any
    /// error to [`Self::default`] (disabled) — same "never fail a read over
    /// a config-file problem" contract as
    /// [`crate::judge::SemanticJudgeConfig::load_default`].
    pub fn load_default() -> Self {
        Self::load(&fornax_types::sensor_config::default_fornax_home()).unwrap_or_default()
    }
}

/// Version of this module's computation policy — bumped whenever the
/// estimator, the confidence level, or the drift-comparison rule changes in
/// a way that could change output for the same input, so a replay can pin
/// an exact version (FORNX-104 AC 4). Mirrors
/// `crate::fusion::BaselineFusionPolicy::policy_version`'s role.
pub const RELIABILITY_POLICY_VERSION: u32 = 1;

/// The z-score for a two-sided 95% confidence level, used by the Wilson
/// score interval below. Hardcoded rather than pulled from a stats crate —
/// same trade-off `fornax-bench::dataset::content_hash_of` made reusing
/// `Uuid::new_v5` instead of adding a hashing dependency for one constant.
const Z_95: f64 = 1.959963984540054;

/// The confidence level [`ConfidenceInterval::confidence_level`] reports for
/// every interval this module computes today. A named constant (not just a
/// literal `0.95` scattered at call sites) so a future change to `Z_95`
/// alone cannot silently desynchronize from the level it claims.
const CONFIDENCE_LEVEL: f64 = 0.95;

/// Whether one adjudicated claim's outcome, within its cohort, counts as
/// evidence the underlying context was reliable. See module docs, "Why
/// three outcome states, not two."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOutcome {
    /// The claim's counted evidence matched the adjudicated ground truth.
    Reliable,
    /// The claim's counted evidence did not match the adjudicated ground
    /// truth.
    Unreliable,
    /// This claim could not be adjudicated at all (evidence unavailable,
    /// nobody looked, etc.) — excluded from both the numerator and the
    /// denominator of a reliability estimate, never coerced into either of
    /// the other two states.
    NotEvaluable,
}

/// One adjudicated claim outcome, already aggregated into a cohort. See
/// module docs, "What a `ReliabilityObservation` is."
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReliabilityObservation {
    pub context_key: ReliabilityContextKey,
    pub outcome: ObservationOutcome,
}

/// A two-sided confidence interval around a point estimate. Carries its own
/// `confidence_level` rather than leaving it implicit, so a serialized
/// interval is self-describing even if [`CONFIDENCE_LEVEL`] changes in a
/// future policy version.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub lower: f64,
    pub upper: f64,
    pub confidence_level: f64,
}

/// Wilson score interval for a binomial proportion — chosen over the naive
/// normal (Wald) approximation because it stays well-behaved (bounded to
/// `[0, 1]`, sane at extreme proportions) at the sample sizes
/// [`fornax_types::MINIMUM_COHORT_SAMPLE_SUPPORT`] actually admits. `n` is
/// the evaluable count (never the raw observation count — see module
/// docs). Bounds are clamped to `[0, 1]` as a final defensive step; the
/// Wilson formula itself does not overshoot at these inputs, but the clamp
/// documents the invariant explicitly rather than relying on that.
fn wilson_score_interval(successes: u32, n: u32, z: f64) -> ConfidenceInterval {
    debug_assert!(n > 0, "wilson_score_interval requires at least one trial");
    let n_f = n as f64;
    let p_hat = successes as f64 / n_f;
    let z2 = z * z;
    let denom = 1.0 + z2 / n_f;
    let center = (p_hat + z2 / (2.0 * n_f)) / denom;
    let half = (z / denom) * (p_hat * (1.0 - p_hat) / n_f + z2 / (4.0 * n_f * n_f)).sqrt();
    ConfidenceInterval {
        lower: (center - half).clamp(0.0, 1.0),
        upper: (center + half).clamp(0.0, 1.0),
        confidence_level: CONFIDENCE_LEVEL,
    }
}

/// The calibrated point estimate for a confident cohort. Only ever present
/// inside [`ReliabilitySignal::reliability_estimate`] when
/// [`ReliabilitySignal::sample_support`] is [`SampleSupport::Confident`] —
/// see [`compute_reliability`] and this module's
/// `some_estimate_iff_confident_support` test.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ReliabilityEstimate {
    /// `successes / evaluable_count`, where `successes` is the count of
    /// [`ObservationOutcome::Reliable`] among evaluable observations.
    pub success_rate: f64,
    pub confidence_interval: ConfidenceInterval,
}

/// Output of [`compute_reliability`] — the reliability signal for one
/// [`ReliabilityContextKey`] (FORNX-104 AC 1: "reliability signal always
/// exposes sample support/context and version"). `context_key`,
/// `sample_support`, `not_evaluable_count`, and `policy_version` are always
/// populated — never optional, never something a caller has to separately
/// track. `reliability_estimate` is the only field that is genuinely absent
/// when the cohort is sparse (AC 2) — see this module's
/// `sparse_context_never_returns_a_numeric_looking_estimate` test, which
/// pins that the JSON key itself disappears rather than serializing as
/// `null`.
///
/// Deliberately does **not** duplicate `sample_count` at the top level —
/// it already lives inside `sample_support`
/// ([`SampleSupport::Confident::sample_count`] /
/// [`SampleSupport::InsufficientSupport::sample_count`]); a second copy
/// could silently disagree with the first, the exact failure
/// `fornax_types::CohortIdentity::new` was built to prevent for
/// `cohort_id`/`context_key`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReliabilitySignal {
    pub context_key: ReliabilityContextKey,
    pub sample_support: SampleSupport,
    /// Observations for this context whose outcome was
    /// [`ObservationOutcome::NotEvaluable`] — excluded from
    /// `sample_support`'s count and from `reliability_estimate`, but never
    /// silently dropped.
    pub not_evaluable_count: u32,
    pub policy_version: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub reliability_estimate: Option<ReliabilityEstimate>,
}

/// Compute a [`ReliabilitySignal`] for `context_key` from `observations`.
/// Pure — no I/O, no clock read, same inputs always produce the same output
/// (FORNX-104 AC 4). Filters `observations` to exact matches on
/// `context_key` first (an observation for a different cohort is simply
/// ignored, not an error — callers are expected to pass in whatever
/// observation store they have and let this function do the cohort split).
///
/// See module docs for why [`evaluate_sample_support`] is fed the evaluable
/// count (excluding [`ObservationOutcome::NotEvaluable`]), never the raw
/// match count.
pub fn compute_reliability(
    context_key: &ReliabilityContextKey,
    observations: &[ReliabilityObservation],
    policy_version: u32,
) -> ReliabilitySignal {
    let matching: Vec<&ReliabilityObservation> = observations
        .iter()
        .filter(|o| &o.context_key == context_key)
        .collect();

    let not_evaluable_count = matching
        .iter()
        .filter(|o| o.outcome == ObservationOutcome::NotEvaluable)
        .count() as u32;

    let evaluable: Vec<&&ReliabilityObservation> = matching
        .iter()
        .filter(|o| o.outcome != ObservationOutcome::NotEvaluable)
        .collect();
    let evaluable_count = evaluable.len() as u32;

    let sample_support = evaluate_sample_support(evaluable_count);

    let reliability_estimate = match sample_support {
        SampleSupport::Confident { sample_count } => {
            let successes = evaluable
                .iter()
                .filter(|o| o.outcome == ObservationOutcome::Reliable)
                .count() as u32;
            let success_rate = successes as f64 / sample_count as f64;
            let confidence_interval = wilson_score_interval(successes, sample_count, Z_95);
            Some(ReliabilityEstimate {
                success_rate,
                confidence_interval,
            })
        }
        SampleSupport::InsufficientSupport { .. } => None,
    };

    ReliabilitySignal {
        context_key: context_key.clone(),
        sample_support,
        not_evaluable_count,
        policy_version,
        reliability_estimate,
    }
}

/// Closed drift vocabulary (FORNX-104 AC 3). Never a bare "percentage
/// changed by X" that a caller has to interpret — a state, decided here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftState {
    /// Both cohorts have sufficient support and their confidence intervals
    /// overlap — no meaningful change detected.
    Stable,
    /// Both cohorts have sufficient support and their confidence intervals
    /// do not overlap — a meaningful reliability change between the two
    /// model/adapter versions. Deliberately conservative: non-overlapping
    /// 95% intervals is a stricter bar than a single p<0.05 test (roughly
    /// p<0.005 for two independent intervals), because a false `Drifted` on
    /// a model release is worse than a missed one at minimum support — see
    /// this module's `small_difference_at_minimum_support_reads_stable`
    /// test for the corresponding negative case.
    Drifted,
    /// At least one side lacks sufficient sample support to compute an
    /// estimate at all — comparing would borrow unjustified certainty from
    /// the side that does have data.
    InsufficientDataForComparison,
    /// The two context keys differ in a dimension other than
    /// `model_version`/`adapter_version` — not a drift comparison at all,
    /// since the cohorts are not "the same context except for the model
    /// release." Comparing them would be exactly the collapse
    /// `reliability_context.rs`'s module docs forbid (a `TestExecution`
    /// cohort is not comparable to a `Deployment` cohort just because both
    /// happen to name the same provider).
    NotComparable { differing_dimensions: Vec<String> },
}

/// Output of [`detect_drift`]: both input signals plus the decided
/// [`DriftState`], so a caller can inspect exactly what each side's
/// estimate was without recomputing it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftAssessment {
    pub baseline_signal: ReliabilitySignal,
    pub comparison_signal: ReliabilitySignal,
    pub drift_state: DriftState,
    pub policy_version: u32,
}

/// Every [`ReliabilityContextKey`] dimension that must match for two
/// cohorts to be a valid drift comparison — everything except
/// `model_version`/`adapter_version`, which are precisely the dimensions a
/// drift check exists to let vary. Returns the (stable-ordered) names of
/// dimensions that differ; empty means comparable.
fn differing_non_version_dimensions(
    a: &ReliabilityContextKey,
    b: &ReliabilityContextKey,
) -> Vec<String> {
    let mut differing = Vec::new();
    if a.schema_version != b.schema_version {
        differing.push("schema_version".to_string());
    }
    if a.provider != b.provider {
        differing.push("provider".to_string());
    }
    if a.model_family != b.model_family {
        differing.push("model_family".to_string());
    }
    if a.task_class != b.task_class {
        differing.push("task_class".to_string());
    }
    if a.toolset != b.toolset {
        differing.push("toolset".to_string());
    }
    if a.repository_class != b.repository_class {
        differing.push("repository_class".to_string());
    }
    if a.policy_version != b.policy_version {
        differing.push("policy_version".to_string());
    }
    if a.verifier_version != b.verifier_version {
        differing.push("verifier_version".to_string());
    }
    if a.fusion_version != b.fusion_version {
        differing.push("fusion_version".to_string());
    }
    if a.capability_schema_version != b.capability_schema_version {
        differing.push("capability_schema_version".to_string());
    }
    if a.capability_fingerprint != b.capability_fingerprint {
        differing.push("capability_fingerprint".to_string());
    }
    differing
}

/// Compare `baseline` against `comparison` for the same logical context,
/// differing only in `model_version`/`adapter_version` (FORNX-104 AC 3).
/// Pure — no I/O, no clock read (AC 4). See [`DriftState`] for what each
/// outcome means.
pub fn detect_drift(
    baseline_key: &ReliabilityContextKey,
    baseline_observations: &[ReliabilityObservation],
    comparison_key: &ReliabilityContextKey,
    comparison_observations: &[ReliabilityObservation],
    policy_version: u32,
) -> DriftAssessment {
    let differing = differing_non_version_dimensions(baseline_key, comparison_key);

    let baseline_signal = compute_reliability(baseline_key, baseline_observations, policy_version);
    let comparison_signal =
        compute_reliability(comparison_key, comparison_observations, policy_version);

    let drift_state = if !differing.is_empty() {
        DriftState::NotComparable {
            differing_dimensions: differing,
        }
    } else {
        match (
            &baseline_signal.reliability_estimate,
            &comparison_signal.reliability_estimate,
        ) {
            (Some(b), Some(c)) => {
                let overlap = b.confidence_interval.lower <= c.confidence_interval.upper
                    && c.confidence_interval.lower <= b.confidence_interval.upper;
                if overlap {
                    DriftState::Stable
                } else {
                    DriftState::Drifted
                }
            }
            _ => DriftState::InsufficientDataForComparison,
        }
    };

    DriftAssessment {
        baseline_signal,
        comparison_signal,
        drift_state,
        policy_version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fornax_types::{
        aggregate_context, CapabilitySignal, ModelFamily, RawReliabilityContext,
        RawRepositoryContext, RepositoryClass, RuntimeCapabilities, SignalAvailability,
        SignalClass, TaskClass, ToolClass, MINIMUM_COHORT_SAMPLE_SUPPORT,
    };
    use std::collections::HashMap;

    fn caps() -> RuntimeCapabilities {
        RuntimeCapabilities {
            schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
            provider: fornax_types::Provider::ClaudeCode,
            signals: vec![CapabilitySignal {
                class: SignalClass::ToolTrace,
                state: SignalAvailability::Available,
                detail: None,
            }],
            notes: HashMap::new(),
        }
    }

    fn key_with(model_version: &str) -> ReliabilityContextKey {
        aggregate_context(RawReliabilityContext {
            provider: fornax_types::Provider::ClaudeCode,
            model_family: ModelFamily::Claude,
            model_version: model_version.to_string(),
            adapter_version: "0.0.4".to_string(),
            task_class: TaskClass::TestExecution,
            toolset: vec![ToolClass::Shell, ToolClass::FileEdit],
            repository: RawRepositoryContext {
                identifying_hint: None,
                class: RepositoryClass::PublicOss,
            },
            policy_version: "policy-v3".to_string(),
            verifier_version: "verifier-v2".to_string(),
            fusion_version: "fusion-v1".to_string(),
            capabilities: caps(),
        })
    }

    fn key() -> ReliabilityContextKey {
        key_with("claude-sonnet-5")
    }

    fn key_with_task_class(task_class: TaskClass) -> ReliabilityContextKey {
        aggregate_context(RawReliabilityContext {
            provider: fornax_types::Provider::ClaudeCode,
            model_family: ModelFamily::Claude,
            model_version: "claude-sonnet-5".to_string(),
            adapter_version: "0.0.4".to_string(),
            task_class,
            toolset: vec![ToolClass::Shell, ToolClass::FileEdit],
            repository: RawRepositoryContext {
                identifying_hint: None,
                class: RepositoryClass::PublicOss,
            },
            policy_version: "policy-v3".to_string(),
            verifier_version: "verifier-v2".to_string(),
            fusion_version: "fusion-v1".to_string(),
            capabilities: caps(),
        })
    }

    fn observations(
        key: &ReliabilityContextKey,
        outcomes: &[ObservationOutcome],
    ) -> Vec<ReliabilityObservation> {
        outcomes
            .iter()
            .map(|o| ReliabilityObservation {
                context_key: key.clone(),
                outcome: *o,
            })
            .collect()
    }

    fn all_reliable(key: &ReliabilityContextKey, n: usize) -> Vec<ReliabilityObservation> {
        observations(key, &vec![ObservationOutcome::Reliable; n])
    }

    fn n_reliable_of(
        key: &ReliabilityContextKey,
        reliable: usize,
        total: usize,
    ) -> Vec<ReliabilityObservation> {
        let mut outcomes = vec![ObservationOutcome::Reliable; reliable];
        outcomes.extend(vec![ObservationOutcome::Unreliable; total - reliable]);
        observations(key, &outcomes)
    }

    // --- AC 2: sparse context never returns a numeric-looking estimate ---

    #[test]
    fn sparse_context_never_returns_a_numeric_looking_estimate_even_when_consistent() {
        let k = key();
        // All identical/consistent observations, but below threshold -- must
        // not let "the data happens to agree" override the sample-size gate.
        let obs = all_reliable(&k, (MINIMUM_COHORT_SAMPLE_SUPPORT - 1) as usize);
        let signal = compute_reliability(&k, &obs, RELIABILITY_POLICY_VERSION);

        assert!(matches!(
            signal.sample_support,
            SampleSupport::InsufficientSupport { .. }
        ));
        assert!(signal.reliability_estimate.is_none());

        let json = serde_json::to_value(&signal).unwrap();
        assert!(json.get("reliability_estimate").is_none());
    }

    #[test]
    fn at_or_above_threshold_produces_an_estimate() {
        let k = key();
        let obs = all_reliable(&k, MINIMUM_COHORT_SAMPLE_SUPPORT as usize);
        let signal = compute_reliability(&k, &obs, RELIABILITY_POLICY_VERSION);
        assert!(matches!(
            signal.sample_support,
            SampleSupport::Confident { .. }
        ));
        assert!(signal.reliability_estimate.is_some());
    }

    #[test]
    fn some_estimate_iff_confident_support() {
        let k = key();
        for n in 0..=(MINIMUM_COHORT_SAMPLE_SUPPORT * 2) {
            let obs = all_reliable(&k, n as usize);
            let signal = compute_reliability(&k, &obs, RELIABILITY_POLICY_VERSION);
            let confident = matches!(signal.sample_support, SampleSupport::Confident { .. });
            assert_eq!(
                signal.reliability_estimate.is_some(),
                confident,
                "n={n}: estimate presence must exactly track Confident support"
            );
        }
    }

    // --- NotEvaluable is excluded from both numerator and denominator ----

    #[test]
    fn not_evaluable_observations_never_inflate_sample_support() {
        let k = key();
        // 25 NotEvaluable + 5 Reliable: only 5 real data points, must read
        // InsufficientSupport even though the raw count is 30.
        let mut outcomes = vec![ObservationOutcome::NotEvaluable; 25];
        outcomes.extend(vec![ObservationOutcome::Reliable; 5]);
        let obs = observations(&k, &outcomes);
        let signal = compute_reliability(&k, &obs, RELIABILITY_POLICY_VERSION);

        assert_eq!(signal.not_evaluable_count, 25);
        match signal.sample_support {
            SampleSupport::InsufficientSupport {
                sample_count,
                minimum_required,
            } => {
                assert_eq!(sample_count, 5);
                assert_eq!(minimum_required, MINIMUM_COHORT_SAMPLE_SUPPORT);
            }
            SampleSupport::Confident { .. } => {
                panic!("25 NotEvaluable + 5 Reliable must not read Confident")
            }
        }
        assert!(signal.reliability_estimate.is_none());
    }

    #[test]
    fn not_evaluable_observations_never_count_as_unreliable() {
        let k = key();
        let mut outcomes =
            vec![ObservationOutcome::Reliable; MINIMUM_COHORT_SAMPLE_SUPPORT as usize];
        outcomes.push(ObservationOutcome::NotEvaluable);
        let obs = observations(&k, &outcomes);
        let signal = compute_reliability(&k, &obs, RELIABILITY_POLICY_VERSION);

        assert_eq!(signal.not_evaluable_count, 1);
        let estimate = signal.reliability_estimate.expect("should be confident");
        assert_eq!(
            estimate.success_rate, 1.0,
            "the NotEvaluable record must not drag down the rate"
        );
    }

    // --- AC 1: signal always carries context/sample-count/version --------

    #[test]
    fn signal_always_carries_context_support_and_version_regardless_of_confidence() {
        let k = key();
        let sparse = compute_reliability(&k, &[], RELIABILITY_POLICY_VERSION);
        assert_eq!(sparse.context_key, k);
        assert_eq!(sparse.policy_version, RELIABILITY_POLICY_VERSION);
        assert!(matches!(
            sparse.sample_support,
            SampleSupport::InsufficientSupport { .. }
        ));

        let obs = all_reliable(&k, MINIMUM_COHORT_SAMPLE_SUPPORT as usize);
        let confident = compute_reliability(&k, &obs, RELIABILITY_POLICY_VERSION);
        assert_eq!(confident.context_key, k);
        assert_eq!(confident.policy_version, RELIABILITY_POLICY_VERSION);
        assert!(matches!(
            confident.sample_support,
            SampleSupport::Confident { .. }
        ));
    }

    #[test]
    fn reliability_signal_requires_a_full_context_key_never_provider_alone() {
        // compute_reliability's signature itself makes this structurally
        // true: it takes a &ReliabilityContextKey, which (per FORNX-103) can
        // only be constructed via aggregate_context supplying every
        // dimension. There is no code path in this module that accepts a
        // bare Provider (or any strict subset of the context) and returns a
        // number.
        let k = key();
        assert_eq!(
            k.schema_version,
            fornax_types::RELIABILITY_CONTEXT_SCHEMA_VERSION
        );
        // Sanity: the key really does carry every dimension, not just
        // provider.
        assert_eq!(k.provider, fornax_types::Provider::ClaudeCode);
        assert_eq!(k.model_family, ModelFamily::Claude);
        assert_eq!(k.task_class, TaskClass::TestExecution);
    }

    // --- Observations for an unrelated context are ignored ----------------

    #[test]
    fn observations_for_a_different_context_are_ignored() {
        let k = key();
        let other = key_with("claude-sonnet-4");
        let mut obs = all_reliable(&k, MINIMUM_COHORT_SAMPLE_SUPPORT as usize);
        obs.extend(all_reliable(&other, MINIMUM_COHORT_SAMPLE_SUPPORT as usize));

        let signal = compute_reliability(&other, &obs, RELIABILITY_POLICY_VERSION);
        match signal.sample_support {
            SampleSupport::Confident { sample_count } => {
                assert_eq!(sample_count, MINIMUM_COHORT_SAMPLE_SUPPORT)
            }
            SampleSupport::InsufficientSupport { .. } => panic!("expected confident"),
        }
    }

    // --- AC 4: reproducibility ---------------------------------------------

    #[test]
    fn compute_reliability_is_deterministic_across_shuffled_observation_order() {
        let k = key();
        let obs_forward = n_reliable_of(&k, 21, 40);
        let mut obs_backward = obs_forward.clone();
        obs_backward.reverse();

        let out_forward = compute_reliability(&k, &obs_forward, RELIABILITY_POLICY_VERSION);
        let out_backward = compute_reliability(&k, &obs_backward, RELIABILITY_POLICY_VERSION);
        assert_eq!(out_forward, out_backward);

        // Calling twice on the identical input is also byte-identical.
        let out_forward_again = compute_reliability(&k, &obs_forward, RELIABILITY_POLICY_VERSION);
        assert_eq!(out_forward, out_forward_again);
    }

    #[test]
    fn frozen_input_round_trips_through_json_to_an_identical_recomputation() {
        let k = key();
        let obs = n_reliable_of(&k, 25, 40);
        let signal = compute_reliability(&k, &obs, RELIABILITY_POLICY_VERSION);

        let obs_json = serde_json::to_string(&obs).unwrap();
        let obs_back: Vec<ReliabilityObservation> = serde_json::from_str(&obs_json).unwrap();
        let signal_again = compute_reliability(&k, &obs_back, RELIABILITY_POLICY_VERSION);

        assert_eq!(
            serde_json::to_string(&signal).unwrap(),
            serde_json::to_string(&signal_again).unwrap()
        );
    }

    // --- AC 3: drift detection ----------------------------------------------

    #[test]
    fn large_reliability_change_between_model_versions_reads_drifted() {
        let baseline_key = key_with("claude-sonnet-4");
        let comparison_key = key_with("claude-sonnet-5");
        let baseline_obs = n_reliable_of(&baseline_key, 30, 30);
        let comparison_obs = n_reliable_of(&comparison_key, 15, 30);

        let assessment = detect_drift(
            &baseline_key,
            &baseline_obs,
            &comparison_key,
            &comparison_obs,
            RELIABILITY_POLICY_VERSION,
        );
        assert_eq!(assessment.drift_state, DriftState::Drifted);
    }

    #[test]
    fn small_difference_at_minimum_support_reads_stable() {
        let baseline_key = key_with("claude-sonnet-4");
        let comparison_key = key_with("claude-sonnet-5");
        let baseline_obs = n_reliable_of(&baseline_key, 30, 30);
        let comparison_obs = n_reliable_of(&comparison_key, 27, 30);

        let assessment = detect_drift(
            &baseline_key,
            &baseline_obs,
            &comparison_key,
            &comparison_obs,
            RELIABILITY_POLICY_VERSION,
        );
        assert_eq!(
            assessment.drift_state,
            DriftState::Stable,
            "a small difference at minimum support must not be blended into a false Drifted"
        );
    }

    #[test]
    fn drift_between_sparse_cohorts_is_insufficient_data_never_a_guess() {
        let baseline_key = key_with("claude-sonnet-4");
        let comparison_key = key_with("claude-sonnet-5");
        let baseline_obs = n_reliable_of(&baseline_key, 5, 5);
        let comparison_obs = n_reliable_of(&comparison_key, 1, 5);

        let assessment = detect_drift(
            &baseline_key,
            &baseline_obs,
            &comparison_key,
            &comparison_obs,
            RELIABILITY_POLICY_VERSION,
        );
        assert_eq!(
            assessment.drift_state,
            DriftState::InsufficientDataForComparison
        );
    }

    #[test]
    fn drift_across_non_comparable_cohorts_is_refused_not_silently_computed() {
        let baseline_key = key_with_task_class(TaskClass::TestExecution);
        let comparison_key = key_with_task_class(TaskClass::Deployment);
        let baseline_obs = n_reliable_of(&baseline_key, 30, 30);
        let comparison_obs = n_reliable_of(&comparison_key, 10, 30);

        let assessment = detect_drift(
            &baseline_key,
            &baseline_obs,
            &comparison_key,
            &comparison_obs,
            RELIABILITY_POLICY_VERSION,
        );
        match assessment.drift_state {
            DriftState::NotComparable {
                differing_dimensions,
            } => {
                assert!(differing_dimensions.contains(&"task_class".to_string()));
            }
            other => panic!("expected NotComparable, got {other:?}"),
        }
    }

    #[test]
    fn drift_comparison_tolerates_model_and_adapter_version_differing_only() {
        // Same context in every dimension except model_version -- the
        // exact shape a real drift check runs against. Confirms the
        // comparability gate does not itself misfire on the one difference
        // it exists to permit.
        let baseline_key = key_with("claude-sonnet-4");
        let comparison_key = key_with("claude-sonnet-5");
        assert!(differing_non_version_dimensions(&baseline_key, &comparison_key).is_empty());
    }

    // --- AC 5: privacy/opt-in gate for historical aggregation --------------

    #[test]
    fn reliability_aggregation_defaults_disabled_when_config_absent() {
        assert_eq!(
            ReliabilityAggregationConfig::default(),
            ReliabilityAggregationConfig {
                historical_aggregation_enabled: false,
            }
        );
        // No file at all, and no [reliability] table, and no key -- all
        // three "absence" shapes must yield the same disabled default.
        assert!(
            !ReliabilityAggregationConfig::from_toml_str("")
                .unwrap()
                .historical_aggregation_enabled
        );
        assert!(
            !ReliabilityAggregationConfig::from_toml_str("[other_table]\nx = 1\n")
                .unwrap()
                .historical_aggregation_enabled
        );
        assert!(
            !ReliabilityAggregationConfig::from_toml_str("[reliability]\n")
                .unwrap()
                .historical_aggregation_enabled
        );
    }

    #[test]
    fn reliability_aggregation_can_be_explicitly_enabled() {
        let cfg = ReliabilityAggregationConfig::from_toml_str(
            "[reliability]\nhistorical_aggregation_enabled = true\n",
        )
        .unwrap();
        assert!(cfg.historical_aggregation_enabled);
    }

    #[test]
    fn reliability_aggregation_load_nonexistent_home_yields_disabled_default_not_error() {
        let dir = std::env::temp_dir().join(format!(
            "fornax-reliability-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        // Deliberately do not create `dir` -- config.toml under it does not exist.
        let cfg = ReliabilityAggregationConfig::load(&dir).unwrap();
        assert!(!cfg.historical_aggregation_enabled);
    }

    #[test]
    fn reliability_aggregation_load_reads_an_explicit_config_file() {
        let dir = std::env::temp_dir().join(format!(
            "fornax-reliability-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(fornax_types::sensor_config::SENSOR_CONFIG_FILE),
            "[reliability]\nhistorical_aggregation_enabled = true\n",
        )
        .unwrap();
        let cfg = ReliabilityAggregationConfig::load(&dir).unwrap();
        assert!(cfg.historical_aggregation_enabled);
        std::fs::remove_dir_all(&dir).ok();
    }
}
