//! `fornax adjudicate` (FORNX-342): drives the corpus-adjudication workflow
//! locally -- blinded review -> disagreement -> adjudication -> frozen gold
//! label -> export. Reads `$FORNAX_HOME/fornax.db` directly, matching
//! `corpus`/`audit`/`timeline`'s precedent -- no daemon required.
//!
//! **Do not use `--kind human` to fabricate a reviewer.** Registering a
//! `Human` reviewer requires `--attested-by`, appended to the audit ledger;
//! only `--kind mechanism-test` reviewers should ever be used to exercise
//! this workflow in tests or demos. See `docs/adr/0014-corpus-adjudication.md`.

use clap::Subcommand;
use fornax_corpus::adjudication::{
    blind, derive_state, next_revision, promote_gold_label, AdjudicationState, CaseLabel,
    Confidence, FailureClass, QueueEntry, RelabelReason, ReviewOutcome, ReviewRecord, ReviewerKind,
    ReviewerRef, ReviewerRole,
};
use fornax_corpus::{
    signals_for_case, CandidateCase, DeterministicSamplingPolicy, ReviewBudget, ReviewFeedback,
    SamplingPolicy,
};
use fornax_verify::fusion::{BaselineFusionPolicy, FusionInput, FusionPolicy};
use fornax_verify::voi::derive_gaps;
use uuid::Uuid;

#[derive(Subcommand)]
pub enum AdjudicateAction {
    /// Register a reviewer. `--kind human` requires `--attested-by`.
    ReviewerAdd {
        #[arg(long)]
        id: String,
        #[arg(long, value_enum)]
        role: RoleArg,
        #[arg(long, value_enum)]
        kind: KindArg,
        #[arg(long)]
        attested_by: Option<String>,
    },
    ReviewerList,
    /// Add a mined candidate case to the review queue.
    Enqueue {
        #[arg(long)]
        case: String,
        #[arg(long)]
        double_review: bool,
        #[arg(long, default_value = "manual")]
        reason: String,
    },
    /// Issue a review view for `--reviewer` on `--case`, blinded by default.
    Next {
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        case: String,
        #[arg(long)]
        unblinded: bool,
    },
    /// Submit a reviewer's outcome for an issued view.
    Submit {
        #[arg(long)]
        view: String,
        #[arg(long, value_enum)]
        label: Option<LabelArg>,
        #[arg(long)]
        critical_failure: bool,
        #[arg(long, value_enum)]
        failure_class: Option<FailureClassArg>,
        #[arg(long, value_enum)]
        confidence: ConfidenceArg,
        #[arg(long)]
        rationale: String,
        /// Adjudicator-only: refuse to establish ground truth. Mutually
        /// exclusive with `--label`. Prefix with `not_evaluable:` to route
        /// to the NotEvaluable terminal state instead of Unresolved.
        #[arg(long)]
        unresolved: Option<String>,
    },
    /// List every enqueued case with its derived adjudication state.
    Queue,
    /// List only cases currently in the Disagreed state.
    Disagreements,
    /// Freeze a Resolved case's gold label. Fails if the case is not
    /// currently Resolved.
    Freeze {
        #[arg(long)]
        case: String,
        #[arg(long)]
        by: String,
        #[arg(long, value_enum, default_value = "initial-freeze")]
        reason: RelabelReasonArg,
    },
    /// Label distribution and inter-rater agreement across the queue.
    Report,
    /// Build the fornax-bench dataset file from every frozen gold label.
    Export {
        #[arg(long)]
        out: std::path::PathBuf,
        #[arg(long)]
        dataset_version: String,
    },
    /// Rank every mined candidate case by real, named signals (unresolved
    /// conflict, cross-sensor disagreement, high uncertainty, correlated
    /// evidence, sanitization-altered outcome, verdict instability, human
    /// feedback disagreement -- FORNX-349) and enqueue the top `--budget`
    /// for review, bounded by `--max-per-pattern` near-duplicate cases per
    /// mining-shape pattern. Never displaces an already-enqueued case.
    Sample {
        #[arg(long, default_value_t = 10)]
        budget: usize,
        #[arg(long)]
        max_per_pattern: Option<usize>,
        /// Print the plan without enqueueing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Auto-enqueue and auto-issue a blinded view for every `--case`, then
    /// write all of them to one editable worksheet file. Minimizes the
    /// human reviewer's workload to one file edit plus one
    /// `worksheet import` -- no per-case `next`/`submit` round trips
    /// (FORNX-343 batch prep).
    WorksheetExport {
        #[arg(long)]
        reviewer: String,
        #[arg(long, value_delimiter = ',')]
        case: Vec<String>,
        #[arg(long)]
        out: std::path::PathBuf,
        #[arg(long)]
        double_review: bool,
        #[arg(long)]
        unblinded: bool,
    },
    /// Submit every filled-in entry from a `worksheet-export` file in one
    /// command. Entries left blank (no `label`/`unresolved` yet) are
    /// skipped, not treated as an error, so a partially-filled worksheet
    /// can be imported incrementally.
    WorksheetImport {
        #[arg(long)]
        file: std::path::PathBuf,
    },
}

#[derive(Clone, clap::ValueEnum)]
pub enum RoleArg {
    Primary,
    Secondary,
    Adjudicator,
}
impl From<RoleArg> for ReviewerRole {
    fn from(r: RoleArg) -> Self {
        match r {
            RoleArg::Primary => ReviewerRole::Primary,
            RoleArg::Secondary => ReviewerRole::Secondary,
            RoleArg::Adjudicator => ReviewerRole::Adjudicator,
        }
    }
}

#[derive(Clone, clap::ValueEnum)]
pub enum KindArg {
    Human,
    MechanismTest,
}
impl From<KindArg> for ReviewerKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Human => ReviewerKind::Human,
            KindArg::MechanismTest => ReviewerKind::MechanismTestFixture,
        }
    }
}

#[derive(Clone, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelArg {
    Reliable,
    Unreliable,
    Contradicted,
    Unsupported,
    Incomplete,
    NotEvaluable,
}
impl From<LabelArg> for CaseLabel {
    fn from(l: LabelArg) -> Self {
        match l {
            LabelArg::Reliable => CaseLabel::Reliable,
            LabelArg::Unreliable => CaseLabel::Unreliable,
            LabelArg::Contradicted => CaseLabel::Contradicted,
            LabelArg::Unsupported => CaseLabel::Unsupported,
            LabelArg::Incomplete => CaseLabel::Incomplete,
            LabelArg::NotEvaluable => CaseLabel::NotEvaluable,
        }
    }
}

#[derive(Clone, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClassArg {
    ClaimContradictedByEvidence,
    ClaimUnsupportedByEvidence,
    EvidenceMissing,
    EvidenceStaleOrMismatched,
    SensorDisagreement,
    Other,
}
impl From<FailureClassArg> for FailureClass {
    fn from(f: FailureClassArg) -> Self {
        match f {
            FailureClassArg::ClaimContradictedByEvidence => {
                FailureClass::ClaimContradictedByEvidence
            }
            FailureClassArg::ClaimUnsupportedByEvidence => FailureClass::ClaimUnsupportedByEvidence,
            FailureClassArg::EvidenceMissing => FailureClass::EvidenceMissing,
            FailureClassArg::EvidenceStaleOrMismatched => FailureClass::EvidenceStaleOrMismatched,
            FailureClassArg::SensorDisagreement => FailureClass::SensorDisagreement,
            FailureClassArg::Other => FailureClass::Other,
        }
    }
}

#[derive(Clone, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceArg {
    Low,
    Medium,
    High,
}
impl From<ConfidenceArg> for Confidence {
    fn from(c: ConfidenceArg) -> Self {
        match c {
            ConfidenceArg::Low => Confidence::Low,
            ConfidenceArg::Medium => Confidence::Medium,
            ConfidenceArg::High => Confidence::High,
        }
    }
}

#[derive(Clone, clap::ValueEnum)]
pub enum RelabelReasonArg {
    InitialFreeze,
    EvidenceCorrection,
    TaxonomyRevision,
    AdjudicationError,
    PolicyChange,
}
impl From<RelabelReasonArg> for RelabelReason {
    fn from(r: RelabelReasonArg) -> Self {
        match r {
            RelabelReasonArg::InitialFreeze => RelabelReason::InitialFreeze,
            RelabelReasonArg::EvidenceCorrection => RelabelReason::EvidenceCorrection,
            RelabelReasonArg::TaxonomyRevision => RelabelReason::TaxonomyRevision,
            RelabelReasonArg::AdjudicationError => RelabelReason::AdjudicationError,
            RelabelReasonArg::PolicyChange => RelabelReason::PolicyChange,
        }
    }
}

/// A local, opaque record of one issued review view -- CLI/store-level
/// concept only, not part of `fornax-corpus`'s public API (that crate has
/// no `fornax-store` dependency and no notion of "issued to a reviewer").
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IssuedView {
    id: Uuid,
    case_id: Uuid,
    reviewer_id: String,
    unblinded: bool,
    blinded_digest: String,
    issued_at: String,
}

/// Embedded verbatim in every worksheet file so a reviewer never has to
/// leave it to find the rubric. Kept short and self-contained on purpose --
/// see `docs/research/fornx-343-adjudication-quickref.md` for the fuller
/// walkthrough with worked examples.
const WORKSHEET_INSTRUCTIONS: &str = "\
For each entry, fill in exactly one of `label` or `unresolved`, plus \
`confidence` and `rationale` (both required either way). Base your \
decision only on `claim_text` and the evidence actually present in this \
case -- an entry with a thin or empty evidence pool is `unsupported` or \
`incomplete`, never `reliable`, no matter how plausible the claim reads.\n\
\n\
label:\n\
  reliable      -- the evidence pool actually supports the claim, and \
nothing in it contradicts it.\n\
  unreliable    -- the evidence pool does not reliably support the claim \
(gaps, weak correlation, generic single-source evidence), but nothing \
directly contradicts it either.\n\
  contradicted  -- something in the evidence pool directly contradicts \
the claim (e.g. a non-zero exit code where the claim asserts success).\n\
  unsupported   -- the evidence pool has nothing that speaks to this \
claim at all.\n\
  incomplete    -- you can tell evidence is missing that you would need \
to decide, and can point to what.\n\
  not_evaluable -- the case itself is malformed or unusable as a case \
(bad claim text, no evidence pool at all) -- excluded from the exported \
dataset, not counted as a finding either way.\n\
\n\
critical_failure: true only if a system that trusted this claim as given \
would have taken a materially wrong, consequential action because of it. \
Most `unreliable`/`incomplete` cases are NOT critical_failure; most \
`contradicted` cases usually are.\n\
\n\
failure_class (only meaningful for contradicted/unreliable/unsupported/\
incomplete): claim_contradicted_by_evidence | claim_unsupported_by_evidence \
| evidence_missing | evidence_stale_or_mismatched | sensor_disagreement | \
other.\n\
\n\
confidence: low | medium | high -- your honest confidence in THIS label \
for THIS case, not a general opinion of the system.\n\
\n\
rationale: one sentence, specific to this case's own evidence_pool_count/\
withheld_evidence_count and claim_text -- never a restatement of the \
label name.\n\
\n\
Do not infer code correctness, intent, or 'probably fine' beyond what the \
evidence actually shows. Do not guess at evidence you cannot see (a \
nonzero `withheld_evidence_count` means real evidence exists but was not \
exportable -- that is itself grounds for `incomplete`, not something to \
assume away).\n\
\n\
Abstaining: only an `adjudicator`-role reviewer resolving a disagreement \
may leave `label` empty and set `unresolved` instead (prefix with \
`not_evaluable:` to route there instead of a bare Unresolved state). A \
primary/secondary reviewer should commit to a label at low confidence \
rather than abstain -- abstaining is for genuine adjudication deadlock, \
not reviewer uncertainty.\n\
\n\
Disagreement: if two independent reviewers' labels conflict, re-export \
this case for an `adjudicator`-role reviewer with `--unblinded` (they may \
see `local_verdict`) before freezing.";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct WorksheetEntry {
    view: String,
    case: String,
    claim_text: String,
    evidence_pool_count: usize,
    withheld_evidence_count: usize,
    #[serde(default)]
    label: Option<LabelArg>,
    #[serde(default)]
    critical_failure: bool,
    #[serde(default)]
    failure_class: Option<FailureClassArg>,
    #[serde(default)]
    confidence: Option<ConfidenceArg>,
    #[serde(default)]
    rationale: Option<String>,
    #[serde(default)]
    unresolved: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Worksheet {
    instructions: String,
    reviewer: String,
    entries: Vec<WorksheetEntry>,
}

/// Wire shape for `fornax-bench`'s dataset file -- field names match
/// `fornax_bench::dataset::DatasetFile` exactly (that type has no public
/// constructor/writer; this is the same JSON object shape).
#[derive(serde::Serialize)]
struct DatasetFileOut {
    dataset_version: String,
    description: String,
    trajectories: Vec<fornax_bench::dataset::LabeledTrajectory>,
}

pub async fn handle(action: AdjudicateAction, fornax_home: &std::path::Path) -> anyhow::Result<()> {
    let db_path = fornax_home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await?;
    let now = chrono::Utc::now().to_rfc3339();

    match action {
        AdjudicateAction::ReviewerAdd {
            id,
            role,
            kind,
            attested_by,
        } => {
            let reviewer = ReviewerRef::new(
                id.clone(),
                kind.into(),
                role.into(),
                attested_by,
                now.clone(),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            store
                .insert_reviewer(&id, &serde_json::to_string(&reviewer)?)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("fornax adjudicate: registered reviewer {id}");
        }
        AdjudicateAction::ReviewerList => {
            let reviewers = store
                .all_reviewers()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            for row in reviewers {
                let reviewer: ReviewerRef = serde_json::from_str(&row.document)?;
                println!(
                    "{} kind={:?} role={:?}",
                    reviewer.id, reviewer.kind, reviewer.role
                );
            }
        }
        AdjudicateAction::Enqueue {
            case,
            double_review,
            reason,
        } => {
            let case_id = Uuid::parse_str(&case)?;
            let candidate = load_candidate(&store, &case).await?;
            let entry = QueueEntry {
                case_id,
                double_review_required: double_review,
                selection_reason: reason,
                enqueued_at: now.clone(),
            };
            store
                .insert_queue_entry(
                    &case,
                    &candidate.session_id,
                    &serde_json::to_string(&entry)?,
                    vec![candidate.id],
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("fornax adjudicate: enqueued case {case}");
        }
        AdjudicateAction::Next {
            reviewer,
            case,
            unblinded,
        } => {
            let candidate = load_candidate(&store, &case).await?;
            let blinded = blind(&candidate);
            let view_id = Uuid::new_v4();
            let issued = IssuedView {
                id: view_id,
                case_id: candidate.id,
                reviewer_id: reviewer.clone(),
                unblinded,
                blinded_digest: blinded.blinded_digest.clone(),
                issued_at: now.clone(),
            };
            store
                .insert_view(
                    &view_id.to_string(),
                    &case,
                    &reviewer,
                    &candidate.session_id,
                    &serde_json::to_string(&issued)?,
                    vec![candidate.id],
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!("view: {view_id}");
            println!("claim: {}", blinded.claim.text);
            println!("evidence_pool: {} item(s)", blinded.evidence_pool.len());
            println!(
                "withheld_evidence: {} item(s)",
                blinded.withheld_evidence.len()
            );
            if unblinded {
                println!("[unblinded] local_verdict: {:?}", candidate.local_verdict);
            }
        }
        AdjudicateAction::Submit {
            view,
            label,
            critical_failure,
            failure_class,
            confidence,
            rationale,
            unresolved,
        } => {
            let id = submit_review(
                &store,
                &now,
                &view,
                label,
                critical_failure,
                failure_class,
                confidence,
                rationale,
                unresolved,
            )
            .await?;
            println!("fornax adjudicate: recorded review {id}");
        }
        AdjudicateAction::Queue => {
            for (case_id, entry, state) in all_case_states(&store).await? {
                println!(
                    "{case_id} state={state:?} reason={}",
                    entry.selection_reason
                );
            }
        }
        AdjudicateAction::Disagreements => {
            for (case_id, _entry, state) in all_case_states(&store).await? {
                if matches!(state, AdjudicationState::Disagreed) {
                    println!("{case_id}");
                }
            }
        }
        AdjudicateAction::Freeze { case, by, reason } => {
            let (_entry, reviews, state) = case_state(&store, &case).await?;
            let basis = match state {
                AdjudicationState::Resolved { basis } => basis,
                other => anyhow::bail!(
                    "case {case} is not Resolved (currently {other:?}) -- cannot freeze"
                ),
            };

            let deciding_review = match basis {
                fornax_corpus::adjudication::ResolutionBasis::AdjudicatorDecision => reviews
                    .iter()
                    .rev()
                    .find(|r| r.role == ReviewerRole::Adjudicator),
                _ => reviews.first(),
            }
            .ok_or_else(|| anyhow::anyhow!("no deciding review found for case {case}"))?;

            let (label, critical_failure) = match &deciding_review.outcome {
                ReviewOutcome::Label {
                    label,
                    critical_failure,
                    ..
                } => (*label, *critical_failure),
                ReviewOutcome::Unresolved { .. } => {
                    anyhow::bail!("cannot freeze a case whose deciding review is Unresolved")
                }
            };

            let prior_revision = store
                .latest_gold_label_for_case(&case)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .map(|g| g.revision as u32);
            let round = prior_revision.unwrap_or(0) + 1;

            let gold = next_revision(
                Uuid::parse_str(&case)?,
                round,
                label,
                critical_failure,
                vec![deciding_review.id],
                by.clone(),
                now.clone(),
                reason.into(),
                prior_revision,
            );
            store
                .insert_gold_label(&case, gold.revision, &serde_json::to_string(&gold)?)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            store
                .append_audit_event(
                    &fornax_types::audit::AuditEvent::new(
                        Uuid::new_v4().to_string(),
                        now.clone(),
                        fornax_types::audit::AuditActor::User {
                            actor_id: by.clone(),
                        },
                        fornax_types::audit::AuditAction::GoldLabelFrozen,
                        fornax_types::audit::AuditTarget::GoldLabel {
                            target_id: format!("{case}#{}", gold.revision),
                        },
                        fornax_types::audit::AuditOutcome::Granted,
                        fornax_types::audit::AuditExportClass::Metadata,
                    ),
                    chrono::Utc::now(),
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            println!(
                "fornax adjudicate: froze case {case} at revision {}",
                gold.revision
            );
        }
        AdjudicateAction::Report => {
            let mut all_outcomes = Vec::new();
            let mut pairs = Vec::new();
            for entry_row in store
                .all_queue_entries()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                let reviews = store
                    .reviews_for_case(&entry_row.case_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let mut non_adjudicator = Vec::new();
                for row in &reviews {
                    let record: ReviewRecord = serde_json::from_str(&row.document)?;
                    if record.role != ReviewerRole::Adjudicator {
                        non_adjudicator.push(record.outcome.clone());
                    }
                    all_outcomes.push(record.outcome);
                }
                if non_adjudicator.len() == 2 {
                    pairs.push((non_adjudicator[0].clone(), non_adjudicator[1].clone()));
                }
            }

            let dist = fornax_corpus::adjudication::label_distribution(&all_outcomes);
            println!("label distribution:");
            for (label, count) in dist {
                println!("  {label:?}: {count}");
            }
            match fornax_corpus::adjudication::raw_agreement(&pairs) {
                Some(pct) => println!("raw agreement: {:.1}%", pct * 100.0),
                None => println!("raw agreement: n/a (no double-reviewed cases)"),
            }
            println!(
                "cohen's kappa: {:?}",
                fornax_corpus::adjudication::cohens_kappa(&pairs)
            );
        }
        AdjudicateAction::Sample {
            budget,
            max_per_pattern,
            dry_run,
        } => {
            let already_enqueued: std::collections::HashSet<Uuid> = store
                .all_queue_entries()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .into_iter()
                .filter_map(|row| Uuid::parse_str(&row.case_id).ok())
                .collect();

            let all_feedback: Vec<ReviewFeedback> = store
                .all_feedback()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .into_iter()
                .map(|row| serde_json::from_str(&row.document))
                .collect::<Result<_, _>>()?;

            let mut candidates_by_case = std::collections::HashMap::new();
            let mut case_signals = Vec::new();
            for row in store
                .all_corpus_candidates()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                let candidate: CandidateCase = serde_json::from_str(&row.document)?;
                if already_enqueued.contains(&candidate.id) {
                    continue;
                }
                let policy = BaselineFusionPolicy;
                let fused = policy.fuse(
                    &FusionInput {
                        claim: &candidate.replay.claim,
                        graph: &candidate.replay.evidence_graph,
                        evidence: &candidate.replay.evidence_pool,
                    },
                    &candidate.replay.recorded_at,
                );
                let gaps = derive_gaps(
                    &candidate.replay.claim,
                    &candidate.replay.evidence_graph,
                    &candidate.replay.evidence_pool,
                    &fused,
                    &[],
                );
                case_signals.push(signals_for_case(&candidate, &gaps, &all_feedback));
                candidates_by_case.insert(candidate.id, candidate);
            }

            let mut review_budget = ReviewBudget::new(budget);
            if let Some(max_per_pattern) = max_per_pattern {
                review_budget.max_per_pattern = max_per_pattern;
            }
            let policy = DeterministicSamplingPolicy;
            let plan = policy.rank(&case_signals, &review_budget);

            println!(
                "fornax adjudicate sample: {} selected, {} deferred, {} distinct patterns, budget_exhausted={}",
                plan.selected.len(),
                plan.deferred.len(),
                plan.distinct_patterns_available,
                plan.budget_exhausted
            );
            for selected in &plan.selected {
                println!(
                    "  #{} {} signals={:?} reason={:?}",
                    selected.rank, selected.case_id, selected.signals, selected.selection_reason
                );
            }
            if dry_run {
                for deferred in &plan.deferred {
                    println!(
                        "  deferred {} reason={:?}",
                        deferred.case_id, deferred.reason
                    );
                }
                println!("fornax adjudicate sample: dry run, nothing enqueued");
            } else {
                for selected in &plan.selected {
                    let case_id_str = selected.case_id.to_string();
                    let candidate = candidates_by_case
                        .get(&selected.case_id)
                        .expect("selected case came from candidates_by_case");
                    let entry = QueueEntry {
                        case_id: selected.case_id,
                        double_review_required: false,
                        selection_reason: selected.selection_reason.clone(),
                        enqueued_at: now.clone(),
                    };
                    store
                        .insert_queue_entry(
                            &case_id_str,
                            &candidate.session_id,
                            &serde_json::to_string(&entry)?,
                            vec![candidate.id],
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                }
                println!(
                    "fornax adjudicate sample: enqueued {} case(s)",
                    plan.selected.len()
                );
            }
        }
        AdjudicateAction::Export {
            out,
            dataset_version,
        } => {
            let mut trajectories = Vec::new();
            let mut excluded = 0usize;
            for row in store
                .all_gold_labels()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
            {
                // Only the latest revision per case.
                let latest = store
                    .latest_gold_label_for_case(&row.case_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .unwrap();
                if latest.revision != row.revision {
                    continue;
                }
                let gold: fornax_corpus::adjudication::GoldLabelRevision =
                    serde_json::from_str(&row.document)?;
                if gold.expected_verdict.is_none() {
                    excluded += 1;
                    continue; // NotEvaluable
                }
                let candidate_row = store
                    .get_corpus_candidate(&row.case_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;
                let candidate = match candidate_row {
                    Some(r) => serde_json::from_str::<CandidateCase>(&r.document)?,
                    None => {
                        excluded += 1; // CandidateDeleted
                        continue;
                    }
                };

                let mut kinds = Vec::new();
                for review_row in store
                    .reviews_for_case(&row.case_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                {
                    let record: ReviewRecord = serde_json::from_str(&review_row.document)?;
                    if gold.contributing_review_ids.contains(&record.id) {
                        if let Some(reviewer_row) = store
                            .get_reviewer(&record.reviewer_id)
                            .await
                            .map_err(|e| anyhow::anyhow!("{e}"))?
                        {
                            let reviewer: ReviewerRef =
                                serde_json::from_str(&reviewer_row.document)?;
                            kinds.push(reviewer.kind);
                        }
                    }
                }

                if let Some(trajectory) = promote_gold_label(
                    &candidate,
                    &gold,
                    &kinds,
                    gold.frozen_by.clone(),
                    gold.frozen_at.clone(),
                ) {
                    trajectories.push(trajectory);
                }
            }

            let dataset = DatasetFileOut {
                dataset_version,
                description: format!(
                    "fornax adjudicate export -- {} trajectories, {excluded} excluded",
                    trajectories.len()
                ),
                trajectories,
            };
            std::fs::write(&out, serde_json::to_string_pretty(&dataset)?)?;
            println!(
                "fornax adjudicate export: wrote {} trajectory(ies), {excluded} excluded, to {}",
                dataset.trajectories.len(),
                out.display()
            );
        }
        AdjudicateAction::WorksheetExport {
            reviewer,
            case,
            out,
            double_review,
            unblinded,
        } => {
            if case.is_empty() {
                anyhow::bail!("--case must name at least one case id");
            }
            let mut seen = std::collections::HashSet::new();
            let mut entries = Vec::with_capacity(case.len());
            for case_id in &case {
                if !seen.insert(case_id.clone()) {
                    anyhow::bail!("duplicate --case {case_id} in one worksheet export");
                }
                let candidate = load_candidate(&store, case_id).await?;

                if store
                    .get_queue_entry(case_id)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .is_none()
                {
                    let entry = QueueEntry {
                        case_id: candidate.id,
                        double_review_required: double_review,
                        selection_reason: "worksheet-export".to_string(),
                        enqueued_at: now.clone(),
                    };
                    store
                        .insert_queue_entry(
                            case_id,
                            &candidate.session_id,
                            &serde_json::to_string(&entry)?,
                            vec![candidate.id],
                        )
                        .await
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                }

                let blinded = blind(&candidate);
                let view_id = Uuid::new_v4();
                let issued = IssuedView {
                    id: view_id,
                    case_id: candidate.id,
                    reviewer_id: reviewer.clone(),
                    unblinded,
                    blinded_digest: blinded.blinded_digest.clone(),
                    issued_at: now.clone(),
                };
                store
                    .insert_view(
                        &view_id.to_string(),
                        case_id,
                        &reviewer,
                        &candidate.session_id,
                        &serde_json::to_string(&issued)?,
                        vec![candidate.id],
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

                entries.push(WorksheetEntry {
                    view: view_id.to_string(),
                    case: case_id.clone(),
                    claim_text: blinded.claim.text.clone(),
                    evidence_pool_count: blinded.evidence_pool.len(),
                    withheld_evidence_count: blinded.withheld_evidence.len(),
                    label: None,
                    critical_failure: false,
                    failure_class: None,
                    confidence: None,
                    rationale: None,
                    unresolved: None,
                });
            }

            let worksheet = Worksheet {
                instructions: WORKSHEET_INSTRUCTIONS.to_string(),
                reviewer,
                entries,
            };
            std::fs::write(&out, serde_json::to_string_pretty(&worksheet)?)?;
            println!(
                "fornax adjudicate worksheet-export: wrote {} entries to {}",
                worksheet.entries.len(),
                out.display()
            );
        }
        AdjudicateAction::WorksheetImport { file } => {
            let raw = std::fs::read_to_string(&file)?;
            let worksheet: Worksheet = serde_json::from_str(&raw)?;
            let mut submitted = 0usize;
            let mut skipped = 0usize;
            let mut failed = 0usize;
            for entry in worksheet.entries {
                if entry.label.is_none() && entry.unresolved.is_none() {
                    println!("skip {}: no label/unresolved filled in yet", entry.case);
                    skipped += 1;
                    continue;
                }
                let Some(confidence) = entry.confidence else {
                    println!("skip {}: confidence not filled in", entry.case);
                    skipped += 1;
                    continue;
                };
                let rationale = match entry.rationale {
                    Some(r) if !r.trim().is_empty() => r,
                    _ => {
                        println!("skip {}: rationale not filled in", entry.case);
                        skipped += 1;
                        continue;
                    }
                };
                match submit_review(
                    &store,
                    &now,
                    &entry.view,
                    entry.label,
                    entry.critical_failure,
                    entry.failure_class,
                    confidence,
                    rationale,
                    entry.unresolved,
                )
                .await
                {
                    Ok(id) => {
                        println!("submitted {}: review {id}", entry.case);
                        submitted += 1;
                    }
                    Err(e) => {
                        println!("failed {}: {e}", entry.case);
                        failed += 1;
                    }
                }
            }
            println!(
                "fornax adjudicate worksheet-import: {submitted} submitted, {skipped} skipped, {failed} failed"
            );
            if failed > 0 {
                anyhow::bail!("{failed} worksheet entry(ies) failed to submit -- see output above");
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn submit_review(
    store: &fornax_store::Store,
    now: &str,
    view: &str,
    label: Option<LabelArg>,
    critical_failure: bool,
    failure_class: Option<FailureClassArg>,
    confidence: ConfidenceArg,
    rationale: String,
    unresolved: Option<String>,
) -> anyhow::Result<Uuid> {
    let view_row = store
        .get_view(view)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("no such view: {view}"))?;
    let issued: IssuedView = serde_json::from_str(&view_row.document)?;

    let candidate = load_candidate(store, &view_row.case_id).await?;
    let current_digest = blind(&candidate).blinded_digest;
    if current_digest != issued.blinded_digest {
        anyhow::bail!(
            "StaleEvidence: the candidate for case {} has changed since this view was issued -- \
             request a fresh `fornax adjudicate next`",
            view_row.case_id
        );
    }

    let reviewer_row = store
        .get_reviewer(&view_row.reviewer_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("no such reviewer: {}", view_row.reviewer_id))?;
    let reviewer: ReviewerRef = serde_json::from_str(&reviewer_row.document)?;

    let outcome = match (label, unresolved) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--label and --unresolved are mutually exclusive")
        }
        (Some(label), None) => ReviewOutcome::Label {
            label: label.into(),
            critical_failure,
            failure_class: failure_class.map(Into::into),
        },
        (None, Some(reason)) => ReviewOutcome::Unresolved { reason },
        (None, None) => anyhow::bail!("one of --label or --unresolved is required"),
    };

    let existing_reviews = store
        .reviews_for_case(&view_row.case_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if existing_reviews
        .iter()
        .any(|r| r.reviewer_id == view_row.reviewer_id)
    {
        anyhow::bail!(
            "reviewer {} has already reviewed case {} -- a repeat submission is not an \
             independent second review",
            view_row.reviewer_id,
            view_row.case_id
        );
    }

    let prior_revision = store
        .latest_gold_label_for_case(&view_row.case_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .map(|g| g.revision as u32);
    let round = prior_revision.unwrap_or(0) + 1;

    let record = ReviewRecord::new(
        Uuid::new_v4(),
        issued.case_id,
        Uuid::parse_str(view)?,
        view_row.reviewer_id.clone(),
        reviewer.role,
        outcome,
        confidence.into(),
        rationale,
        now.to_string(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    store
        .insert_review(
            &record.id.to_string(),
            &view_row.case_id,
            &view_row.reviewer_id,
            round,
            &candidate.session_id,
            &serde_json::to_string(&record)?,
            vec![candidate.id],
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(record.id)
}

async fn load_candidate(
    store: &fornax_store::Store,
    case_id: &str,
) -> anyhow::Result<CandidateCase> {
    let row = store
        .get_corpus_candidate(case_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("no such candidate case: {case_id}"))?;
    Ok(serde_json::from_str(&row.document)?)
}

async fn case_state(
    store: &fornax_store::Store,
    case_id: &str,
) -> anyhow::Result<(QueueEntry, Vec<ReviewRecord>, AdjudicationState)> {
    let entry_row = store
        .get_queue_entry(case_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .ok_or_else(|| anyhow::anyhow!("case {case_id} is not enqueued"))?;
    let entry: QueueEntry = serde_json::from_str(&entry_row.document)?;

    let review_rows = store
        .reviews_for_case(case_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut reviews = Vec::with_capacity(review_rows.len());
    for row in review_rows {
        reviews.push(serde_json::from_str::<ReviewRecord>(&row.document)?);
    }

    let frozen_revision = store
        .latest_gold_label_for_case(case_id)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .map(|g| g.revision as u32);

    let state = derive_state(&entry, &reviews, frozen_revision);
    Ok((entry, reviews, state))
}

async fn all_case_states(
    store: &fornax_store::Store,
) -> anyhow::Result<Vec<(String, QueueEntry, AdjudicationState)>> {
    let mut results = Vec::new();
    for row in store
        .all_queue_entries()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
    {
        let (entry, _reviews, state) = case_state(store, &row.case_id).await?;
        results.push((row.case_id, entry, state));
    }
    Ok(results)
}
