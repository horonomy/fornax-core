//! `fornax feedback` (FORNX-349): product feedback on a live
//! finding/recommendation, kept structurally separate from research
//! adjudication (`fornax adjudicate`). Reads `$FORNAX_HOME/fornax.db`
//! directly, matching `corpus`/`adjudicate`'s precedent -- no daemon
//! required.
//!
//! **This is not adjudication.** Feedback here can never become a frozen
//! gold label -- see `fornax_corpus::feedback` module docs for the
//! structural reason. It only ever raises a case's priority for real human
//! review via `fornax adjudicate sample`.

use clap::Subcommand;
use fornax_corpus::adjudication::Confidence;
use fornax_corpus::{CandidateCase, FeedbackAuthor, FeedbackDisposition, ReviewFeedback};

#[derive(Subcommand)]
pub enum FeedbackAction {
    /// Submit one piece of feedback on a mined candidate case.
    Submit {
        #[arg(long)]
        case: String,
        #[arg(long, value_enum)]
        disposition: DispositionArg,
        #[arg(long)]
        reason: String,
        #[arg(long, value_enum)]
        confidence: ConfidenceArg,
        /// Identify yourself as the local operator giving this feedback.
        /// Mutually exclusive with `--as-agent`.
        #[arg(long)]
        as_operator: Option<String>,
        /// Identify yourself as an automated agent giving this feedback --
        /// recorded honestly as such, never disguised as a person. Mutually
        /// exclusive with `--as-operator`.
        #[arg(long)]
        as_agent: Option<String>,
    },
    /// List every piece of feedback recorded for one case.
    List {
        #[arg(long)]
        case: String,
    },
}

#[derive(Clone, clap::ValueEnum)]
pub enum DispositionArg {
    AgreesWithFinding,
    DisagreesWithFinding,
    MissingContext,
    WrongEvidenceMapping,
    WrongRecommendation,
    NotEvaluable,
}
impl From<DispositionArg> for FeedbackDisposition {
    fn from(d: DispositionArg) -> Self {
        match d {
            DispositionArg::AgreesWithFinding => FeedbackDisposition::AgreesWithFinding,
            DispositionArg::DisagreesWithFinding => FeedbackDisposition::DisagreesWithFinding,
            DispositionArg::MissingContext => FeedbackDisposition::MissingContext,
            DispositionArg::WrongEvidenceMapping => FeedbackDisposition::WrongEvidenceMapping,
            DispositionArg::WrongRecommendation => FeedbackDisposition::WrongRecommendation,
            DispositionArg::NotEvaluable => FeedbackDisposition::NotEvaluable,
        }
    }
}

#[derive(Clone, clap::ValueEnum)]
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

pub async fn handle(action: FeedbackAction, fornax_home: &std::path::Path) -> anyhow::Result<()> {
    let db_path = fornax_home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await?;
    let now = chrono::Utc::now().to_rfc3339();

    match action {
        FeedbackAction::Submit {
            case,
            disposition,
            reason,
            confidence,
            as_operator,
            as_agent,
        } => {
            let author = match (as_operator, as_agent) {
                (Some(operator_ref), None) => FeedbackAuthor::LocalOperator { operator_ref },
                (None, Some(agent_ref)) => FeedbackAuthor::AutomatedAgent { agent_ref },
                (None, None) => {
                    return Err(anyhow::anyhow!(
                        "one of --as-operator or --as-agent is required"
                    ))
                }
                (Some(_), Some(_)) => {
                    return Err(anyhow::anyhow!(
                        "--as-operator and --as-agent are mutually exclusive"
                    ))
                }
            };

            let candidate = load_candidate(&store, &case).await?;
            let claim_id = candidate.replay.claim.id;
            let feedback = ReviewFeedback::new(
                &candidate,
                claim_id,
                disposition.into(),
                reason,
                confidence.into(),
                author,
                now,
            );
            let document = serde_json::to_string(&feedback)?;
            store
                .insert_feedback(
                    &feedback.id.to_string(),
                    &case,
                    &candidate.session_id,
                    &feedback.submitted_at,
                    &document,
                    vec![candidate.id],
                )
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("fornax feedback: recorded {} on case {case}", feedback.id);
        }
        FeedbackAction::List { case } => {
            let rows = store
                .feedback_for_case(&case)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            if rows.is_empty() {
                println!("no feedback recorded for case {case}");
            }
            for row in rows {
                let feedback: ReviewFeedback = serde_json::from_str(&row.document)?;
                println!(
                    "{} disposition={:?} confidence={:?} author={:?} reason={:?}",
                    feedback.id,
                    feedback.disposition,
                    feedback.reviewer_confidence,
                    feedback.author,
                    feedback.reason,
                );
            }
        }
    }
    Ok(())
}
