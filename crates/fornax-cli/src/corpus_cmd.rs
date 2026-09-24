//! `fornax corpus` (FORNX-341): mine real local sessions into sanitized
//! candidate integrity cases, and export a versioned corpus manifest.
//!
//! Reads `$FORNAX_HOME/fornax.db` directly, matching `audit`/`timeline`'s
//! precedent (`main.rs`'s `Commands::Audit` doc comment) -- no daemon
//! required. `fornax-corpus` itself has no `fornax-store` dependency; this
//! module is where the two meet.

use clap::Subcommand;
use fornax_types::{Claim, EvidenceGraph, Provider, Verdict};
use fornax_verify::decision::RiskClass;
use fornax_verify::fusion::{BaselineFusionPolicy, FusionInput, FusionPolicy};

#[derive(Subcommand)]
pub enum CorpusAction {
    /// Mine one session's claims into candidate integrity cases, if any
    /// mining strategy fires for them. Refuses with a clear message naming
    /// `FORNAX_CORPUS_MINING_ENABLED` if mining is not opted in.
    Mine {
        /// Session id to mine.
        #[arg(long)]
        session: String,
    },
    /// Build a deterministic corpus manifest from every candidate mined so
    /// far and write it to `--out`. Never derives the output filename from
    /// any session/candidate id -- `--out` is the only source of the path.
    Export {
        /// File path to write the manifest to.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Version label to stamp on the manifest (not a git/crate version
        /// -- an operator-chosen corpus revision label).
        #[arg(long)]
        corpus_version: String,
    },
}

pub async fn handle(action: CorpusAction, fornax_home: &std::path::Path) -> anyhow::Result<()> {
    let db_path = fornax_home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await?;

    match action {
        CorpusAction::Mine { session } => mine_session(&store, &session).await,
        CorpusAction::Export {
            out,
            corpus_version,
        } => export_corpus(&store, fornax_home, &out, corpus_version).await,
    }
}

async fn mine_session(store: &fornax_store::Store, session_id: &str) -> anyhow::Result<()> {
    let claims = store.claims_for_session(session_id).await?;
    let evidence_outcome = store.evidence_for_session(session_id).await?;
    if !evidence_outcome.failed.is_empty() {
        println!(
            "fornax corpus mine: {} evidence row(s) failed to deserialize and were skipped",
            evidence_outcome.failed.len()
        );
    }
    let full_pool = evidence_outcome.evidence;
    let all_findings = store.findings_for_session(session_id).await?;

    let mut mined = 0usize;
    for claim in &claims {
        let graph = store
            .evidence_graph_for_claim(&claim.id.to_string(), session_id)
            .await?;

        let fused = BaselineFusionPolicy.fuse(
            &FusionInput {
                claim,
                graph: &graph,
                evidence: &full_pool,
            },
            &claim.claimed_at,
        );

        let prior_verdicts: Vec<Verdict> = all_findings
            .iter()
            .filter(|f| f.claim_id == claim.id.to_string())
            .map(|f| serde_json::from_value(serde_json::Value::String(f.verdict.clone())))
            .collect::<Result<_, _>>()
            .unwrap_or_default();

        let strategies = fornax_corpus::evaluate(&fornax_corpus::MiningInput {
            claim,
            graph: &graph,
            evidence_pool: &full_pool,
            fused: &fused,
            prior_verdicts: &prior_verdicts,
        });
        if strategies.is_empty() {
            continue;
        }

        if let Err(e) = persist_candidate(
            store,
            session_id,
            claim,
            &graph,
            &full_pool,
            fused.verdict,
            fused.uncertainty,
            strategies,
        )
        .await
        {
            println!("fornax corpus mine: {e}");
            return Ok(());
        }
        mined += 1;
    }

    println!("fornax corpus mine: {mined} candidate(s) mined for session {session_id}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn persist_candidate(
    store: &fornax_store::Store,
    session_id: &str,
    claim: &Claim,
    graph: &EvidenceGraph,
    full_pool: &[fornax_types::Evidence],
    local_verdict: Verdict,
    local_uncertainty: fornax_verify::fusion::UncertaintyBand,
    mut mined_by: Vec<fornax_corpus::MiningStrategy>,
) -> anyhow::Result<()> {
    mined_by.sort();
    mined_by.dedup();

    let (sanitized_pool, sanitized_claim, withheld_evidence) =
        fornax_corpus::sanitize(full_pool.to_vec(), claim.clone());

    let mined_at = chrono::Utc::now().to_rfc3339();
    let replay = fornax_replay::manifest::build_manifest(
        sanitized_claim,
        sanitized_pool,
        graph.clone(),
        Provider::Unknown,
        "unknown".to_string(),
        &BaselineFusionPolicy,
        &fornax_verify::decision::DefaultRiskPolicy,
        RiskClass::Balanced,
        Default::default(),
        &mined_at,
    );

    let candidate = fornax_corpus::CandidateCase {
        schema_version: fornax_corpus::CANDIDATE_SCHEMA_VERSION,
        id: fornax_corpus::CandidateCase::derive_id(session_id, &replay),
        session_id: session_id.to_string(),
        replay,
        context: None,
        local_verdict,
        local_uncertainty,
        mined_by,
        withheld_evidence,
        mined_at: mined_at.clone(),
    };

    let document = serde_json::to_string(&candidate)?;
    store
        .insert_corpus_candidate(
            &candidate.id.to_string(),
            session_id,
            candidate.schema_version,
            &mined_at,
            &document,
            vec![claim.id],
        )
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
}

async fn export_corpus(
    store: &fornax_store::Store,
    fornax_home: &std::path::Path,
    out: &std::path::Path,
    corpus_version: String,
) -> anyhow::Result<()> {
    let rows = store.all_corpus_candidates().await?;
    let mut candidates = Vec::with_capacity(rows.len());
    for row in rows {
        candidates.push(serde_json::from_str::<fornax_corpus::CandidateCase>(
            &row.document,
        )?);
    }

    let home_identity = fornax_types::home_identity(fornax_home);
    let mined_at = chrono::Utc::now().to_rfc3339();
    let manifest =
        fornax_corpus::build_corpus_manifest(candidates, corpus_version, home_identity, mined_at)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

    std::fs::write(out, serde_json::to_string_pretty(&manifest)?)?;
    println!(
        "fornax corpus export: wrote {} candidate(s) ({} control(s)) to {}",
        manifest.candidate_count,
        manifest.control_count,
        out.display()
    );
    Ok(())
}
