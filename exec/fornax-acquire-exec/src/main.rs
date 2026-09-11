//! `fornax-acquire-exec` (FORNX-346 Part 2, ADR 0022): a physically separate,
//! explicitly opt-in binary that implements `RerunTest`/`QueryCiStatus` --
//! the two `fornax_verify::voi::ProbeKind` variants `fornax-acquire`
//! deliberately does not implement, because they require `ProcessSpawn`/
//! `NetworkCall` (see `docs/adr/0016-evidence-acquisition-boundary.md`'s
//! "Escalated, not built" section and `docs/adr/0022-privileged-acquisition-executor.md`).
//!
//! This crate lives under `exec/`, not `crates/` -- structural enforcement,
//! not a naming convention: `crates/fornax-daemon/tests/adversarial_daemon_input.rs`'s
//! zero-subprocess-spawn scan only walks `crates/`, and nothing under
//! `crates/` (daemon, cli) depends on or spawns this binary. An operator
//! invokes it directly, out-of-band, having explicitly configured both
//! `GlobalExperimentPolicy` (`[experiment]`) and `ExecutorGrants`
//! (`[acquisition_exec]`) in `$FORNAX_HOME/config.toml` first -- both
//! deny-by-default, both required.
//!
//! # Flow
//!
//! 1. `GET /api/evidence-plan?claim=&session=&risk=` -- the real ranked
//!    plan the running daemon computes for this claim (never trusts a
//!    stale plan a caller might hold from earlier).
//! 2. The operator selects one candidate by `--rank`.
//! 3. Gate 1: `fornax_acquire::classify_for_execution` against the
//!    locally-loaded `GlobalExperimentPolicy` -- the same re-gate
//!    `/api/acquire-evidence` itself performs.
//! 4. Gate 2: `ExecutorGrants` (`crate::grants`) -- checked inside
//!    `crate::rerun`/`crate::ci` themselves, independently of gate 1.
//! 5. Execute the probe (`crate::rerun::run_rerun_test` or
//!    `crate::ci::query_ci_status`).
//! 6. On `Acquired`, persist the evidence and an `acquisition_log` entry
//!    directly against `$FORNAX_HOME/fornax.db` (the same direct-store
//!    pattern `fornax-cli`'s other commands already use).
//! 7. `POST /api/reverify?claim=&session=` against the running daemon, and
//!    print `fused_before`/`fused_after` as JSON.

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use fornax_acquire::AcquisitionRoots;
use fornax_acquire_exec::{ci, grants::ExecutorGrants, rerun};
use fornax_experiment_runner::GlobalExperimentPolicy;
use fornax_verify::voi::{AcquisitionCandidate, CandidateAvailability, ProbeKind};
use uuid::Uuid;

/// See this crate's module docs for the full flow.
#[derive(Parser, Debug)]
#[command(
    name = "fornax-acquire-exec",
    about = "Privileged evidence-acquisition executor (RerunTest/QueryCiStatus) -- \
             opt-in, deny-by-default, deliberately outside crates/. See \
             docs/adr/0022-privileged-acquisition-executor.md."
)]
struct Cli {
    /// Claim id to acquire evidence for (from an existing `fornax decision`/
    /// `fornax evidence-plan` run).
    #[arg(long)]
    claim: String,
    /// Session id the claim belongs to.
    #[arg(long)]
    session: String,
    /// Risk class passed through to `/api/evidence-plan` -- affects only
    /// candidate ranking, never the gates.
    #[arg(long, default_value = "balanced")]
    risk: String,
    /// 1-based `AcquisitionCandidate::rank` from the freshly computed plan.
    #[arg(long)]
    rank: u32,
    /// Which operator-approved CI repo to query for `QueryCiStatus`.
    /// Required only when `[acquisition_exec].allowed_ci_repos` names more
    /// than one repo.
    #[arg(long)]
    repo: Option<String>,
    /// Working directory for a `RerunTest` command -- must resolve inside a
    /// configured `[acquisition]` root.
    #[arg(long, default_value = ".")]
    cwd: String,
    /// Latency budget for a `RerunTest` command, in seconds.
    #[arg(long, default_value_t = 30)]
    timeout_secs: u64,
}

fn fornax_home() -> PathBuf {
    std::env::var("FORNAX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".fornax"))
                .unwrap_or_else(|_| PathBuf::from("."))
        })
}

fn base_url() -> String {
    let port = std::env::var("FORNAX_HTTP_PORT").unwrap_or_else(|_| "4317".to_string());
    format!("http://127.0.0.1:{port}")
}

async fn fetch_json(url: &str) -> anyhow::Result<serde_json::Value> {
    let response = reqwest::get(url)
        .await
        .map_err(|_| anyhow::anyhow!("daemon unreachable at {url} (is fornax-daemon running?)"))?;
    Ok(response.json::<serde_json::Value>().await?)
}

async fn post_json(url: &str) -> anyhow::Result<serde_json::Value> {
    let client = reqwest::Client::new();
    let response =
        client.post(url).send().await.map_err(|_| {
            anyhow::anyhow!("daemon unreachable at {url} (is fornax-daemon running?)")
        })?;
    Ok(response.json::<serde_json::Value>().await?)
}

/// Find the most recent evidence row of `kind` in `evidence` -- evidence is
/// stored oldest-first, so scan from the end, mirroring
/// `fornax_verify`'s own "most recent first" convention for evidence scans.
fn most_recent(
    evidence: &[fornax_types::Evidence],
    kind: fornax_types::EvidenceKind,
) -> Option<&fornax_types::Evidence> {
    evidence.iter().rev().find(|e| e.kind == kind)
}

/// Find the most recent `VcsOperation` evidence carrying a `commit_sha` --
/// the real evidence type that would carry one (see
/// `fornax_types::ProcessObservationDetail::VcsOperation`).
fn most_recent_commit_sha(evidence: &[fornax_types::Evidence]) -> Option<String> {
    evidence.iter().rev().find_map(|e| {
        if e.kind != fornax_types::EvidenceKind::ProcessObservation {
            return None;
        }
        let payload: fornax_types::ProcessObservationPayload =
            serde_json::from_value(e.payload.clone()).ok()?;
        match payload.observation {
            Some(fornax_types::ProcessObservationDetail::VcsOperation {
                commit_sha: Some(sha),
                ..
            }) => Some(sha),
            _ => None,
        }
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let home = fornax_home();

    let policy = match GlobalExperimentPolicy::load(&home) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("fornax-acquire-exec: failed to load experiment policy ({e}); denying all side effects");
            GlobalExperimentPolicy::new(std::iter::empty())
        }
    };
    let grants = match ExecutorGrants::load(&home) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("fornax-acquire-exec: failed to load executor grants ({e}); denying every command/repo");
            ExecutorGrants::default()
        }
    };
    let roots = match AcquisitionRoots::load(&home) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "fornax-acquire-exec: failed to load acquisition roots ({e}); denying every target"
            );
            AcquisitionRoots::default()
        }
    };

    let plan_url = format!(
        "{}/api/evidence-plan?claim={}&session={}&risk={}",
        base_url(),
        cli.claim,
        cli.session,
        cli.risk
    );
    let plan_response = fetch_json(&plan_url).await?;

    let found = plan_response
        .get("found")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    if !found {
        println!("{}", serde_json::to_string_pretty(&plan_response)?);
        return Ok(());
    }

    let candidates = plan_response
        .get("plan")
        .and_then(|p| p.get("candidates"))
        .and_then(|c| c.as_array())
        .cloned()
        .unwrap_or_default();
    let Some(candidate_json) = candidates
        .iter()
        .find(|c| c.get("rank").and_then(|r| r.as_u64()) == Some(cli.rank as u64))
    else {
        println!(
            "fornax-acquire-exec: no candidate with rank {} in the current plan",
            cli.rank
        );
        return Ok(());
    };
    let candidate: AcquisitionCandidate = serde_json::from_value(candidate_json.clone())?;

    // Gate 1: the same GlobalExperimentPolicy re-gate `/api/acquire-evidence`
    // itself performs -- never trusts the plan's own (possibly stale)
    // `availability` field.
    match fornax_acquire::classify_for_execution(&candidate, &policy) {
        CandidateAvailability::Available => {}
        other => {
            println!("fornax-acquire-exec: refused by GlobalExperimentPolicy: {other:?}");
            return Ok(());
        }
    }

    let db_path = home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await?;
    let evidence_read = store.evidence_for_session(&cli.session).await?;

    let session_id = cli.session.clone();
    let source_event_id = Uuid::new_v4();
    let observed_at = chrono::Utc::now().to_rfc3339();

    // Gate 2 (ExecutorGrants) is checked inside rerun::run_rerun_test /
    // ci::query_ci_status themselves -- independent of gate 1 above.
    let (outcome, stdout, stderr) = match candidate.request.kind {
        ProbeKind::RerunTest => {
            let Some(command) = most_recent(
                &evidence_read.evidence,
                fornax_types::EvidenceKind::ExitCode,
            )
            .and_then(|e| e.payload.get("command").cloned()) else {
                println!(
                    "fornax-acquire-exec: no ExitCode evidence with a command found for session {}",
                    cli.session
                );
                return Ok(());
            };
            let result = rerun::run_rerun_test(
                &command,
                &grants,
                &roots,
                &cli.cwd,
                Duration::from_secs(cli.timeout_secs),
                &session_id,
                source_event_id,
                &observed_at,
            );
            (result.outcome, result.stdout, result.stderr)
        }
        ProbeKind::QueryCiStatus => {
            let Some(commit_sha) = most_recent_commit_sha(&evidence_read.evidence) else {
                println!(
                    "fornax-acquire-exec: no VcsOperation evidence with a commit_sha found for session {}",
                    cli.session
                );
                return Ok(());
            };
            let Some(source) = fornax_ci::GitHubCheckRunSource::from_env() else {
                println!(
                    "fornax-acquire-exec: no GitHub credential present (GITHUB_TOKEN/GH_TOKEN)"
                );
                return Ok(());
            };
            let outcome = ci::query_ci_status(
                &grants,
                cli.repo.as_deref(),
                &commit_sha,
                &source,
                &session_id,
                source_event_id,
                &observed_at,
            );
            (outcome, String::new(), String::new())
        }
        other => {
            println!("fornax-acquire-exec: unsupported probe kind for this executor: {other:?}");
            return Ok(());
        }
    };

    if !stdout.is_empty() {
        println!("--- child stdout ---\n{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("--- child stderr ---\n{stderr}");
    }

    let (outcome_kind, outcome_json): (&str, serde_json::Value) = match &outcome {
        fornax_acquire::AcquisitionOutcome::Acquired(evidence) => {
            ("acquired", serde_json::json!({ "evidence": evidence }))
        }
        fornax_acquire::AcquisitionOutcome::Refused { reason } => {
            ("refused", serde_json::json!({ "reason": reason }))
        }
        fornax_acquire::AcquisitionOutcome::Unavailable { reason } => {
            ("unavailable", serde_json::json!({ "reason": reason }))
        }
        fornax_acquire::AcquisitionOutcome::Failed { reason } => {
            ("failed", serde_json::json!({ "reason": reason }))
        }
        fornax_acquire::AcquisitionOutcome::Unsupported { reason } => {
            ("unsupported", serde_json::json!({ "reason": reason }))
        }
        fornax_acquire::AcquisitionOutcome::TimedOut { reason, elapsed_ms } => (
            "timed_out",
            serde_json::json!({ "reason": reason, "elapsed_ms": elapsed_ms }),
        ),
    };
    println!(
        "fornax-acquire-exec: outcome={outcome_kind} detail={}",
        outcome_json
    );

    let policy_name = plan_response
        .get("plan")
        .and_then(|p| p.get("policy_name"))
        .and_then(|s| s.as_str())
        .unwrap_or("fornax-acquire-exec")
        .to_string();
    let policy_version = plan_response
        .get("plan")
        .and_then(|p| p.get("policy_version"))
        .and_then(|n| n.as_u64())
        .unwrap_or(1) as u32;
    let log_document = serde_json::json!({
        "request": candidate.request,
        "outcome": outcome_json,
    });
    if let Err(e) = store
        .insert_acquisition_log_entry(
            &Uuid::new_v4().to_string(),
            &cli.session,
            &cli.claim,
            &format!("{:?}", candidate.request.kind),
            &policy_name,
            policy_version,
            outcome_kind,
            &observed_at,
            &log_document.to_string(),
        )
        .await
    {
        eprintln!("fornax-acquire-exec: failed to persist acquisition_log entry: {e}");
    }

    let fornax_acquire::AcquisitionOutcome::Acquired(evidence) = outcome else {
        return Ok(());
    };

    store.insert_evidence(&evidence).await?;

    let reverify_url = format!(
        "{}/api/reverify?claim={}&session={}",
        base_url(),
        cli.claim,
        cli.session
    );
    let reverify_response = post_json(&reverify_url).await?;
    println!("{}", serde_json::to_string_pretty(&reverify_response)?);

    Ok(())
}
