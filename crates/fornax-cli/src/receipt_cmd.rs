//! `fornax receipt` (FORNX-350): issue a portable integrity receipt from a
//! real local finding, and verify one against a gate policy. Reads
//! `$FORNAX_HOME/fornax.db` directly, matching `corpus`/`audit`/`timeline`'s
//! precedent -- no daemon required.
//!
//! **Verification-only.** `fornax receipt issue` never signs anything --
//! see `fornax_types::receipt`'s module docs for why. `fornax receipt
//! verify` verifies a signature produced elsewhere.

use std::path::PathBuf;

use clap::Subcommand;
use fornax_receipt::gate::{evaluate_receipt_gate, GateOutcome, ReceiptGatePolicy};
use fornax_receipt::issue::{issue_receipt, ReceiptInputs};
use fornax_receipt::verify::{resolve_receipt_trust_store, verify_receipt_bytes};
use fornax_types::RuntimeCapabilities;
use fornax_verify::decision::{DecisionPolicy, DefaultRiskPolicy, RiskClass};
use fornax_verify::fusion::{BaselineFusionPolicy, FusionInput, FusionPolicy};
use fornax_verify::independence::SourceFamilyMap;
use fornax_verify::voi::derive_gaps;

#[derive(Subcommand)]
pub enum ReceiptAction {
    /// Re-fuses `--claim`'s real evidence graph and issues a deterministic,
    /// reference-only receipt for it, written to `--out`.
    Issue {
        #[arg(long)]
        session: String,
        #[arg(long)]
        claim: String,
        #[arg(long, default_value = "balanced")]
        risk: String,
        /// Receipt time-to-live. Omit for a receipt with no declared
        /// expiry (see `fornax_receipt::freshness`'s `NoExpiryDeclared`
        /// state -- the default gate policy treats that as a `Hold`, not
        /// a fabricated "fresh forever").
        #[arg(long)]
        ttl_seconds: Option<i64>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verifies `<file>` (a bare receipt or a signed envelope) against
    /// `--policy` (default: `require_proceed_no_critical_gaps`), printing
    /// the verification result plus gate decision as JSON. Exit code: `0`
    /// = Accept, `10` = Reject, `11` = Hold, `12` = Untested.
    Verify {
        file: PathBuf,
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(long)]
        trust_store: Option<PathBuf>,
    },
}

fn parse_risk_class(s: &str) -> anyhow::Result<RiskClass> {
    match s {
        "strict" => Ok(RiskClass::Strict),
        "balanced" => Ok(RiskClass::Balanced),
        "lenient" => Ok(RiskClass::Lenient),
        other => Err(anyhow::anyhow!(
            "unknown risk class '{other}' -- expected one of strict, balanced, lenient"
        )),
    }
}

fn default_unknown_caps() -> RuntimeCapabilities {
    RuntimeCapabilities {
        schema_version: fornax_types::CAPABILITY_SCHEMA_VERSION,
        provider: fornax_types::Provider::Unknown,
        signals: vec![],
        notes: [(
            "reason".to_string(),
            "no capabilities announced by adapter yet".to_string(),
        )]
        .into(),
    }
}

pub async fn handle(action: ReceiptAction, fornax_home: &std::path::Path) -> anyhow::Result<()> {
    match action {
        ReceiptAction::Issue {
            session,
            claim,
            risk,
            ttl_seconds,
            out,
        } => issue(fornax_home, &session, &claim, &risk, ttl_seconds, &out).await,
        ReceiptAction::Verify {
            file,
            policy,
            trust_store,
        } => verify(
            fornax_home,
            &file,
            policy.as_deref(),
            trust_store.as_deref(),
        ),
    }
}

async fn issue(
    fornax_home: &std::path::Path,
    session_id: &str,
    claim_id: &str,
    risk: &str,
    ttl_seconds: Option<i64>,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let risk_class = parse_risk_class(risk)?;
    let db_path = fornax_home.join("fornax.db");
    let store = fornax_store::Store::open(&db_path).await?;

    let claims = store.claims_for_session(session_id).await?;
    let claim = claims
        .into_iter()
        .find(|c| c.id.to_string() == claim_id)
        .ok_or_else(|| anyhow::anyhow!("no claim {claim_id} found in session {session_id}"))?;

    let graph = store
        .evidence_graph_for_claim(&claim.id.to_string(), session_id)
        .await?;
    let evidence_outcome = store.evidence_for_session(session_id).await?;
    let full_pool = evidence_outcome.evidence;

    let fused = BaselineFusionPolicy.fuse(
        &FusionInput {
            claim: &claim,
            graph: &graph,
            evidence: &full_pool,
        },
        &claim.claimed_at,
    );
    let recommendation = DefaultRiskPolicy.decide(&fused, risk_class);

    // Deliberately an empty capabilities slice, matching
    // `fornax adjudicate sample`'s (FORNX-349) identical choice: a receipt
    // must be reproducible from the same frozen inputs regardless of which
    // machine/session capabilities happen to be live when it's issued.
    let gaps = derive_gaps(&claim, &graph, &full_pool, &fused, &[]);
    let families = SourceFamilyMap::build(&full_pool);

    let capabilities = store
        .capabilities_for_session(session_id)
        .await?
        .into_iter()
        .next()
        .unwrap_or_else(default_unknown_caps);
    let disabled_sensors = fornax_types::SensorDisableConfig::load(fornax_home)
        .map(|c| c.disabled_names().clone())
        .unwrap_or_default();
    let provenance = fornax_verify::calibration::live_provenance(
        &capabilities,
        &disabled_sensors,
        None, // no live policy-cache read from this offline CLI path
        None,
        None,
    );
    let calibration = fornax_verify::calibration::CalibrationAssessment {
        state: fornax_verify::calibration::CalibrationState::NoActiveCalibration,
        policy_version: 1,
    };

    let inputs = ReceiptInputs {
        claim: &claim,
        graph: &graph,
        evidence: &full_pool,
        fused: &fused,
        recommendation: &recommendation,
        gaps: &gaps,
        families: &families,
        provenance: &provenance,
        calibration: &calibration,
        issuer: "fornax-cli/receipt-issue/v1",
        home_identity: &fornax_types::home_identity(fornax_home),
    };

    let issued_at = chrono::Utc::now().to_rfc3339();
    let receipt = issue_receipt(&inputs, &issued_at, ttl_seconds)?;
    std::fs::write(out, serde_json::to_string_pretty(&receipt)?)?;
    println!(
        "fornax receipt issue: wrote receipt {} to {}",
        receipt.body().receipt_id,
        out.display()
    );
    Ok(())
}

fn verify(
    fornax_home: &std::path::Path,
    file: &std::path::Path,
    policy_path: Option<&std::path::Path>,
    trust_store_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(file)?;

    let trusted = match trust_store_path {
        Some(path) => {
            let raw = std::fs::read_to_string(path)?;
            Some(
                fornax_types::policy::TrustedVerificationKeys::load(&raw)
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
            )
        }
        None => resolve_receipt_trust_store(fornax_home).0,
    };

    let now = chrono::Utc::now();
    let verified =
        verify_receipt_bytes(&bytes, trusted.as_ref(), now).map_err(|e| anyhow::anyhow!("{e}"))?;

    let policy = match policy_path {
        Some(path) => serde_json::from_str(&std::fs::read_to_string(path)?)?,
        None => ReceiptGatePolicy::require_proceed_no_critical_gaps(),
    };
    let decision = evaluate_receipt_gate(&verified, &policy);

    let output = serde_json::json!({
        "receipt_id": verified.receipt().body().receipt_id,
        "verdict": verified.receipt().body().finding.verdict,
        "action": verified.receipt().body().recommendation.action,
        "signature": verified.signature(),
        "freshness": verified.freshness(),
        "gate": decision,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);

    match decision.outcome {
        GateOutcome::Accept => Ok(()),
        GateOutcome::Reject => std::process::exit(10),
        GateOutcome::Hold => std::process::exit(11),
        GateOutcome::Untested => std::process::exit(12),
    }
}
