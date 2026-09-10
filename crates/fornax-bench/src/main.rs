//! `fornax-bench` CLI (FORNX-95): thin JSON-in/JSON-out wrapper over the
//! `fornax_bench` library. See `fornax_bench`'s crate docs for why this is a
//! separate binary/crate rather than a `fornax-verify` module.

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use fornax_verify::decision::{DefaultRiskPolicy, RiskClass};
use fornax_verify::fusion::BaselineFusionPolicy;

use fornax_bench::ablation::run_ablation;
use fornax_bench::baseline::{freeze_baseline, BaselineReport};
use fornax_bench::dataset::Dataset;
use fornax_bench::gate::{evaluate_gate, GateVerdict, RegressionBudget};
use fornax_bench::harness::{run_harness, HarnessConfig};
use fornax_bench::manifest::build_manifest;
use fornax_bench::metrics::compute_metrics;
use fornax_bench::regression::compare;
use fornax_bench::slice::compute_slices;

#[derive(Parser)]
#[command(
    name = "fornax-bench",
    about = "Fornax calibration/ablation benchmark harness"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn parse_risk_class(s: &str) -> Result<RiskClass, String> {
    match s {
        "strict" => Ok(RiskClass::Strict),
        "balanced" => Ok(RiskClass::Balanced),
        "lenient" => Ok(RiskClass::Lenient),
        other => Err(format!(
            "unknown risk class '{other}' -- expected one of strict, balanced, lenient"
        )),
    }
}

#[derive(Subcommand)]
enum Command {
    /// Run the fusion/decision pipeline over a labeled dataset and print a
    /// manifest + metrics report as JSON.
    Run {
        #[arg(long)]
        dataset: PathBuf,
        #[arg(long, default_value = "balanced")]
        risk: String,
        /// Comma-separated sensor names to disable for this run (default:
        /// none).
        #[arg(long, default_value = "")]
        disable_sensor: String,
    },
    /// Run the per-sensor ablation sweep over a labeled dataset and print
    /// each sensor's baseline/ablated metrics + deltas as JSON.
    Ablate {
        #[arg(long)]
        dataset: PathBuf,
        #[arg(long, default_value = "balanced")]
        risk: String,
        /// Comma-separated sensor names to sweep. When omitted, sweeps every
        /// sensor name found in the dataset's own evidence
        /// (`Dataset::known_sensor_names`).
        #[arg(long)]
        sensors: Option<String>,
    },
    /// The integrity regression lab (FORNX-344): freeze a baseline run, or
    /// compare a fresh run against a previously frozen one.
    Regress {
        #[command(subcommand)]
        action: RegressAction,
    },
}

#[derive(Subcommand)]
enum RegressAction {
    /// Run the pipeline over `--dataset` and write a `BaselineReport` to
    /// `--out` -- the artifact `regress compare` diffs a later run against.
    Freeze {
        #[arg(long)]
        dataset: PathBuf,
        #[arg(long, default_value = "balanced")]
        risk: String,
        #[arg(long, default_value = "")]
        disable_sensor: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Run the pipeline over `--dataset` and compare it against the frozen
    /// `--baseline`, printing the case-level `RegressionComparison` plus
    /// the gate's `GateReason` as JSON. Exits non-zero only on
    /// `GateVerdict::Block` -- `Untested`/`Inconclusive` are printed but do
    /// not fail the process, since neither one is itself a detected defect.
    Compare {
        #[arg(long)]
        dataset: PathBuf,
        #[arg(long, default_value = "balanced")]
        risk: String,
        #[arg(long, default_value = "")]
        disable_sensor: String,
        #[arg(long)]
        baseline: PathBuf,
        /// Path to a `RegressionBudget` JSON file. When omitted, uses
        /// `{"calibrated": false, "rules": []}` -- the same honestly-
        /// uncalibrated default this crate's own committed fixture ships,
        /// which always resolves to `Untested`.
        #[arg(long)]
        budget: Option<PathBuf>,
    },
}

fn parse_sensor_list(s: &str) -> BTreeSet<String> {
    s.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // The one place this binary reads the wall clock -- never inside the
    // library crate itself (see `fornax_bench::manifest`'s module docs, and
    // `fornax-daemon`'s `compute_fusion` for the same one-clock-read
    // precedent this mirrors).
    let run_at = chrono::Utc::now().to_rfc3339();

    match cli.command {
        Command::Run {
            dataset,
            risk,
            disable_sensor,
        } => {
            let dataset = Dataset::load(&dataset)?;
            let risk_class = parse_risk_class(&risk).map_err(anyhow::Error::msg)?;
            let mut config = HarnessConfig::new(risk_class);
            config.disabled_sensors = parse_sensor_list(&disable_sensor);

            let predictions = run_harness(&dataset, &config, &run_at);
            let metrics = compute_metrics(&predictions);
            let manifest = build_manifest(
                &dataset,
                &config,
                &BaselineFusionPolicy,
                &DefaultRiskPolicy,
                None,
                &run_at,
            );

            let output = serde_json::json!({
                "manifest": manifest,
                "metrics": metrics,
                "predictions": predictions,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        Command::Ablate {
            dataset,
            risk,
            sensors,
        } => {
            let dataset = Dataset::load(&dataset)?;
            let risk_class = parse_risk_class(&risk).map_err(anyhow::Error::msg)?;
            let config = HarnessConfig::new(risk_class);
            let sensor_names = match sensors {
                Some(s) => parse_sensor_list(&s),
                None => dataset.known_sensor_names(),
            };

            let results = run_ablation(&dataset, &config, &sensor_names, &run_at);
            let manifest = build_manifest(
                &dataset,
                &config,
                &BaselineFusionPolicy,
                &DefaultRiskPolicy,
                None,
                &run_at,
            );

            let output = serde_json::json!({
                "manifest": manifest,
                "ablation_results": results,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
        }
        Command::Regress { action } => match action {
            RegressAction::Freeze {
                dataset,
                risk,
                disable_sensor,
                out,
            } => {
                let dataset = Dataset::load(&dataset)?;
                let risk_class = parse_risk_class(&risk).map_err(anyhow::Error::msg)?;
                let mut config = HarnessConfig::new(risk_class);
                config.disabled_sensors = parse_sensor_list(&disable_sensor);

                let baseline = freeze_baseline(&dataset, &config, &run_at);
                std::fs::write(&out, serde_json::to_string_pretty(&baseline)?)?;
                println!(
                    "fornax-bench regress freeze: wrote baseline ({} trajectories) to {}",
                    baseline.predictions.len(),
                    out.display()
                );
            }
            RegressAction::Compare {
                dataset,
                risk,
                disable_sensor,
                baseline,
                budget,
            } => {
                let dataset = Dataset::load(&dataset)?;
                let risk_class = parse_risk_class(&risk).map_err(anyhow::Error::msg)?;
                let mut config = HarnessConfig::new(risk_class);
                config.disabled_sensors = parse_sensor_list(&disable_sensor);

                let current = freeze_baseline(&dataset, &config, &run_at);
                let baseline: BaselineReport = serde_json::from_slice(&std::fs::read(&baseline)?)?;
                let comparison = compare(&baseline, &current);
                let slices = compute_slices(&dataset.trajectories);
                let regression_budget: RegressionBudget = match budget {
                    Some(path) => serde_json::from_slice(&std::fs::read(&path)?)?,
                    None => RegressionBudget {
                        calibrated: false,
                        rules: Vec::new(),
                    },
                };
                let gate = evaluate_gate(&comparison, &slices, &regression_budget);

                let output = serde_json::json!({
                    "comparison": comparison,
                    "gate": gate,
                });
                println!("{}", serde_json::to_string_pretty(&output)?);

                if gate.verdict == GateVerdict::Block {
                    anyhow::bail!("fornax-bench regress compare: gate verdict is Block");
                }
            }
        },
    }

    Ok(())
}
