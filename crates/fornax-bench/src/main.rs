//! `fornax-bench` CLI (FORNX-95): thin JSON-in/JSON-out wrapper over the
//! `fornax_bench` library. See `fornax_bench`'s crate docs for why this is a
//! separate binary/crate rather than a `fornax-verify` module.

use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use fornax_verify::decision::{DefaultRiskPolicy, RiskClass};
use fornax_verify::fusion::BaselineFusionPolicy;

use fornax_bench::ablation::run_ablation;
use fornax_bench::dataset::Dataset;
use fornax_bench::harness::{run_harness, HarnessConfig};
use fornax_bench::manifest::build_manifest;
use fornax_bench::metrics::compute_metrics;

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
    }

    Ok(())
}
