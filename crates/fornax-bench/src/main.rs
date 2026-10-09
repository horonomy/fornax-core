//! `fornax-bench` CLI (FORNX-95): thin JSON-in/JSON-out wrapper over the
//! `fornax_bench` library. See `fornax_bench`'s crate docs for why this is a
//! separate binary/crate rather than a `fornax-verify` module.
//!
//! This binary also owns the one process-wide `#[global_allocator]` used by
//! `independence-capacity` (FORNX-432 PR 1) to count allocations/peak heap
//! around `fornax_bench::independence_capacity::run_fixture` calls -- see
//! that module's docs for why the allocator lives here and not in the lib.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use clap::{Parser, Subcommand};
use fornax_verify::decision::{DefaultRiskPolicy, RiskClass};
use fornax_verify::fusion::BaselineFusionPolicy;

use fornax_bench::ablation::run_ablation;
use fornax_bench::baseline::{freeze_baseline, BaselineReport};
use fornax_bench::dataset::Dataset;
use fornax_bench::gate::{evaluate_gate, GateVerdict, RegressionBudget};
use fornax_bench::harness::{run_harness, HarnessConfig};
use fornax_bench::independence_capacity::{self, CapacityReport, SkippedFixture};
use fornax_bench::manifest::build_manifest;
use fornax_bench::metrics::compute_metrics;
use fornax_bench::regression::compare;
use fornax_bench::slice::compute_slices;

/// Process-wide allocation counters for `independence-capacity`. Unused by
/// every other subcommand -- the wrapping allocator still delegates to
/// `System` unconditionally, so it adds only atomic-increment overhead to
/// those paths, never a behavior change.
static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static CURRENT_BYTES: AtomicI64 = AtomicI64::new(0);
static PEAK_BYTES: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            let cur = CURRENT_BYTES.fetch_add(layout.size() as i64, Ordering::Relaxed)
                + layout.size() as i64;
            PEAK_BYTES.fetch_max(cur.max(0) as u64, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT_BYTES.fetch_sub(layout.size() as i64, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            let diff = new_size as i64 - layout.size() as i64;
            if diff > 0 {
                ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
                ALLOC_BYTES.fetch_add(diff as u64, Ordering::Relaxed);
            }
            let cur = CURRENT_BYTES.fetch_add(diff, Ordering::Relaxed) + diff;
            PEAK_BYTES.fetch_max(cur.max(0) as u64, Ordering::Relaxed);
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

/// Resets the per-fixture counters. Deliberately does NOT reset
/// `CURRENT_BYTES` (it tracks real outstanding process memory; resetting it
/// would desync from reality) -- so `PEAK_BYTES` after a run reflects
/// "already-outstanding baseline at reset time, plus whatever this fixture
/// added on top", not an isolated delta. Documented in the markdown report.
fn reset_alloc_counters() {
    ALLOC_COUNT.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    PEAK_BYTES.store(
        CURRENT_BYTES.load(Ordering::Relaxed).max(0) as u64,
        Ordering::Relaxed,
    );
}

fn snapshot_alloc_counters() -> (u64, u64, u64) {
    (
        ALLOC_COUNT.load(Ordering::Relaxed),
        ALLOC_BYTES.load(Ordering::Relaxed),
        PEAK_BYTES.load(Ordering::Relaxed),
    )
}

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
    /// FORNX-432 PR 1: run the independence-capacity harness over frozen
    /// synthetic fixtures and write a JSON + markdown report.
    IndependenceCapacity {
        #[arg(
            long,
            default_value = "docs/research/fornx-432-independence-capacity.json"
        )]
        out_json: PathBuf,
        #[arg(
            long,
            default_value = "docs/research/fornx-432-independence-capacity.md"
        )]
        out_md: PathBuf,
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
        Command::IndependenceCapacity { out_json, out_md } => {
            run_independence_capacity(&out_json, &out_md)?;
        }
    }

    Ok(())
}

/// Runs every shape/size combination from
/// `independence_capacity::shape_specs()`, applying the per-shape
/// early-skip rule (`independence_capacity::should_skip_remaining`), and
/// writes both a JSON report and a markdown summary.
fn run_independence_capacity(out_json: &Path, out_md: &Path) -> anyhow::Result<()> {
    let mut results = Vec::new();
    let mut skipped = Vec::new();

    for spec in independence_capacity::shape_specs() {
        let mut shape_skipped = false;
        for &size in spec.sizes {
            if shape_skipped {
                skipped.push(SkippedFixture {
                    shape: spec.name,
                    size,
                    reason: format!(
                        "prior size for shape '{}' exceeded the {:.0}s wall-time budget",
                        spec.name,
                        independence_capacity::TIME_BUDGET.as_secs_f64()
                    ),
                });
                continue;
            }

            reset_alloc_counters();
            let (elapsed, mut result) = independence_capacity::run_fixture(spec.name, size);
            let (count, bytes, peak) = snapshot_alloc_counters();
            result.alloc_count = Some(count);
            result.alloc_bytes = Some(bytes);
            result.peak_bytes = Some(peak);
            eprintln!(
                "independence-capacity: {} @ {} -> {:.1}ms, {} families, peak {} bytes",
                result.shape, result.size, result.wall_time_ms, result.family_count, peak
            );
            results.push(result);

            if independence_capacity::should_skip_remaining(elapsed) {
                shape_skipped = true;
            }
        }
    }

    let report = CapacityReport {
        results,
        skipped,
        time_budget_seconds: independence_capacity::TIME_BUDGET.as_secs_f64(),
        contains_synthetic_labels: true,
        note: "Synthetic shapes, not a real workload -- see \
               crates/fornax-bench/src/independence_capacity.rs module docs.",
    };

    if let Some(parent) = out_json.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out_json, serde_json::to_string_pretty(&report)?)?;
    std::fs::write(out_md, render_independence_capacity_markdown(&report))?;
    println!(
        "fornax-bench independence-capacity: {} runs, {} skipped. Wrote {} and {}.",
        report.results.len(),
        report.skipped.len(),
        out_json.display(),
        out_md.display()
    );
    Ok(())
}

fn render_independence_capacity_markdown(report: &CapacityReport) -> String {
    let mut s = String::new();
    s.push_str("# FORNX-432 PR 1 — independence-capacity benchmark results\n\n");
    s.push_str(
        "**Synthetic shapes, not a real workload.** See \
         `crates/fornax-bench/src/independence_capacity.rs` module docs for fixture \
         definitions, size caps and the `bench-reference` cross-check. `peak_bytes` is \
         process-wide (this binary's own allocator), reset to the already-outstanding \
         baseline before each run rather than to zero -- see `reset_alloc_counters` in \
         `main.rs`. `wall_time_ms` approximates CPU time: `SourceFamilyMap::build` runs \
         single-threaded.\n\n",
    );
    s.push_str(&format!(
        "Per-fixture wall-time budget: {:.0}s (a shape exceeding it skips its remaining \
         larger configured sizes, recorded under Skipped below).\n\n",
        report.time_budget_seconds
    ));
    s.push_str(
        "| shape | size | evidence_count | family_count | wall_time_ms | alloc_count | \
         alloc_bytes | peak_bytes | reference_hash_matches |\n",
    );
    s.push_str("|---|---|---|---|---|---|---|---|---|\n");
    for r in &report.results {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {:.2} | {} | {} | {} | {} |\n",
            r.shape,
            r.size,
            r.evidence_count,
            r.family_count,
            r.wall_time_ms,
            r.alloc_count
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            r.alloc_bytes
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            r.peak_bytes
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            r.reference_hash_matches
                .map(|v| v.to_string())
                .unwrap_or_else(|| "n/a (bench-reference feature not enabled)".into()),
        ));
    }
    if !report.skipped.is_empty() {
        s.push_str("\n## Skipped\n\n");
        for sk in &report.skipped {
            s.push_str(&format!("- `{}` @ {}: {}\n", sk.shape, sk.size, sk.reason));
        }
    }
    s
}
