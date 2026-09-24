//! `fornax-replay` CLI (FORNX-98): thin JSON-in/JSON-out wrapper over the
//! `fornax_replay` library, following `fornax-bench`'s own
//! "thin wrapper, separate binary" precedent (see `fornax_bench::main`'s
//! module docs) rather than growing `fornax-cli`'s already-large
//! subcommand set.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use fornax_replay::engine::replay;
use fornax_replay::manifest::ReplayManifest;

#[derive(Parser)]
#[command(
    name = "fornax-replay",
    about = "Deterministic replay of frozen Fornax trajectories against the real verifier/fusion pipeline"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Replay a frozen manifest and print the comparison report as JSON.
    /// Never performs a network call or spawns a subprocess -- the manifest
    /// file is the only input read.
    Replay {
        /// Path to a JSON-encoded `ReplayManifest`.
        manifest_path: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Replay { manifest_path } => run_replay(&manifest_path),
    }
}

fn run_replay(manifest_path: &PathBuf) -> ExitCode {
    let contents = match std::fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to read manifest {}: {e}", manifest_path.display());
            return ExitCode::FAILURE;
        }
    };
    let manifest: ReplayManifest = match serde_json::from_str(&contents) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("failed to parse manifest {}: {e}", manifest_path.display());
            return ExitCode::FAILURE;
        }
    };

    match replay(&manifest) {
        Ok(comparison) => {
            let json =
                serde_json::to_string_pretty(&comparison).expect("ReplayComparison must serialize");
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "manifest {} failed validation: {e}",
                manifest_path.display()
            );
            ExitCode::FAILURE
        }
    }
}
