//! `fornax-host-adapter-exec` (HORO-1712/HORO-1715): the separate executable
//! boundary a registered `host-adapter-v1` descriptor would, in a future
//! phase, actually run through. This build never runs one.
//!
//! Founder decision, 2026-10-09, in response to an independent review of an
//! earlier draft (the review's core finding: re-checking a path or hash
//! immediately before `exec()` cannot prove which bytes the kernel actually
//! loads against a non-root writer running as the same user as this
//! process -- macOS has no `fexecve`/`execveat`, and a held file descriptor
//! does not stop the same user from rewriting the file in place):
//!
//! 1. **Launch**: operator-invoked only (`doctor <id>`). No Codex hook, no
//!    daemon, no other `crates/` code may trigger this binary. Hook-driven
//!    execution is explicitly deferred to a future, separately approved
//!    security model.
//! 2. **Fail closed**: this build contains no subprocess-spawn call at all
//!    (grep this crate -- there is no `std::process::Command`,
//!    `std::os::unix::process`, or FFI `exec*` anywhere in it). Inspection,
//!    manifest validation, and digest measurement are fully supported (see
//!    `review`), but no measurement, match, or confirmation flag ever
//!    authorizes a spawn, because there is no spawn code path to authorize.
//!    Every `doctor` call ends in the single closed outcome
//!    `execution_binding_unavailable`.
//!
//! This crate lives under `exec/`, not `crates/`, for the same structural
//! reason `exec/fornax-acquire-exec` does (ADR-0022): nothing under
//! `crates/` depends on it, so the daemon's zero-subprocess scan
//! (`crates/fornax-daemon/tests/adversarial_daemon_input.rs`) never needs
//! to know this binary exists.

use std::path::PathBuf;

use clap::Parser;
use fornax_experiment_runner::GlobalExperimentPolicy;
use fornax_host_adapter_exec::review::{self, Review, VersionCompatibility};
use fornax_store::adapter_registry::lookup_host_descriptor;
use fornax_types::experiment::SideEffectClass;

#[derive(Parser, Debug)]
#[command(
    name = "fornax-host-adapter-exec",
    about = "Read-only review of a registered host adapter descriptor. Never executes \
             adapter code -- see this crate's module docs for the founder-recorded \
             fail-closed decision (2026-10-09)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Review a registered host-adapter descriptor: version compatibility,
    /// declared capabilities, and runtime-file digest drift. Always
    /// concludes with `execution_binding_unavailable` -- this subcommand
    /// never spawns the adapter.
    Doctor {
        /// The registered adapter id (`adapter_id` in its manifest).
        id: String,
        /// Emit the CLI envelope as JSON instead of a human-readable report.
        #[arg(long)]
        json: bool,
    },
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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Doctor { id, json } => {
            let exit_code = run_doctor(&id, json);
            std::process::exit(exit_code);
        }
    }
}

/// Returns the process exit code: `0` for a completed review (regardless of
/// what it found -- refusal to execute is the expected, successful
/// outcome of this tool), nonzero only for a usage/lookup failure that
/// prevented a review from running at all.
fn run_doctor(id: &str, json: bool) -> i32 {
    let home = fornax_home();

    // Informational only -- never gates the review itself. Even a fully
    // granted `ProcessSpawn` permission cannot unlock execution in this
    // build, since there is no spawn code path for it to unlock.
    let process_spawn_granted = GlobalExperimentPolicy::load(&home)
        .map(|policy| policy.permits(SideEffectClass::ProcessSpawn))
        .unwrap_or(false);

    let descriptor = match lookup_host_descriptor(&home, id) {
        Ok(descriptor) => descriptor,
        Err(err) => {
            print_lookup_failure(id, err.code_str(), json);
            return 1;
        }
    };

    let review = match review::build_review(&descriptor) {
        Ok(review) => review,
        Err(err) => {
            print_malformed_manifest(id, &err.to_string(), json);
            return 1;
        }
    };

    if json {
        print_json_review(process_spawn_granted, &review);
    } else {
        print_human_review(id, process_spawn_granted, &review);
    }
    0
}

const OUTCOME: &str = "execution_binding_unavailable";

fn print_lookup_failure(id: &str, reason_code: &str, json: bool) {
    if json {
        let envelope = serde_json::json!({
            "schema_version": 1,
            "operation": "doctor",
            "adapter_id": id,
            "outcome": "refused",
            "reason_codes": [reason_code],
            "verification_state": "unverified",
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).expect("serialize envelope")
        );
    } else {
        println!("fornax-host-adapter-exec doctor: {id}");
        println!("  registration lookup failed: {reason_code}");
        println!("  outcome: refused (no review performed)");
    }
}

fn print_malformed_manifest(id: &str, detail: &str, json: bool) {
    if json {
        let envelope = serde_json::json!({
            "schema_version": 1,
            "operation": "doctor",
            "adapter_id": id,
            "outcome": "refused",
            "reason_codes": ["manifest_contract_violation"],
            "verification_state": "unverified",
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).expect("serialize envelope")
        );
    } else {
        println!("fornax-host-adapter-exec doctor: {id}");
        println!("  registered manifest did not have an expected field shape: {detail}");
        println!("  outcome: refused (no review performed)");
    }
}

fn version_reason_code(version: &VersionCompatibility) -> Option<&'static str> {
    match version {
        VersionCompatibility::Compatible { .. } => None,
        VersionCompatibility::ProtocolIncompatible => Some("protocol_version_incompatible"),
        VersionCompatibility::ContractIncompatible => Some("host_contract_version_incompatible"),
    }
}

fn print_json_review(process_spawn_granted: bool, review: &Review) {
    let mut reason_codes: Vec<&str> = vec![OUTCOME];
    if let Some(code) = version_reason_code(&review.version) {
        reason_codes.push(code);
    }
    if review.environment_grant_declared {
        reason_codes.push("environment_grant_unavailable");
    }
    if review.measurement_capacity_exceeded {
        reason_codes.push("capacity_exceeded");
    }

    let drift = review::drift_counts(review);
    let envelope = serde_json::json!({
        "schema_version": 1,
        "operation": "doctor",
        "adapter_id": review.fields.adapter_id,
        "outcome": "refused",
        "reason_codes": reason_codes,
        "verification_state": "unverified",
        "result": {
            "registered_enabled": review.entry_enabled,
            "adapter_version": review.fields.adapter_version,
            "roles": review.fields.roles,
            "capabilities": review.fields.capabilities,
            "version_compatible": matches!(review.version, VersionCompatibility::Compatible { .. }),
            "environment_grant_declared": review.environment_grant_declared,
            "needs_read_paths_declared": review.fields.needs_read_paths.len(),
            "needs_write_paths_declared": review.fields.needs_write_paths.len(),
            "runtime_files_declared": review.fields.runtime_files.len(),
            "runtime_files_measured": review.runtime_files.len(),
            "runtime_files_matched": drift.get("matched").copied().unwrap_or(0),
            "runtime_files_mismatched_or_unreadable": drift.get("mismatched_or_unreadable").copied().unwrap_or(0),
            "measurement_capacity_exceeded": review.measurement_capacity_exceeded,
            "executable_measured_digest": review.executable_measured_digest,
            "implementation_digest": review.implementation_digest,
            "process_spawn_grant_present": process_spawn_granted,
        },
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&envelope).expect("serialize envelope")
    );
}

fn print_human_review(id: &str, process_spawn_granted: bool, review: &Review) {
    println!("fornax-host-adapter-exec doctor: {id}");
    println!(
        "  registration: {} ({})",
        if review.entry_enabled {
            "enabled"
        } else {
            "disabled"
        },
        review.fields.adapter_version
    );
    println!("  roles: {}", review.fields.roles.join(", "));
    println!("  capabilities: {}", review.fields.capabilities.join(", "));
    match &review.version {
        VersionCompatibility::Compatible {
            protocol_version,
            contract_version,
        } => println!(
            "  version: compatible (protocol {protocol_version}, host contract {contract_version})"
        ),
        VersionCompatibility::ProtocolIncompatible => {
            println!("  version: incompatible (protocol_version_incompatible)")
        }
        VersionCompatibility::ContractIncompatible => {
            println!("  version: incompatible (host_contract_version_incompatible)")
        }
    }
    if review.environment_grant_declared {
        println!(
            "  environment grant: declared, {} variable(s) -- would be refused \
             (environment_grant_unavailable) even if execution were implemented",
            review.fields.needs_environment.len()
        );
    } else {
        println!("  environment grant: none declared");
    }
    println!(
        "  declared file access: {} read path(s), {} write path(s)",
        review.fields.needs_read_paths.len(),
        review.fields.needs_write_paths.len()
    );

    let drift = review::drift_counts(review);
    println!(
        "  runtime files: {} declared, {} measured ({} matched, {} mismatched or unreadable)",
        review.fields.runtime_files.len(),
        review.runtime_files.len(),
        drift.get("matched").copied().unwrap_or(0),
        drift.get("mismatched_or_unreadable").copied().unwrap_or(0)
    );
    for file in &review.runtime_files {
        let status = if file.matches_declared {
            "match"
        } else if file.measured_digest.is_none() {
            "unreadable"
        } else {
            "MISMATCH"
        };
        println!("    [{status}] {} ({})", file.path, file.kind);
    }
    if review.measurement_capacity_exceeded {
        println!(
            "  WARNING: measurement stopped early (capacity_exceeded) -- the runtime-file \
             list above is partial"
        );
    }
    match &review.executable_measured_digest {
        Some(digest) => println!("  executable measured digest: {digest}"),
        None => println!("  executable measured digest: unreadable"),
    }
    match &review.implementation_digest {
        Some(digest) => println!("  implementation digest (fornax-host-impl-v1): {digest}"),
        None => println!("  implementation digest: unavailable"),
    }
    println!(
        "  process_spawn grant: {}",
        if process_spawn_granted {
            "present"
        } else {
            "absent"
        }
    );
    println!();
    println!("  outcome: {OUTCOME}");
    println!(
        "  This build never executes adapter code. A matching digest here is a drift \
         diagnostic, not proof of which bytes a future exec() would run against a \
         non-root writer running as the same user -- see docs/adr/0023-external-adapter-registry.md, \
         D11. Execution is fail-closed pending a separately approved integrity model."
    );
}
