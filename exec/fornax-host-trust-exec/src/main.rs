//! `fornax-host-trust-exec verify-codex` -- the only entry point into this
//! crate (internal-docs ADR-0015 R1/R2: no other command exists, so there
//! is no passive-output path that could ever reach a spawn). See
//! `docs/adr/0026-codex-host-trust-verification.md` for the full design.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use serde::Serialize;

use fornax_host_trust_exec::launch::{self, LaunchPlan, ScratchCwd};
use fornax_host_trust_exec::protocol::{ClientMessage, HooksListResult, InitializeResult, Session};
use fornax_host_trust_exec::snapshot::{self, Snapshot};
use fornax_host_trust_exec::verdict::{self, AggregateVerdict, ReasonCode, Trust};
use fornax_host_trust_exec::{identity, protocol};

#[derive(Parser)]
#[command(name = "fornax-host-trust-exec")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Starts a sandboxed `codex app-server`, calls its `hooks/list` RPC,
    /// and reports Fornax's own installed hooks' real trust state.
    /// Operator-invoked only -- nothing else in this binary, and nothing
    /// outside it, can trigger this.
    VerifyCodex {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        codex_bin: Option<PathBuf>,
        #[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u64).range(500..=30_000))]
        timeout_ms: u64,
    },
}

#[derive(Serialize)]
struct Timing {
    version_check_ms: u128,
    spawn_to_initialize_ms: Option<u128>,
    spawn_to_hooks_list_ms: Option<u128>,
    total_ms: u128,
}

#[derive(Serialize)]
struct Envelope {
    schema_version: u32,
    operation: &'static str,
    adapter_id: &'static str,
    outcome: &'static str,
    codex: Option<CodexInfo>,
    result: AggregateVerdict,
    timing_ms: Timing,
}

#[derive(Serialize)]
struct CodexInfo {
    binary: PathBuf,
    version: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::VerifyCodex {
            json,
            codex_bin,
            timeout_ms,
        } => {
            let total_start = Instant::now();
            let (verdict, codex_info, timing) =
                run_verify(codex_bin, Duration::from_millis(timeout_ms), total_start);
            print_report(&verdict, &codex_info, &timing, json);
            std::process::exit(if verdict.host_trust == Trust::Trusted {
                0
            } else {
                3
            });
        }
    }
}

fn refuse(reason: ReasonCode) -> AggregateVerdict {
    AggregateVerdict {
        host_trust: Trust::Unknown,
        hooks: Vec::new(),
        global_reasons: vec![reason],
    }
}

fn run_verify(
    codex_bin_arg: Option<PathBuf>,
    timeout: Duration,
    total_start: Instant,
) -> (AggregateVerdict, Option<CodexInfo>, Timing) {
    let mut timing = Timing {
        version_check_ms: 0,
        spawn_to_initialize_ms: None,
        spawn_to_hooks_list_ms: None,
        total_ms: 0,
    };

    macro_rules! finish {
        ($verdict:expr, $codex_info:expr) => {{
            timing.total_ms = total_start.elapsed().as_millis();
            return ($verdict, $codex_info, timing);
        }};
    }

    if let Err(reason) = launch::require_sandbox_available() {
        finish!(refuse(reason), None);
    }

    let home = match std::env::var_os("HOME") {
        Some(h) => PathBuf::from(h),
        None => finish!(refuse(ReasonCode::CodexBinaryNotFound), None),
    };
    // Canonicalize before anything derives a Seatbelt literal-path param
    // from it: macOS's sandbox literal-path match compares against the
    // kernel-resolved path, and `$HOME` commonly sits under a symlinked
    // prefix (`/tmp` -> `/private/tmp`, `/var` -> `/private/var`) that a
    // non-canonical `HOME` would silently fail to match, making the
    // write-deny clauses in `launch.rs` quietly no-ops. Empirically
    // confirmed: without this, a tamper attempt against `hooks.json`
    // succeeded instead of being denied.
    let home = std::fs::canonicalize(&home).unwrap_or(home);
    let codex_home = snapshot::codex_home_dir(&home);
    let hooks_json_path = codex_home.join("hooks.json");

    let codex_bin = match launch::resolve_codex_binary(codex_bin_arg.as_deref()) {
        Ok(p) => p,
        Err(reason) => finish!(refuse(reason), None),
    };

    let expected = match identity::read_expected_hooks(&hooks_json_path) {
        Ok(e) => e,
        Err(_) => finish!(
            refuse(ReasonCode::HooksJsonUnreadable),
            Some(CodexInfo {
                binary: codex_bin,
                version: None
            })
        ),
    };
    if expected.is_empty() {
        finish!(
            refuse(ReasonCode::FornaxHooksNotInstalled),
            Some(CodexInfo {
                binary: codex_bin,
                version: None
            })
        );
    }

    let scratch_cwd = match ScratchCwd::new() {
        Ok(s) => s,
        Err(_) => finish!(
            refuse(ReasonCode::CodexBinaryNotFound),
            Some(CodexInfo {
                binary: codex_bin,
                version: None
            })
        ),
    };
    let plan = LaunchPlan {
        codex_bin: codex_bin.clone(),
        codex_home: home.clone(),
        cwd: scratch_cwd.path.clone(),
    };

    let version_start = Instant::now();
    let version = match launch::check_reviewed_version(&plan, Duration::from_secs(5)) {
        Ok(v) => v,
        Err(reason) => {
            timing.version_check_ms = version_start.elapsed().as_millis();
            finish!(
                refuse(reason),
                Some(CodexInfo {
                    binary: codex_bin,
                    version: None
                })
            );
        }
    };
    timing.version_check_ms = version_start.elapsed().as_millis();
    let codex_info = Some(CodexInfo {
        binary: codex_bin.clone(),
        version: Some(version.clone()),
    });

    let before = Snapshot::take(&codex_home);
    let spawn_start = Instant::now();
    let mut child = match launch::spawn_app_server(&plan) {
        Ok(c) => c,
        Err(_) => finish!(refuse(ReasonCode::CodexBinaryNotFound), codex_info),
    };
    let (stdin, stdout) = launch::take_pipes(&mut child);
    let mut session = Session::new(Box::new(stdin), Box::new(stdout));

    let deadline = Instant::now() + timeout;
    let run = (|| -> Result<AggregateVerdict, ReasonCode> {
        session
            .send(&ClientMessage::Initialize)
            .map_err(|_| ReasonCode::HostUnreachable)?;
        let init_value = session
            .recv_response(0, deadline)
            .map_err(map_protocol_error)?;
        timing.spawn_to_initialize_ms = Some(spawn_start.elapsed().as_millis());
        let init: InitializeResult =
            serde_json::from_value(init_value).map_err(|_| ReasonCode::HostResponseMalformed)?;

        let mut extra_global = Vec::new();
        let canonical_home =
            std::fs::canonicalize(&codex_home).unwrap_or_else(|_| codex_home.clone());
        let canonical_reported =
            std::fs::canonicalize(&init.codex_home).unwrap_or(init.codex_home.clone());
        if canonical_reported != canonical_home {
            extra_global.push(ReasonCode::CodexHomeMismatch);
        }
        if !init.user_agent.contains(version.as_str()) {
            extra_global.push(ReasonCode::CodexVersionConflict);
        }

        session
            .send(&ClientMessage::Initialized)
            .map_err(|_| ReasonCode::HostUnreachable)?;
        session
            .send(&ClientMessage::HooksList {
                cwd: scratch_cwd.path.clone(),
            })
            .map_err(|_| ReasonCode::HostUnreachable)?;
        let hooks_value = session
            .recv_response(1, deadline)
            .map_err(map_protocol_error)?;
        timing.spawn_to_hooks_list_ms = Some(spawn_start.elapsed().as_millis());

        let result: HooksListResult =
            serde_json::from_value(hooks_value).map_err(|_| ReasonCode::HostResponseMalformed)?;
        if result.data.len() != 1 {
            return Err(ReasonCode::HostResponseMalformed);
        }
        let entry = &result.data[0];
        if !entry.errors.is_empty() {
            extra_global.push(ReasonCode::HostReportedHookErrors);
        }

        let mut v = verdict::reconcile(&hooks_json_path, &expected, &entry.hooks);
        for reason in extra_global {
            verdict::downgrade_to_unknown_with(&mut v, reason);
        }
        Ok(v)
    })();

    session.close_stdin();
    launch::teardown(child);
    let after = Snapshot::take(&codex_home);

    let mut v = run.unwrap_or_else(refuse);
    if let Some(changed) = snapshot::tripwire_tripped(&before, &after) {
        eprintln!("fornax-host-trust-exec: WARNING state changed during verification: {changed:?}");
        verdict::downgrade_to_unknown_with(&mut v, ReasonCode::HostStateChangedDuringVerification);
    }

    finish!(v, codex_info);
}

fn map_protocol_error(e: protocol::ProtocolError) -> ReasonCode {
    match e {
        protocol::ProtocolError::HostUnreachable => ReasonCode::HostUnreachable,
        protocol::ProtocolError::Timeout => ReasonCode::Timeout,
        protocol::ProtocolError::HostResponseMalformed(_) => ReasonCode::HostResponseMalformed,
        protocol::ProtocolError::HostRpcError { message, .. } => ReasonCode::HostRpcError(message),
    }
}

fn print_report(
    verdict: &AggregateVerdict,
    codex: &Option<CodexInfo>,
    timing: &Timing,
    json: bool,
) {
    if json {
        let envelope = Envelope {
            schema_version: 1,
            operation: "verify_host_trust",
            adapter_id: "codex",
            outcome: if verdict.global_reasons.is_empty()
                && verdict.hooks.iter().all(|h| h.reasons.is_empty())
            {
                "completed"
            } else {
                "completed_with_findings"
            },
            codex: codex.as_ref().map(|c| CodexInfo {
                binary: c.binary.clone(),
                version: c.version.clone(),
            }),
            result: verdict.clone(),
            timing_ms: Timing {
                version_check_ms: timing.version_check_ms,
                spawn_to_initialize_ms: timing.spawn_to_initialize_ms,
                spawn_to_hooks_list_ms: timing.spawn_to_hooks_list_ms,
                total_ms: timing.total_ms,
            },
        };
        println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        return;
    }

    if let Some(c) = codex {
        print!("codex: {}", c.binary.display());
        if let Some(v) = &c.version {
            print!(" ({v})");
        }
        println!();
    }
    if !verdict.global_reasons.is_empty() {
        println!(
            "host_trust: {:?} -- {:?}",
            verdict.host_trust, verdict.global_reasons
        );
    } else {
        println!("host_trust: {:?}", verdict.host_trust);
    }
    for hook in &verdict.hooks {
        println!(
            "  {} {:>9} {}{}",
            hook.event,
            format!("{:?}", hook.trust),
            hook.host_trust_status.as_deref().unwrap_or("-"),
            if hook.reasons.is_empty() {
                String::new()
            } else {
                format!(" {:?}", hook.reasons)
            }
        );
    }
    println!(
        "timing: version_check={}ms total={}ms",
        timing.version_check_ms, timing.total_ms
    );
    println!("note: plugin-provided hooks excluded; verdict as evaluated by this codex binary");
}
