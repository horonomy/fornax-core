//! `RerunTest` -- the one deliberate subprocess-spawn exception in this
//! entire workspace (see `docs/adr/0022-privileged-acquisition-executor.md`
//! and this crate's own `Cargo.toml` comment). **The only file, in the whole
//! repository, that may contain `std::process::Command` or an inline shell
//! invocation.**
//!
//! # Injection-surface rules (structural, not heuristic)
//!
//! The command comes from agent-reported evidence
//! (`fornax_types::ExitCodePayload::command`) -- untrusted, unvalidated
//! JSON. This module enforces exactly five rules, no sanitization or
//! blocklisting substitutes for any of them:
//!
//! 1. **Never invoke a shell.** [`std::process::Command::new`] +
//!    [`std::process::Command::args`] only -- no `sh -c`, ever, anywhere in
//!    this file.
//! 2. **Accept only a `serde_json::Value::Array` of strings as the
//!    command.** A `Value::String` is refused with a clear reason -- never
//!    split into argv. See "the argv-splitting asymmetry" below.
//! 3. **`argv[0]` must pass [`crate::grants::ExecutorGrants::permits_argv`]**
//!    (an operator-approved command prefix) or the attempt is refused.
//! 4. **`current_dir` must resolve inside a configured acquisition root**
//!    (`fornax_acquire::containment::AcquisitionRoots`) or the attempt is
//!    refused.
//! 5. **Credential-shaped env vars are stripped from the child.** Defense
//!    against exfiltrating a `QueryCiStatus` credential (`GITHUB_TOKEN`/
//!    `GH_TOKEN`) via a `RerunTest` child process, in case an operator
//!    grants both probes.
//!
//! ## The argv-splitting asymmetry is the security property
//!
//! `crate::grants::ExecutorGrants::load` whitespace-splits each
//! `allowed_commands` entry into argv **once, at config-load time** --
//! that string is trusted operator configuration. This module does the
//! opposite: an agent-reported command is accepted *only* as an
//! already-structured `Value::Array` of strings and is **never** split from
//! a string. Splitting a trusted string and refusing to split an untrusted
//! one is not an inconsistency -- it is the entire point. If this module
//! ever split an evidence-supplied string into argv the way config strings
//! are split, an agent could report a "command" containing a `;`, `&&`, or
//! `$(...)` and rely on some downstream shell to interpret it; because
//! [`std::process::Command`] never invokes a shell, the string would either
//! be passed as one single (harmless) argv element or refused outright by
//! rule 2 above -- there is no path from evidence JSON to shell
//! interpretation.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fornax_acquire::{AcquisitionOutcome, AcquisitionRoots};
use fornax_types::{Evidence, EvidenceKind, ExitCodePayload};
use uuid::Uuid;

use crate::grants::ExecutorGrants;

/// Credential-shaped env vars stripped from every `RerunTest` child.
/// Named explicitly (not inferred) -- mirrors `fornax_ci::GitHubCheckRunSource
/// ::from_env`'s own `GITHUB_TOKEN`, `GH_TOKEN` precedence, so a credential
/// `QueryCiStatus` would use is never inherited by a sibling `RerunTest`
/// child process run through this same executor.
const STRIPPED_CREDENTIAL_ENV_VARS: [&str; 2] = ["GITHUB_TOKEN", "GH_TOKEN"];

/// Real result of one `RerunTest` attempt. `stdout`/`stderr` are exposed
/// alongside the canonical `outcome` purely for caller/test observability
/// (proving argv elements were passed as inert literals, never
/// shell-interpreted) -- they are not part of the `Evidence` this produces.
/// `pid` is `Some` whenever a child was actually spawned, so a caller can
/// independently confirm a timed-out child was really reaped, not merely
/// abandoned.
#[derive(Debug)]
pub struct RerunOutcome {
    pub outcome: AcquisitionOutcome,
    pub stdout: String,
    pub stderr: String,
    pub pid: Option<u32>,
}

fn refused(reason: String) -> RerunOutcome {
    RerunOutcome {
        outcome: AcquisitionOutcome::Refused { reason },
        stdout: String::new(),
        stderr: String::new(),
        pid: None,
    }
}

/// Rule 2: only a `Value::Array` of strings is ever accepted as a command.
fn parse_argv(command: &serde_json::Value) -> Result<Vec<String>, String> {
    match command {
        serde_json::Value::Array(items) => {
            let mut argv = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(s) => argv.push(s.to_string()),
                    None => {
                        return Err(
                            "command array contains a non-string element; refusing".to_string()
                        )
                    }
                }
            }
            if argv.is_empty() {
                return Err("command array is empty; refusing".to_string());
            }
            Ok(argv)
        }
        serde_json::Value::String(_) => Err(
            "command is not a structured argv array; refusing to parse a shell string".to_string(),
        ),
        _ => Err("command is neither an argv array nor a string; refusing".to_string()),
    }
}

/// Run one `RerunTest` probe. `command` is agent-reported evidence
/// (untrusted); `cwd` is an operator-supplied working directory (validated
/// against `roots` before use, same as any other acquisition target).
#[allow(clippy::too_many_arguments)]
pub fn run_rerun_test(
    command: &serde_json::Value,
    grants: &ExecutorGrants,
    roots: &AcquisitionRoots,
    cwd: &str,
    timeout: Duration,
    session_id: &str,
    source_event_id: Uuid,
    observed_at: &str,
) -> RerunOutcome {
    let argv = match parse_argv(command) {
        Ok(argv) => argv,
        Err(reason) => return refused(reason),
    };

    // Rule 3: gate 2 (ExecutorGrants), independent of gate 1
    // (GlobalExperimentPolicy), which the caller already checked.
    if !grants.permits_argv(&argv) {
        return refused(format!(
            "'{}' is not an operator-approved command prefix",
            argv[0]
        ));
    }

    // Rule 4: containment, reusing fornax-acquire's own trusted
    // resolve_contained -- never a bespoke path check.
    let contained_cwd = match roots.resolve_contained(cwd) {
        Ok(p) => p,
        Err(e) => return refused(format!("cwd refused by containment: {e}")),
    };

    // Rule 1: Command::new + args only, never a shell.
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.current_dir(&contained_cwd);
    // Rule 5.
    for var in STRIPPED_CREDENTIAL_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return RerunOutcome {
                outcome: AcquisitionOutcome::Failed {
                    reason: format!("failed to spawn {}: {e}", argv[0]),
                },
                stdout: String::new(),
                stderr: String::new(),
                pid: None,
            }
        }
    };
    let pid = child.id();

    // Drain stdout/stderr concurrently on their own threads so a chatty
    // child can never deadlock this polling loop by filling its pipe buffer
    // before it exits.
    let stdout_buf = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::new()));
    let stdout_reader = child.stdout.take().map(|mut pipe| {
        let buf = Arc::clone(&stdout_buf);
        std::thread::spawn(move || {
            let mut data = Vec::new();
            let _ = pipe.read_to_end(&mut data);
            *buf.lock().expect("stdout buffer mutex poisoned") = data;
        })
    });
    let stderr_reader = child.stderr.take().map(|mut pipe| {
        let buf = Arc::clone(&stderr_buf);
        std::thread::spawn(move || {
            let mut data = Vec::new();
            let _ = pipe.read_to_end(&mut data);
            *buf.lock().expect("stderr buffer mutex poisoned") = data;
        })
    });

    let start = Instant::now();
    let deadline = start + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                return RerunOutcome {
                    outcome: AcquisitionOutcome::Failed {
                        reason: format!("failed to poll child process: {e}"),
                    },
                    stdout: String::new(),
                    stderr: String::new(),
                    pid: Some(pid),
                }
            }
        }
    };

    let Some(status) = status else {
        // Real kill, not an abandoned thread: actually reap the process
        // rather than merely stop waiting for it.
        let _ = child.kill();
        let _ = child.wait();
        if let Some(h) = stdout_reader {
            let _ = h.join();
        }
        if let Some(h) = stderr_reader {
            let _ = h.join();
        }
        return RerunOutcome {
            outcome: AcquisitionOutcome::TimedOut {
                reason: format!("rerun exceeded the {timeout:?} acquisition budget"),
                elapsed_ms: start.elapsed().as_millis() as u64,
            },
            stdout: String::new(),
            stderr: String::new(),
            pid: Some(pid),
        };
    };

    if let Some(h) = stdout_reader {
        let _ = h.join();
    }
    if let Some(h) = stderr_reader {
        let _ = h.join();
    }
    let stdout = String::from_utf8_lossy(&stdout_buf.lock().expect("stdout buffer mutex poisoned"))
        .into_owned();
    let stderr = String::from_utf8_lossy(&stderr_buf.lock().expect("stderr buffer mutex poisoned"))
        .into_owned();

    let exit_code = status.code().unwrap_or(-1) as i64;
    let payload = ExitCodePayload {
        command: serde_json::Value::Array(
            argv.iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
        exit_code,
        heuristic: false,
    };
    let evidence = Evidence {
        id: Uuid::new_v4(),
        session_id: session_id.to_string(),
        source_event_id,
        kind: EvidenceKind::ExitCode,
        observed_at: observed_at.to_string(),
        payload: serde_json::to_value(payload).expect("ExitCodePayload always serializes"),
        provenance: "fornax-acquire-exec:rerun_test:FORNX-346".to_string(),
        source: None,
        extension: None,
        evidence_purged: false,
    };

    RerunOutcome {
        outcome: AcquisitionOutcome::Acquired(Box::new(evidence)),
        stdout,
        stderr,
        pid: Some(pid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn roots_here() -> AcquisitionRoots {
        AcquisitionRoots::new([Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()])
    }

    #[test]
    fn a_value_string_command_is_refused_never_shell_parsed() {
        let grants = ExecutorGrants::new(vec![vec!["echo".to_string()]], vec![]);
        let outcome = run_rerun_test(
            &serde_json::json!("echo hello"),
            &grants,
            &roots_here(),
            ".",
            Duration::from_secs(5),
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        match outcome.outcome {
            AcquisitionOutcome::Refused { reason } => {
                assert!(reason.contains("shell string"));
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn an_argv0_not_in_the_allowlist_is_refused() {
        let grants =
            ExecutorGrants::new(vec![vec!["cargo".to_string(), "test".to_string()]], vec![]);
        let outcome = run_rerun_test(
            &serde_json::json!(["rm", "-rf", "/"]),
            &grants,
            &roots_here(),
            ".",
            Duration::from_secs(5),
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        assert!(matches!(
            outcome.outcome,
            AcquisitionOutcome::Refused { .. }
        ));
    }

    #[test]
    fn cwd_outside_every_root_is_refused() {
        let grants = ExecutorGrants::new(vec![vec!["echo".to_string()]], vec![]);
        let outcome = run_rerun_test(
            &serde_json::json!(["echo", "hi"]),
            &grants,
            &roots_here(),
            "/etc",
            Duration::from_secs(5),
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        assert!(matches!(
            outcome.outcome,
            AcquisitionOutcome::Refused { .. }
        ));
    }

    #[test]
    fn an_allowlisted_command_with_an_adversarial_later_argv_element_runs_as_an_inert_literal() {
        let grants = ExecutorGrants::new(vec![vec!["/bin/echo".to_string()]], vec![]);
        let payload = "; rm -rf /tmp/fornax-exec-test-sentinel; $(whoami)";
        let outcome = run_rerun_test(
            &serde_json::json!(["/bin/echo", payload]),
            &grants,
            &roots_here(),
            ".",
            Duration::from_secs(5),
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        assert!(matches!(outcome.outcome, AcquisitionOutcome::Acquired(_)));
        assert!(
            outcome.stdout.contains(payload),
            "expected the literal payload verbatim in stdout, got: {}",
            outcome.stdout
        );
    }

    #[test]
    fn github_token_is_not_inherited_by_the_child() {
        std::env::set_var("GITHUB_TOKEN", "should-never-leak");
        let grants = ExecutorGrants::new(vec![vec!["/usr/bin/env".to_string()]], vec![]);
        let outcome = run_rerun_test(
            &serde_json::json!(["/usr/bin/env"]),
            &grants,
            &roots_here(),
            ".",
            Duration::from_secs(5),
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        std::env::remove_var("GITHUB_TOKEN");
        assert!(matches!(outcome.outcome, AcquisitionOutcome::Acquired(_)));
        assert!(
            !outcome.stdout.contains("GITHUB_TOKEN"),
            "GITHUB_TOKEN leaked into child env output: {}",
            outcome.stdout
        );
    }

    #[test]
    fn a_long_running_command_is_actually_killed_on_timeout() {
        let grants = ExecutorGrants::new(vec![vec!["/bin/sleep".to_string()]], vec![]);
        let outcome = run_rerun_test(
            &serde_json::json!(["/bin/sleep", "30"]),
            &grants,
            &roots_here(),
            ".",
            Duration::from_millis(150),
            "s1",
            Uuid::new_v4(),
            "2026-01-01T00:00:00Z",
        );
        let (reason, elapsed_ms) = match outcome.outcome {
            AcquisitionOutcome::TimedOut { reason, elapsed_ms } => (reason, elapsed_ms),
            other => panic!("expected TimedOut, got {other:?}"),
        };
        assert!(!reason.is_empty());
        assert!(
            elapsed_ms < 30_000,
            "must not have waited for the full 30s sleep, elapsed_ms={elapsed_ms}"
        );
        let pid = outcome.pid.expect("a child was spawned");
        // Real reap, not an abandoned thread: `wait()` was already called
        // inside `run_rerun_test` before returning, so the OS no longer
        // reports this pid as a running process (`ps -p` -- a test-only
        // subprocess spawn, outside this crate's own `src/`, so it is not
        // scanned by the workspace's zero-subprocess-spawn / confinement
        // tests).
        let still_running = Command::new("ps")
            .args(["-p", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(
            !still_running,
            "pid {pid} is still reported as running after run_rerun_test returned TimedOut"
        );
    }
}
