//! FORNX-433: automated regression for the real `fornax-hook-codex` ->
//! `fornax-daemon` (over a real Unix domain socket) transport leg, carried
//! all the way through to a persisted `Verdict` -- not just events/evidence
//! landing in storage (the bar `fornax-adapter-opencode`'s
//! `live_transport.rs` set for FORNX-291).
//!
//! Everything here is genuine, unstubbed code on the Fornax side: a real
//! `fornax-daemon` process, bound to a real Unix domain socket, and the
//! real, compiled `fornax-hook-codex` binary invoked exactly the way it
//! runs in production -- tailing a real rollout JSONL file on disk,
//! forwarding over the socket. The one thing stood in for is Codex's own
//! runtime: this test does not run a live `codex exec` session (which
//! would cost real API spend and isn't installed in CI), it writes a real
//! rollout JSONL file for the binary to tail.
//!
//! The negative case reuses `fornax-adapter-conformance/fixtures/codex/custom_tool_call_exec_pair_failure.json`
//! verbatim -- FORNX-16's genuine, live-captured-2026-08-31 `pytest -q`
//! failure through `tools.shell_command`'s real `custom_tool_call`/
//! `custom_tool_call_output` response-item pair, already a real negative
//! capture, no new capture needed. No real positive capture of that exact
//! `tools.shell_command` shape exists in the fixture set yet (the one
//! success exec-pair fixture uses `tools.exec_command`, which carries no
//! literal exit code at all -- see that fixture's own description), so the
//! positive case uses the exact real field shape `CodexCustomToolCallOutputSensor`'s
//! own doc comment confirms for a successful `tools.shell_command` run
//! (`"Script completed"` / `"Exit code: 0"`), with pytest output text --
//! constructed from a confirmed-real shape, not a new live capture, same
//! precedent as `fornax-adapter-claude`'s `live_transport.rs`. No new
//! native `codex`/API invocation, no new spend.
//!
//! This closes FORNX-433 AC1's "real authenticated native positive+negative
//! pair takes end-to-end ingress through verdict and audit" for the Codex
//! provider.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn sibling_workspace_bin(name: &str) -> PathBuf {
    let mut dir = std::env::current_exe().expect("current_exe");
    loop {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return candidate;
        }
        let is_profile_dir = dir
            .file_name()
            .map(|f| f == "debug" || f == "release")
            .unwrap_or(false);
        if is_profile_dir {
            panic!(
                "could not find sibling binary `{name}` under {}; build the workspace first \
                 (`cargo build --workspace`)",
                dir.display()
            );
        }
        if !dir.pop() {
            panic!("walked past filesystem root looking for `{name}`");
        }
    }
}

fn fixture_native_events(name: &str) -> Vec<serde_json::Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fornax-adapter-conformance/fixtures/codex")
        .join(name);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {name}: {e}"));
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse fixture JSON");
    assert_eq!(
        doc["sanitized"],
        serde_json::json!(true),
        "fixture {name} must be sanitized"
    );
    doc["native_events"]
        .as_array()
        .expect("native_events array")
        .clone()
}

/// The real field shape `CodexCustomToolCallOutputSensor`'s own doc
/// comment confirms for a successful `tools.shell_command` run
/// (`"Script completed"` / `"Exit code: 0"`), mirroring
/// `custom_tool_call_exec_pair_failure.json`'s real failure structure --
/// see module docs for why no genuine positive capture of this exact
/// shape exists yet.
fn pytest_success_exec_pair(call_id: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": call_id,
                "name": "exec",
                "input": "const r = await tools.shell_command({command:\"pytest -q\",workdir:\"/workspace\",timeout_ms:120000}); text(r)\n",
            }
        }),
        serde_json::json!({
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": call_id,
                "output": [
                    { "type": "input_text", "text": "Script completed\nWall time 0.4 seconds\nOutput:\n" },
                    { "type": "input_text", "text": "Exit code: 0\n...................... [100%]\n2 passed in 0.02s\n" },
                ]
            }
        }),
    ]
}

fn task_complete_line(assistant_text: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "event_msg",
        "payload": {"type": "task_complete", "last_agent_message": assistant_text}
    })
}

fn poll_until<T>(
    timeout: Duration,
    label: &str,
    diagnostics: impl FnOnce() -> String,
    mut f: impl FnMut() -> Option<T>,
) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        if start.elapsed() > timeout {
            panic!(
                "{label}: condition not met within {timeout:?}\n--- diagnostics ---\n{}",
                diagnostics()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn tail_log(path: &Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(contents) if contents.trim().is_empty() => "(empty)".to_string(),
        Ok(contents) => {
            let lines: Vec<&str> = contents.lines().collect();
            let start = lines.len().saturating_sub(40);
            lines[start..].join("\n")
        }
        Err(e) => format!("(could not read {}: {e})", path.display()),
    }
}

fn tempdir(label: &str) -> PathBuf {
    let dir = PathBuf::from("/tmp").join(format!("fx433-codex-{label}-{:x}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    dir
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn_daemon(fornax_home: &Path) -> (KillOnDrop, PathBuf) {
    let daemon_bin = sibling_workspace_bin("fornax-daemon");
    let http_port = free_tcp_port();
    let sock_path = fornax_home.join("fornax.sock");
    let daemon_log_path = fornax_home.join("daemon.log");
    let daemon_log = std::fs::File::create(&daemon_log_path).expect("create daemon.log");

    let daemon = Command::new(&daemon_bin)
        .env("FORNAX_HOME", fornax_home)
        .env("FORNAX_HTTP_PORT", http_port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(daemon_log)
        .spawn()
        .expect("spawn fornax-daemon");
    let guard = KillOnDrop(daemon);

    poll_until(
        Duration::from_secs(5),
        "waiting for daemon UDS socket to be created",
        || tail_log(&daemon_log_path),
        || sock_path.exists().then_some(()),
    );
    (guard, daemon_log_path)
}

/// Writes `lines` to a fresh rollout JSONL file upfront, then spawns the
/// real, compiled `fornax-hook-codex` binary pointed at it via `--file`
/// (same arg real deployments use to override the default
/// `~/.codex/sessions` discovery) and lets it tail the whole file in one
/// pass before killing it -- the real binary's own 500ms poll loop, not a
/// mocked timer.
fn run_hook_codex_over_rollout(
    fornax_home: &Path,
    rollout_path: &Path,
    lines: &[serde_json::Value],
) {
    let mut content = String::new();
    for line in lines {
        content.push_str(&line.to_string());
        content.push('\n');
    }
    std::fs::write(rollout_path, content).expect("write rollout file");

    let hook_bin = env!("CARGO_BIN_EXE_fornax-hook-codex");
    let mut child = Command::new(hook_bin)
        .arg("--file")
        .arg(rollout_path)
        .env("FORNAX_HOME", fornax_home)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fornax-hook-codex");
    // The binary's own poll loop wakes every 500ms; give it several cycles
    // to read, normalize, and forward every line over the socket before
    // killing it -- this test controls both ends (the rollout file's full
    // content is written before the binary even starts), so there is
    // nothing left to tail after the first full pass.
    std::thread::sleep(Duration::from_millis(1500));
    let _ = child.kill();
    let _ = child.wait();
}

fn run_case(label: &str, passed: bool, assistant_text: &str) -> (String, fornax_store::FindingRow) {
    let tmp = tempdir(label);
    let fornax_home = tmp.clone();
    let db_path = fornax_home.join("fornax.db");
    let rollout_path = tmp.join("rollout.jsonl");
    // `fornax-hook-codex` uses the rollout file's own path as the session
    // hint when no `session_meta` line supplies a real session id -- this
    // test supplies none, so the file path itself is the session id,
    // deterministic and unique per test run via `tempdir`'s pid+label.
    let session_id = rollout_path.to_string_lossy().to_string();
    let (daemon_guard, daemon_log_path) = spawn_daemon(&fornax_home);

    let mut lines = if passed {
        pytest_success_exec_pair("fx433-call-pos")
    } else {
        fixture_native_events("custom_tool_call_exec_pair_failure.json")
    };
    lines.push(task_complete_line(assistant_text));

    run_hook_codex_over_rollout(&fornax_home, &rollout_path, &lines);

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let finding = poll_until(
        Duration::from_secs(5),
        "waiting for the daemon to persist a real Finding for this session",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                let findings = store.findings_for_session(&session_id).await.ok()?;
                findings.into_iter().next()
            })
        },
    );

    drop(daemon_guard);
    std::fs::remove_dir_all(&tmp).ok();
    (session_id, finding)
}

#[test]
fn real_codex_shell_command_success_reaches_a_verified_finding_end_to_end() {
    let (_session_id, finding) = run_case("positive", true, "All tests passed.");
    assert_eq!(
        finding.verdict, "verified",
        "a genuine exit-code-0 tools.shell_command result plus a matching task_complete \
         claim must reach Verified through the real daemon, got verdict={} evidence_ids={}",
        finding.verdict, finding.evidence_ids
    );
    let evidence_ids: Vec<uuid::Uuid> =
        serde_json::from_str(&finding.evidence_ids).expect("decode evidence_ids");
    assert!(
        !evidence_ids.is_empty(),
        "the finding must actually cite the real evidence the exec pair produced"
    );
}

#[test]
fn real_codex_shell_command_failure_contradicts_a_false_success_claim_end_to_end() {
    // The adversarial negative control (FORNX-433 AC1): FORNX-16's real,
    // live-captured 2026-08-31 pytest failure through tools.shell_command,
    // plus a task_complete message that *falsely* claims success. A
    // verdict of anything other than Contradicted/Review here would mean
    // the real ingest path accepted a false claim against real contrary
    // evidence.
    let (_session_id, finding) = run_case("negative", false, "All tests passed.");
    assert_ne!(
        finding.verdict, "verified",
        "a false success claim against a real captured failure must never reach Verified, \
         got verdict={} evidence_ids={}",
        finding.verdict, finding.evidence_ids
    );
    assert!(
        finding.verdict == "contradicted" || finding.verdict == "review",
        "expected Contradicted or Review for a false claim against real failure evidence, \
         got verdict={} evidence_ids={}",
        finding.verdict,
        finding.evidence_ids
    );
}
