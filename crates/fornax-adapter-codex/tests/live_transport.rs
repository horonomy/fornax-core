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

/// Resolves the real, guaranteed-fresh `fornax-daemon` binary for this test
/// run. `env!("CARGO_BIN_EXE_*")` only resolves binaries that live in *this*
/// crate (`fornax-hook-codex` does; `fornax-daemon` does not — a separate
/// crate, and bin-only with no lib target, so it cannot even be added as a
/// dev-dependency to get Cargo to set that env var for it), so this must be
/// resolved by hand.
///
/// This used to walk up from `current_exe()` looking for a sibling file
/// literally named `fornax-daemon` and trust whatever it found. Found
/// 2026-10-14 (HORO-1712) to be a real hazard: on a machine whose default
/// `CARGO_TARGET_DIR` is a dir shared across many unrelated checkouts (this
/// repo's own `~/.claude/CLAUDE.md` documents exactly this, and tells
/// contributors to override it with `CARGO_TARGET_DIR=./target` for that
/// reason), the walk could silently find a `fornax-daemon` built from a
/// different, much older commit rather than failing to find one at all — a
/// *wrong* binary, not a missing one, so `is_file()` alone can't catch it.
///
/// An mtime-based staleness check was tried and rejected: `cargo build
/// --workspace` legitimately skips rebuilding `fornax-daemon` when its own
/// sources haven't changed, so a perfectly correct binary can be "old"
/// relative to a freshly relinked test binary — that produced a false
/// positive on this very machine during this fix's own verification.
///
/// Instead: find `target/<profile>/` the same way as before (there is no
/// avoiding *some* walk — this is how every binary in this workspace is
/// ever located), then explicitly `cargo build -p fornax-daemon` into that
/// exact target dir before returning its path. This is correct regardless
/// of whether `CARGO_TARGET_DIR` is shared or isolated: a build that is
/// already up to date is a fast no-op; a stale or foreign binary gets
/// genuinely rebuilt, every time, rather than guessed about.
fn fresh_daemon_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current_exe");
    let profile_dir = loop {
        let is_profile_dir = dir
            .file_name()
            .map(|f| f == "debug" || f == "release")
            .unwrap_or(false);
        if is_profile_dir {
            break dir;
        }
        if !dir.pop() {
            panic!("walked past filesystem root looking for target/<profile>/");
        }
    };
    let profile = profile_dir
        .file_name()
        .and_then(|f| f.to_str())
        .expect("profile dir has a name");
    let target_dir = profile_dir.parent().expect("profile dir has a parent");

    // CARGO_MANIFEST_DIR is this crate's own dir (crates/fornax-adapter-codex),
    // always correct at compile time regardless of how the test was invoked
    // — the workspace root is two levels up.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&workspace_root)
        .args(["build", "-p", "fornax-daemon", "--bin", "fornax-daemon"])
        .arg("--target-dir")
        .arg(target_dir);
    if profile == "release" {
        cmd.arg("--release");
    }
    let status = cmd.status().expect("spawn cargo build -p fornax-daemon");
    assert!(
        status.success(),
        "cargo build -p fornax-daemon failed (exit {status}) — see output above"
    );

    let bin = profile_dir.join("fornax-daemon");
    assert!(
        bin.is_file(),
        "cargo build -p fornax-daemon reported success but {} does not exist",
        bin.display()
    );
    bin
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
    let daemon_bin = fresh_daemon_bin();
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
/// `~/.codex/sessions` discovery) and lets it tail the whole file -- the
/// real binary's own 500ms poll loop, not a mocked timer -- until `done`
/// reports the condition the caller is actually waiting for, then kills it.
///
/// A fixed sleep-and-hope here would be both slow and flaky (same
/// precedent/warning as `fornax-adapter-opencode`'s `live_transport.rs`):
/// too short under load and the hook gets killed before it finishes
/// forwarding every line; too long and every test run pays the worst case.
/// Poll the real condition the test cares about instead, while the hook
/// process is still alive.
fn run_hook_codex_over_rollout(
    fornax_home: &Path,
    rollout_path: &Path,
    lines: &[serde_json::Value],
    mut done: impl FnMut() -> bool,
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

    let start = Instant::now();
    let timeout = Duration::from_secs(5);
    while !done() {
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            panic!("fornax-hook-codex: condition not met within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = child.kill();
    let _ = child.wait();
}

fn session_meta_line(session_id: &str) -> serde_json::Value {
    serde_json::json!({
        "timestamp": "2026-10-23T00:00:00.000Z",
        "type": "session_meta",
        "payload": {"id": session_id, "session_id": session_id}
    })
}

fn run_case(label: &str, passed: bool, assistant_text: &str) -> (String, fornax_store::FindingRow) {
    let tmp = tempdir(label);
    let fornax_home = tmp.clone();
    let db_path = fornax_home.join("fornax.db");
    let rollout_path = tmp.join("rollout.jsonl");
    // Real rollouts open with a `session_meta` line carrying the provider's
    // native session id, and `fornax-hook-codex` forwards nothing until it
    // has seen one (FORNX-462), so the fixture opens the same way.
    let session_id = format!("fx462-{label}-session");
    let (daemon_guard, daemon_log_path) = spawn_daemon(&fornax_home);

    let mut lines = vec![session_meta_line(&session_id)];
    lines.extend(if passed {
        pytest_success_exec_pair("fx433-call-pos")
    } else {
        fixture_native_events("custom_tool_call_exec_pair_failure.json")
    });
    lines.push(task_complete_line(assistant_text));

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    run_hook_codex_over_rollout(&fornax_home, &rollout_path, &lines, || {
        rt.block_on(async {
            let store = match fornax_store::Store::open(&db_path).await {
                Ok(s) => s,
                Err(_) => return false,
            };
            matches!(store.evidence_for_session(&session_id).await, Ok(e) if !e.evidence.is_empty())
        })
    });

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

/// HORO-1712 part B acceptance: "hook + rollout together do not double
/// count". Feeds the real rollout path for a genuinely failing
/// `item_completed` `CommandExecution` (the real 0.160+ shape, HORO-1712
/// comments 27283/27302), reaching a real Contradicted finding exactly
/// like the test above, then separately runs the real, compiled
/// `fornax-hook-codex-event` binary with a `PostToolUse` hook payload for
/// the SAME native call id against the SAME session. The hook path must
/// insert its own `AgentEvent` row (proving it does not silently no-op or
/// collide/quarantine against the rollout's row for the same native id)
/// while adding zero `Evidence` and leaving the finding's verdict and
/// evidence set byte-identical to the rollout-only baseline.
#[test]
fn hook_and_rollout_for_the_same_call_do_not_double_count_evidence() {
    let tmp = tempdir("double-count");
    let fornax_home = tmp.clone();
    let db_path = fornax_home.join("fornax.db");
    let rollout_path = tmp.join("rollout.jsonl");
    let session_id = "fx1712-double-count-session";
    let native_call_id = "exec-fx1712-double-count-001";

    let (daemon_guard, daemon_log_path) = spawn_daemon(&fornax_home);

    let lines = vec![
        serde_json::json!({
            "timestamp": "2026-10-13T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": session_id, "session_id": session_id}
        }),
        serde_json::json!({
            "type": "event_msg",
            "payload": {
                "type": "item_completed",
                "item": {
                    "type": "CommandExecution",
                    "id": native_call_id,
                    "status": "failed",
                    "exit_code": 1,
                    "command": ["/bin/zsh", "-lc", "pytest -q"],
                    "source": "unified_exec_startup"
                }
            }
        }),
        task_complete_line("All tests passed."),
    ];

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    run_hook_codex_over_rollout(&fornax_home, &rollout_path, &lines, || {
        rt.block_on(async {
            let store = match fornax_store::Store::open(&db_path).await {
                Ok(s) => s,
                Err(_) => return false,
            };
            matches!(store.evidence_for_session(session_id).await, Ok(e) if !e.evidence.is_empty())
        })
    });

    let baseline_finding = poll_until(
        Duration::from_secs(5),
        "waiting for the rollout-only baseline Finding",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                store
                    .findings_for_session(session_id)
                    .await
                    .ok()?
                    .into_iter()
                    .next()
            })
        },
    );
    let baseline_evidence_count = rt.block_on(async {
        fornax_store::Store::open(&db_path)
            .await
            .expect("open store")
            .evidence_for_session(session_id)
            .await
            .expect("query evidence")
            .evidence
            .len()
    });

    let has_hook_event = |events: &[fornax_types::AgentEvent]| {
        events.iter().any(|event| {
            event.raw.get("hook_event_name").and_then(|v| v.as_str()) == Some("PostToolUse")
        })
    };
    let baseline_events = rt.block_on(async {
        fornax_store::Store::open(&db_path)
            .await
            .expect("open baseline store")
            .events_for_session(session_id)
            .await
            .expect("query baseline events")
    });
    assert_eq!(
        baseline_events.len(),
        2,
        "rollout event and completion baseline"
    );
    assert!(
        !has_hook_event(&baseline_events),
        "two rollout-only events must not satisfy the hook-presence wait"
    );

    // Now the real hook binary, same native call id, same session.
    let hook_bin = env!("CARGO_BIN_EXE_fornax-hook-codex-event");
    let hook_payload = serde_json::json!({
        "session_id": session_id,
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "pytest -q"},
        "tool_response": "",
        "tool_use_id": native_call_id
    });
    let mut child = Command::new(hook_bin)
        .env("FORNAX_HOME", &fornax_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fornax-hook-codex-event");
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(hook_payload.to_string().as_bytes())
            .expect("write hook payload");
    }
    let status = child.wait().expect("wait for fornax-hook-codex-event");
    assert!(
        status.success(),
        "fornax-hook-codex-event must always exit 0"
    );

    // The rollout already created two events. Wait for the actual hook
    // origin; a count threshold can return before that connection drains.
    let events_after = poll_until(
        Duration::from_secs(5),
        "waiting for the hook-sourced AgentEvent to persist",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                let events = store.events_for_session(session_id).await.ok()?;
                has_hook_event(&events).then_some(events)
            })
        },
    );
    assert!(
        has_hook_event(&events_after),
        "the hook-sourced PostToolUse event must actually be present, not merely counted"
    );

    let evidence_after = rt.block_on(async {
        fornax_store::Store::open(&db_path)
            .await
            .expect("open store")
            .evidence_for_session(session_id)
            .await
            .expect("query evidence")
            .evidence
    });
    assert_eq!(
        evidence_after.len(),
        baseline_evidence_count,
        "the hook path must add zero Evidence -- any growth here is double counting"
    );

    let finding_after = rt.block_on(async {
        fornax_store::Store::open(&db_path)
            .await
            .expect("open store")
            .findings_for_session(session_id)
            .await
            .expect("query findings")
            .into_iter()
            .next()
            .expect("finding still present")
    });
    assert_eq!(
        finding_after.verdict, baseline_finding.verdict,
        "the hook-sourced event must not change the verdict"
    );
    assert_eq!(
        finding_after.evidence_ids, baseline_finding.evidence_ids,
        "the hook-sourced event must not change which evidence the finding cites"
    );
    assert_eq!(baseline_finding.verdict, "contradicted");

    drop(daemon_guard);
    std::fs::remove_dir_all(&tmp).ok();
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
    assert_eq!(
        finding.verdict, "contradicted",
        "this fixture carries a literal, non-heuristic exit_code=1 (FORNX-16's real \
         tools.shell_command capture), so the verdict is deterministically Contradicted, \
         not merely Review -- a fallback to Review here would mean the adapter silently \
         stopped parsing the literal exit code, got verdict={} evidence_ids={}",
        finding.verdict, finding.evidence_ids
    );
}

/// FORNX-462: the rollout path is never an identity. Lines the tailer reads
/// before the stream has supplied a native session id are not stored under
/// the file path (or anywhere); once a `session_meta` line arrives later in
/// the same stream, subsequent lines are stored under that native id. The
/// control half proves the hook was alive and forwarding throughout, so the
/// negative half cannot pass vacuously.
#[test]
fn lines_before_a_native_session_id_are_never_stored_under_the_rollout_path() {
    use std::io::Write;

    let tmp = tempdir("no-native-id");
    let fornax_home = tmp.clone();
    let db_path = fornax_home.join("fornax.db");
    let rollout_path = tmp.join("rollout.jsonl");
    let path_id = rollout_path.to_string_lossy().to_string();
    let native_id = "fx462-native-session";
    let (daemon_guard, daemon_log_path) = spawn_daemon(&fornax_home);

    let encode = |lines: &[serde_json::Value]| {
        let mut s = String::new();
        for l in lines {
            s.push_str(&l.to_string());
            s.push('\n');
        }
        s
    };

    // 1. A complete exec pair + claim, but no session_meta yet.
    let mut unidentified = pytest_success_exec_pair("fx462-pre-id-call");
    unidentified.push(task_complete_line("All tests passed."));
    std::fs::write(&rollout_path, encode(&unidentified)).expect("write rollout");

    let hook = Command::new(env!("CARGO_BIN_EXE_fornax-hook-codex"))
        .arg("--file")
        .arg(&rollout_path)
        .env("FORNAX_HOME", &fornax_home)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fornax-hook-codex");
    let _hook_guard = KillOnDrop(hook);

    // Several 500ms poll cycles: ample time for the hook to have read and
    // (wrongly) forwarded the unidentified lines if it were going to.
    std::thread::sleep(Duration::from_millis(3000));

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let stored_under = |id: &str| -> (usize, usize, usize) {
        rt.block_on(async {
            let store = fornax_store::Store::open(&db_path)
                .await
                .expect("open store");
            (
                store
                    .events_for_session(id)
                    .await
                    .map(|e| e.len())
                    .unwrap_or(0),
                store
                    .evidence_for_session(id)
                    .await
                    .map(|e| e.evidence.len())
                    .unwrap_or(0),
                store
                    .findings_for_session(id)
                    .await
                    .map(|f| f.len())
                    .unwrap_or(0),
            )
        })
    };
    assert_eq!(
        stored_under(&path_id),
        (0, 0, 0),
        "nothing may be stored under the rollout path as a session id"
    );
    let all_findings = rt.block_on(async {
        fornax_store::Store::open(&db_path)
            .await
            .expect("open store")
            .recent_findings(10)
            .await
            .expect("recent findings")
    });
    assert!(
        all_findings.is_empty(),
        "no finding may exist before an identity is known"
    );

    // 2. Control: the same live stream now learns its native id.
    let mut identified = vec![session_meta_line(native_id)];
    identified.extend(pytest_success_exec_pair("fx462-post-id-call"));
    identified.push(task_complete_line("All tests passed."));
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&rollout_path)
        .expect("open rollout for append");
    f.write_all(encode(&identified).as_bytes())
        .expect("append rollout");
    drop(f);

    let finding = poll_until(
        Duration::from_secs(8),
        "waiting for a Finding under the native session id",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                store
                    .findings_for_session(native_id)
                    .await
                    .ok()?
                    .into_iter()
                    .next()
            })
        },
    );
    // The tailer is still connected, so the daemon conservatively reports
    // `review` instead of a definite verdict (HORO-1712); this test is about
    // identity, not the verdict.
    assert!(
        matches!(finding.verdict.as_str(), "verified" | "review"),
        "unexpected verdict {}",
        finding.verdict
    );
    assert!(
        stored_under(native_id).0 > 0,
        "events after the native id are stored under it"
    );
    assert_eq!(
        stored_under(&path_id),
        (0, 0, 0),
        "still nothing under the rollout path once the native id is known"
    );

    drop(daemon_guard);
    std::fs::remove_dir_all(&tmp).ok();
}

/// FORNX-462 review finding: a tailer that has not (yet) learned a native id
/// must not hold a silent connection open, because the daemon then treats
/// every session's evidence as possibly incomplete and downgrades their
/// verdicts to `review`.
#[test]
fn a_tailer_without_a_native_id_does_not_downgrade_other_sessions() {
    let tmp = tempdir("silent-tailer");
    let fornax_home = tmp.clone();
    let db_path = fornax_home.join("fornax.db");
    let (daemon_guard, daemon_log_path) = spawn_daemon(&fornax_home);

    // Tailer A: a rollout whose only line carries no session id.
    let rollout_a = tmp.join("rollout-a.jsonl");
    std::fs::write(
        &rollout_a,
        "{\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\"}}\n",
    )
    .expect("write rollout a");
    let hook_a = Command::new(env!("CARGO_BIN_EXE_fornax-hook-codex"))
        .arg("--file")
        .arg(&rollout_a)
        .env("FORNAX_HOME", &fornax_home)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fornax-hook-codex A");
    let _hook_a_guard = KillOnDrop(hook_a);
    // Longer than the daemon's 1s drain budget for a silent connection.
    std::thread::sleep(Duration::from_millis(2500));

    // Session B, with a native id, while A is still running.
    let b_id = "fx462-session-b";
    let rollout_b = tmp.join("rollout-b.jsonl");
    let mut lines = vec![session_meta_line(b_id)];
    lines.extend(pytest_success_exec_pair("fx462-b-call"));
    lines.push(task_complete_line("All tests passed."));
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    run_hook_codex_over_rollout(&fornax_home, &rollout_b, &lines, || {
        rt.block_on(async {
            let store = match fornax_store::Store::open(&db_path).await {
                Ok(s) => s,
                Err(_) => return false,
            };
            matches!(store.evidence_for_session(b_id).await, Ok(e) if !e.evidence.is_empty())
        })
    });
    let finding = poll_until(
        Duration::from_secs(8),
        "waiting for session B's Finding",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                store
                    .findings_for_session(b_id)
                    .await
                    .ok()?
                    .into_iter()
                    .next()
            })
        },
    );
    assert_eq!(
        finding.verdict, "verified",
        "an unrelated tailer with no identity must not downgrade session B's verdict"
    );
    drop(daemon_guard);
    std::fs::remove_dir_all(&tmp).ok();
}

/// FORNX-462 review finding: if the daemon socket is down when `session_meta`
/// is read, the tailer must still learn the id from it, so that lines read
/// once the daemon is back are forwarded under that native id.
#[test]
fn the_native_id_is_learned_even_when_the_daemon_was_down_at_session_meta() {
    let tmp = tempdir("daemon-down-at-meta");
    let fornax_home = tmp.clone();
    let db_path = fornax_home.join("fornax.db");
    let rollout_path = tmp.join("rollout.jsonl");
    let native_id = "fx462-late-daemon-session";

    // The rollout (with session_meta) exists and is read before any daemon runs.
    let mut first = vec![session_meta_line(native_id)];
    first.extend(pytest_success_exec_pair("fx462-before-daemon"));
    let mut content = String::new();
    for l in &first {
        content.push_str(&l.to_string());
        content.push('\n');
    }
    std::fs::write(&rollout_path, content).expect("write rollout");
    let hook = Command::new(env!("CARGO_BIN_EXE_fornax-hook-codex"))
        .arg("--file")
        .arg(&rollout_path)
        .env("FORNAX_HOME", &fornax_home)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn fornax-hook-codex");
    let _hook_guard = KillOnDrop(hook);
    std::thread::sleep(Duration::from_millis(1500));

    let (daemon_guard, daemon_log_path) = spawn_daemon(&fornax_home);

    // New lines arrive once the daemon is up.
    use std::io::Write;
    let mut more = pytest_success_exec_pair("fx462-after-daemon");
    more.push(task_complete_line("All tests passed."));
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&rollout_path)
        .expect("open rollout for append");
    for l in &more {
        writeln!(f, "{l}").expect("append");
    }
    drop(f);

    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    poll_until(
        Duration::from_secs(8),
        "waiting for evidence under the native id after the daemon came up",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                let e = store.evidence_for_session(native_id).await.ok()?;
                (!e.evidence.is_empty()).then_some(())
            })
        },
    );
    drop(daemon_guard);
    std::fs::remove_dir_all(&tmp).ok();
}
