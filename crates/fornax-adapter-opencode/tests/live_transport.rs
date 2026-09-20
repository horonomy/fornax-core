//! FORNX-291: automated regression for the real
//! plugin (`fornax-capture.js`) -> binary (`fornax-hook-opencode`) ->
//! daemon (`fornax-daemon`, over a real Unix domain socket) transport leg.
//!
//! Everything in this test is genuine, unstubbed code on the Fornax side:
//! a real `fornax-daemon` process, a real `fornax-hook-opencode` process it
//! spawns via `node`, and the real `plugin/fornax-capture.js` file loaded
//! and invoked by that `node` process exactly as opencode's own runtime
//! would invoke it (`spawn()` + NDJSON over stdin). The one thing stood in
//! for is opencode's own runtime itself -- opencode is not installed in CI,
//! so this test drives the plugin's exported `Hooks` directly with
//! payload shapes matching the real fixtures captured from a live opencode
//! session in FORNX-161 (`fornax-adapter-conformance/fixtures/opencode/`),
//! rather than running the actual opencode binary. A full, actually-live
//! opencode session (real opencode CLI + a deterministic HTTP stub for the
//! LLM turn only) was run manually to prove this same pipeline end-to-end
//! against genuine opencode-driven hook invocations -- see FORNX-291's Jira
//! comment/PR description for that evidence; this test is the automated,
//! CI-safe regression for the part of the leg that doesn't require
//! installing opencode.
//!
//! Requires `node` on PATH (present on GitHub's `ubuntu-latest` runners
//! without any extra setup step).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Walk up from the test binary's own path to find `target/<profile>/`,
/// then resolve a sibling workspace binary by name. `env!("CARGO_BIN_EXE_*")`
/// only resolves binaries that live in *this* crate (`fornax-hook-opencode`
/// does; `fornax-daemon` does not), so `fornax-daemon` must be found this
/// way instead.
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

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn plugin_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("plugin/fornax-capture.js")
}

/// The Node harness that drives the *real* plugin file exactly the way
/// opencode's runtime does: import the default export, call the returned
/// hooks in the real session-lifecycle order, then `dispose()`. Payload
/// shapes mirror the real captures in
/// `fornax-adapter-conformance/fixtures/opencode/` (FORNX-161). Written as a
/// real `.mjs` file rather than inlined via `node -e`, since `node -e`
/// cannot cleanly load a real ES module `import`.
fn write_harness(dir: &Path, session_id: &str) -> PathBuf {
    let plugin = plugin_path();
    let plugin_url = format!("file://{}", plugin.display());
    let script = format!(
        r#"
import {{ FornaxCapture }} from "{plugin_url}";

const plugin = await FornaxCapture();

await plugin.event({{
  event: {{
    type: "session.created",
    properties: {{ sessionID: "{session_id}", info: {{ id: "{session_id}" }} }},
  }},
}});

await plugin["tool.execute.before"](
  {{ tool: "bash", sessionID: "{session_id}", callID: "call_1" }},
  {{ args: {{ command: "ls -la .", description: "List files in the current directory" }} }},
);

await plugin["tool.execute.after"](
  {{
    tool: "bash",
    sessionID: "{session_id}",
    callID: "call_1",
    args: {{ command: "ls -la ." }},
  }},
  {{
    title: "ls -la .",
    metadata: {{ output: "total 0\n", exit: 0, truncated: false }},
    output: "total 0\n",
  }},
);

await plugin.event({{
  event: {{ type: "session.idle", properties: {{ sessionID: "{session_id}" }} }},
}});

await plugin.dispose();
"#
    );
    let path = dir.join("harness.mjs");
    std::fs::write(&path, script).expect("write harness.mjs");
    path
}

/// Polls `f` until it returns `Some`, up to `timeout` -- this pipeline has
/// no ack anywhere by design (see `fornax-daemon`'s ingest loop), so a fixed
/// sleep-and-hope would be both slow and flaky. On timeout, calls
/// `diagnostics` for context (e.g. the daemon's own stderr) rather than
/// failing with a bare "didn't happen in time".
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

/// Best-effort tail of a log file for panic diagnostics -- never itself a
/// source of test failure if the file is missing or unreadable.
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

#[test]
fn plugin_binary_daemon_pipeline_delivers_real_evidence() {
    if Command::new("node").arg("--version").output().is_err() {
        panic!(
            "`node` is required for this test (drives the real fornax-capture.js plugin file) \
             but was not found on PATH"
        );
    }

    let daemon_bin = sibling_workspace_bin("fornax-daemon");
    let hook_bin = env!("CARGO_BIN_EXE_fornax-hook-opencode");
    let hook_dir = Path::new(hook_bin)
        .parent()
        .expect("hook bin has parent dir");

    let tmp = tempdir();
    // The daemon binds a real Unix domain socket directly under
    // `FORNAX_HOME` -- no extra subdirectory, to keep the socket path well
    // under macOS's short `sockaddr_un` limit (see `tempdir()`'s doc
    // comment).
    let fornax_home = tmp.clone();
    let http_port = free_tcp_port();
    let sock_path = fornax_home.join("fornax.sock");
    let db_path = fornax_home.join("fornax.db");
    let daemon_log_path = tmp.join("daemon.log");
    let daemon_log = std::fs::File::create(&daemon_log_path).expect("create daemon.log");

    let daemon = Command::new(&daemon_bin)
        .env("FORNAX_HOME", &fornax_home)
        .env("FORNAX_HTTP_PORT", http_port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(daemon_log)
        .spawn()
        .expect("spawn fornax-daemon");

    // Best-effort cleanup even if an assertion below panics.
    struct KillOnDrop(std::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut daemon_guard = KillOnDrop(daemon);

    poll_until(
        Duration::from_secs(5),
        "waiting for daemon UDS socket to be created",
        || tail_log(&daemon_log_path),
        || sock_path.exists().then_some(()),
    );

    let session_id = format!("fornx-291-live-{}", std::process::id());
    let harness = write_harness(&tmp, &session_id);

    let path_env = format!(
        "{}:{}",
        hook_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let node_status = Command::new("node")
        .arg(&harness)
        .env("PATH", path_env)
        .env("FORNAX_HOME", &fornax_home)
        .status()
        .expect("run node harness");
    assert!(node_status.success(), "node harness exited non-zero");

    // Poll the actual on-disk SQLite store -- the same store the daemon
    // itself reads/writes -- rather than trusting the plugin's own exit
    // code. The plugin/hook sends four messages (session.created,
    // tool.execute.before, tool.execute.after, session.idle) over a
    // fire-and-forget socket with no ack, and the daemon ingests them one at
    // a time, so the store can legitimately contain a partial prefix (e.g.
    // only `SessionStart`, or all three events but not yet the evidence
    // derived from `PostToolUse`) for a little while after the harness
    // process exits. Waiting for merely a *non-empty* event list races that
    // ingestion: on a loaded runner it can observe the store between
    // messages rather than after all of them have landed. Wait for the
    // exact end state the assertions below check instead, so `poll_until`
    // keeps polling until the daemon has actually finished, rather than
    // stopping at the first sign of partial progress.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let (events, evidence) = poll_until(
        Duration::from_secs(5),
        "waiting for the daemon to persist the real session's events and evidence",
        || tail_log(&daemon_log_path),
        || {
            rt.block_on(async {
                let store = fornax_store::Store::open(&db_path).await.ok()?;
                let events = store.events_for_session(&session_id).await.ok()?;
                let evidence = store.evidence_for_session(&session_id).await.ok()?.evidence;
                let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
                let has_all_events = kinds.contains(&fornax_types::EventKind::SessionStart)
                    && kinds.contains(&fornax_types::EventKind::PreToolUse)
                    && kinds.contains(&fornax_types::EventKind::PostToolUse);
                if has_all_events && !evidence.is_empty() {
                    Some((events, evidence))
                } else {
                    None
                }
            })
        },
    );

    daemon_guard.0.kill().ok();

    let kinds: Vec<_> = events.iter().map(|e| e.kind).collect();
    assert!(
        kinds.contains(&fornax_types::EventKind::SessionStart),
        "expected a SessionStart event reached the daemon, got {kinds:?}"
    );
    assert!(
        kinds.contains(&fornax_types::EventKind::PreToolUse),
        "expected a PreToolUse event reached the daemon, got {kinds:?}"
    );
    assert!(
        kinds.contains(&fornax_types::EventKind::PostToolUse),
        "expected a PostToolUse event reached the daemon, got {kinds:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.tool_name.as_deref() == Some("bash")),
        "expected a bash tool event, got {events:?}"
    );
    assert!(
        !evidence.is_empty(),
        "expected the real exit-code sensor to have produced Evidence"
    );
    assert_eq!(
        evidence[0].payload["exit_code"], 0,
        "expected the real ls -la exit code (0) to have reached storage"
    );
}

/// Deliberately short and under `/tmp` directly rather than
/// `std::env::temp_dir()` (which resolves to a long `/var/folders/...` path
/// via `TMPDIR` on macOS): the daemon binds a real Unix domain socket
/// inside this directory, and `sockaddr_un` has a short, fixed-size path
/// buffer (`SUN_LEN`, ~104 bytes on macOS) -- a descriptive-but-long temp
/// path reliably overflows it and fails the bind with a confusing error.
fn tempdir() -> PathBuf {
    let dir = PathBuf::from("/tmp").join(format!("fx291-{:x}", std::process::id()));
    // A PID can be reused across separate test runs (e.g. re-run after a
    // crash) and this directory is not otherwise cleaned up -- wipe any
    // leftover `fornax.db`/`fornax.sock` first so a stale DB from a
    // previous run can never make this test pass against old data while
    // the real transport leg is actually broken.
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).expect("mkdir tempdir");
    dir
}
