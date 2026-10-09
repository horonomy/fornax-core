//! End-to-end test for `fornax statusline` (HORO-1567) against the real
//! compiled binary.
//!
//! The unit tests in `statusline.rs` cover what the payload *says*. These
//! cover what the process *does*, which is the half that can break someone
//! else's statusline: the host runs this binary on every refresh, reads its
//! stdout, and composes the result after the user's own line. So the
//! properties asserted here are process properties — exit status, stdout
//! shape, stderr silence, and leaving the filesystem alone — and they are
//! asserted in the state that actually breaks things, with no daemon running.
//!
//! The other half of the coexistence guarantee — that enabling Fornax leaves
//! a custom user statusline and other products' registrations intact — is a
//! property of the shared host, is tested there against a real custom script,
//! and is deliberately not duplicated (or silently skipped) here.

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use uuid::Uuid;

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

/// A port with nothing listening on it: bound to prove it is free, then
/// released. Hardcoding one would make this test fail for whoever happens to
/// be running something there.
fn closed_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// A port where something is listening but will never answer: a daemon that
/// is up and hung, rather than stopped.
///
/// The accepted connection is held open on purpose. Dropping it would close
/// the socket, and a closed socket is a refusal — which is the other case
/// entirely, and already covered.
fn hung_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(30));
                drop(stream);
            });
        }
    });
    port
}

fn temp_home(label: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("fornax-statusline-e2e-{label}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    path
}

struct Run {
    stdout: String,
    stderr: String,
    status: std::process::ExitStatus,
}

fn run(subcommand: &str, home: &std::path::Path, port: u16) -> Run {
    let out = Command::new(fornax_bin())
        .args(["statusline", subcommand])
        .env("FORNAX_HOME", home)
        .env("FORNAX_HTTP_PORT", port.to_string())
        .output()
        .unwrap();
    Run {
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
        status: out.status,
    }
}

#[test]
fn the_provider_exits_zero_with_a_payload_when_no_daemon_is_running() {
    // A non-zero exit would make "Fornax is stopped" indistinguishable from
    // "the provider is broken", and the payload already says which it is.
    let home = temp_home("no-daemon");
    let run = run("provider", &home, closed_port());
    assert!(run.status.success(), "exit {:?}", run.status.code());

    let payload: serde_json::Value = serde_json::from_str(run.stdout.trim())
        .unwrap_or_else(|e| panic!("stdout was not a payload: {e}\n{}", run.stdout));
    assert_eq!(payload["availability"], "unavailable");
    assert_eq!(payload["provider"], "fornax");
    assert_eq!(payload["scope"], "host");

    // Still says something, and never says everything is fine: an empty
    // answer renders as silence and silence reads as "all clear".
    let segments = payload["segments"].as_array().unwrap();
    assert_eq!(segments.len(), 1);
    assert_eq!(segments[0]["reason_code"], "daemon_unreachable");
    assert_ne!(segments[0]["state"], "ok");
}

#[test]
fn the_provider_writes_nothing_to_stderr() {
    // Claude Code runs the slot command with its stderr inherited, so noise
    // here can land in the user's terminal — including, on a bad day, an
    // error string carrying a $FORNAX_HOME path.
    let home = temp_home("stderr");
    let run = run("provider", &home, closed_port());
    assert_eq!(run.stderr, "", "provider wrote to stderr");
}

#[test]
fn the_provider_creates_nothing_and_modifies_nothing() {
    // This is a read-only surface, on the hot path, in someone's home
    // directory. Creating a cache or a lock file here would be a write per
    // statusline refresh.
    let home = temp_home("read-only");
    let before = std::fs::read_dir(&home).unwrap().count();
    run("provider", &home, closed_port());
    run("explain", &home, closed_port());
    let after: Vec<_> = std::fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(before, 0);
    assert!(after.is_empty(), "created {after:?}");
}

#[test]
fn the_explain_surface_names_a_next_step_when_there_is_nothing_to_read() {
    // A diagnostic that reports a state without reporting what to do about it
    // sends the user looking for a bug in the wrong place.
    let home = temp_home("explain");
    let run = run("explain", &home, closed_port());
    assert!(run.status.success());
    assert!(
        run.stdout.contains("No Fornax daemon answered"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("Start it"), "{}", run.stdout);
}

#[test]
fn no_failure_output_reveals_the_home_directory_or_the_port() {
    // Both are in the environment of every invocation, both appear in this
    // codebase's error strings, and both are rendered straight into the
    // user's terminal.
    let home = temp_home("no-leak");
    let port = closed_port();
    let home_name = home.file_name().unwrap().to_str().unwrap().to_string();
    for subcommand in ["provider", "explain"] {
        let run = run(subcommand, &home, port);
        let all = format!("{}{}", run.stdout, run.stderr);
        assert!(
            !all.contains(&home_name),
            "{subcommand} leaked the home path"
        );
        assert!(
            !all.contains(&port.to_string()),
            "{subcommand} leaked the port"
        );
    }
}

#[test]
fn a_hung_daemon_is_bounded_and_is_not_reported_as_a_stopped_one() {
    // The provider runs on every statusline refresh. Without its own budget
    // it would wait here until the host killed it, contributing nothing at
    // all -- and calling a listening daemon "Not running" would send the
    // reader to start one that is already up.
    let home = temp_home("hung");
    let started = Instant::now();
    let run = run("provider", &home, hung_port());
    let elapsed = started.elapsed();

    assert!(run.status.success(), "exit {:?}", run.status.code());
    assert_eq!(run.stderr, "");
    let payload: serde_json::Value = serde_json::from_str(run.stdout.trim())
        .unwrap_or_else(|e| panic!("stdout was not a payload: {e}\n{}", run.stdout));
    assert_eq!(payload["availability"], "unknown");
    let segments = payload["segments"].as_array().unwrap();
    assert_eq!(segments[0]["reason_code"], "daemon_too_slow");
    assert_ne!(segments[0]["state"], "ok");

    // The socket holds the connection for 30s. Returning at all proves the
    // budget bit; the generous bound leaves room for macOS's one-time
    // first-exec cost on a freshly built binary.
    assert!(elapsed < Duration::from_secs(5), "took {elapsed:?}");
}

/// Feeds a real, well-formed identity-stdin document to the real process on
/// its real stdin (HORO-1601/1602/1604 anti-vacuity: "raw provider/session
/// ID printed to statusline"). `read_identity_stdin()` runs unconditionally
/// before the daemon probe, so this exercises the actual parse-then-render
/// path end to end -- not just `parse_identity_document`'s own unit tests,
/// which never go through a real pipe, and not just `reading()`'s unit
/// tests, which start from a hand-built daemon response rather than a real
/// resolved session id flowing in from stdin.
fn run_with_stdin(subcommand: &str, home: &std::path::Path, port: u16, stdin_bytes: &[u8]) -> Run {
    let mut child = Command::new(fornax_bin())
        .args(["statusline", subcommand])
        .env("FORNAX_HOME", home)
        .env("FORNAX_HTTP_PORT", port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin_bytes).unwrap();
    let out = child.wait_with_output().unwrap();
    Run {
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
        status: out.status,
    }
}

/// Starts a fake daemon that answers `/api/status` with a correctly-identified,
/// session-scoped reading and lets every other path (`/api/fusion` included)
/// fall through to a plain error response.
///
/// `closed_port()` alone only proves the leak-free property when the daemon
/// is unreachable, which steers every call through `no_reading`/
/// `explain_unavailable` -- neither of which takes a session id. Only a
/// *successful* probe reaches `reading()` and, for `explain`, `explain_text()`,
/// which is the one function that actually receives the resolved session id
/// as a parameter (HORO-1604 adversarial review: a raw-session-id
/// interpolation into `explain_text`'s header survived the closed-port test
/// untouched). This stub exists to make that path real.
fn spawn_stub_daemon(
    home: &std::path::Path,
    session_id: &str,
) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let identity = fornax_types::home_identity(home);
    let session_id = session_id.to_string();
    let seen_requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_requests_bg = seen_requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle_stub_connection(stream, &identity, &session_id, &seen_requests_bg);
        }
    });
    (port, seen_requests)
}

fn handle_stub_connection(
    mut stream: std::net::TcpStream,
    identity: &str,
    session_id: &str,
    seen_requests: &std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    use std::io::BufRead;

    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) if line == "\r\n" || line == "\n" => break,
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    seen_requests
        .lock()
        .unwrap()
        .push(request_line.trim().to_string());

    let body = if request_line.contains("/api/status") {
        serde_json::json!({
            "latest": {
                "verdict": "verified",
                "computed_at": "2026-01-01T00:00:00Z",
                "claim_id": "stub-claim",
                "session_id": session_id,
            },
            "session_scoped": true,
        })
        .to_string()
    } else {
        // `probe_fusion` collapses every failure to `None`; an unrecognized
        // path answering with an error body is enough to exercise that, and
        // nothing in this test depends on the fusion surface.
        serde_json::json!({"error": "not found"}).to_string()
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nx-fornax-home-id: {identity}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
}

#[test]
fn a_real_session_id_never_leaks_through_a_successful_daemon_response_either() {
    let home = temp_home("identity-no-leak-success");
    let session_id = format!("claude-sess-{}", Uuid::new_v4());
    let identity_doc = serde_json::json!({
        "identity_stdin_version": 1,
        "provider_session_id": session_id,
        "host_capabilities": ["segment_scope"],
    });
    let (port, _seen) = spawn_stub_daemon(&home, &session_id);

    for subcommand in ["provider", "explain"] {
        let run = run_with_stdin(subcommand, &home, port, identity_doc.to_string().as_bytes());
        assert!(run.status.success(), "exit {:?}", run.status.code());
        assert!(
            !run.stdout.contains(&session_id),
            "{subcommand} leaked the session id into stdout on a successful probe: {}",
            run.stdout
        );
        assert!(
            !run.stderr.contains(&session_id),
            "{subcommand} leaked the session id into stderr on a successful probe: {}",
            run.stderr
        );
    }
}

/// Anti-vacuity guard: "guessed session ID derived from cwd/PID/tmux". With
/// no identity document on stdin at all, the real outbound request to the
/// daemon must carry no `session` query parameter -- proving nothing derived
/// from this process's own PID, cwd, or any other local guess ever gets
/// substituted for the absent, host-supplied identity. A text-only assertion
/// on stdout/stderr would miss a guess that never gets printed but still
/// gets sent to the daemon and silently narrows the query.
#[test]
fn no_identity_on_stdin_means_no_guessed_session_is_ever_sent_to_the_daemon() {
    let home = temp_home("no-identity-no-guess");
    let session_id = format!("claude-sess-{}", Uuid::new_v4());
    let (port, seen_requests) = spawn_stub_daemon(&home, &session_id);
    let pid = std::process::id().to_string();

    for subcommand in ["provider", "explain"] {
        // Empty stdin: `read_identity_stdin()` sees zero bytes and must
        // resolve to `None`, not fall back to a local guess.
        let run = run_with_stdin(subcommand, &home, port, b"");
        assert!(run.status.success(), "exit {:?}", run.status.code());
        assert!(
            !run.stdout.contains(&pid),
            "{subcommand} leaked this process's own pid into stdout: {}",
            run.stdout
        );
    }

    let requests = seen_requests.lock().unwrap();
    let status_requests: Vec<&String> = requests
        .iter()
        .filter(|r| r.contains("/api/status"))
        .collect();
    assert_eq!(
        status_requests.len(),
        2,
        "expected one /api/status request per subcommand, saw: {requests:?}"
    );
    for request_line in status_requests {
        assert!(
            !request_line.contains("session="),
            "a session query parameter was sent to the daemon with no identity document on stdin: {request_line}"
        );
    }
}

#[test]
fn a_real_session_id_piped_on_stdin_never_reaches_stdout_or_stderr() {
    let home = temp_home("identity-no-leak");
    let session_id = format!("claude-sess-{}", Uuid::new_v4());
    let identity_doc = serde_json::json!({
        "identity_stdin_version": 1,
        "provider_session_id": session_id,
        "host_capabilities": ["segment_scope"],
    });
    for subcommand in ["provider", "explain"] {
        let run = run_with_stdin(
            subcommand,
            &home,
            closed_port(),
            identity_doc.to_string().as_bytes(),
        );
        assert!(run.status.success(), "exit {:?}", run.status.code());
        assert!(
            !run.stdout.contains(&session_id),
            "{subcommand} leaked the session id into stdout: {}",
            run.stdout
        );
        assert!(
            !run.stderr.contains(&session_id),
            "{subcommand} leaked the session id into stderr: {}",
            run.stderr
        );
    }
}
