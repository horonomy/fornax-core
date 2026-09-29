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

use std::net::TcpListener;
use std::process::Command;

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
