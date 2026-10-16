//! Exercises `protocol::Session` over a real OS pipe/real child process
//! boundary (not just an in-memory `Cursor`, which `src/protocol.rs`'s own
//! unit tests already cover) -- every negative mode internal-docs
//! ADR-0015 requires (app-server unreachable, RPC timeout, malformed/
//! truncated response) plus a few more. Runs on every platform; this
//! layer never touches a sandbox or a real Codex binary, only the shim at
//! `tests/fixtures/fake-codex.sh`. Test code is allowed to use `Command`
//! directly -- there is no spawn-confinement rule for test code, only for
//! `src/launch.rs` (see `tests/boundary_invariants.rs`).

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fornax_host_trust_exec::protocol::{ClientMessage, ProtocolError, Session};

fn shim_path() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/fake-codex.sh"
    ))
}

fn spawn_shim(mode: &str) -> (Child, Session) {
    let mut child = Command::new(shim_path())
        .arg(mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("shim must spawn");
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let session = Session::new(Box::new(stdin), Box::new(stdout));
    (child, session)
}

fn deadline(secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(secs)
}

#[test]
fn positive_handshake_and_hooks_list() {
    let (mut child, mut session) = spawn_shim("positive");
    session.send(&ClientMessage::Initialize).unwrap();
    let init = session.recv_response(0, deadline(5)).unwrap();
    assert!(init["codexHome"].as_str().unwrap().ends_with("/.codex"));
    session.send(&ClientMessage::Initialized).unwrap();
    session
        .send(&ClientMessage::HooksList {
            cwd: PathBuf::from("/isolated"),
        })
        .unwrap();
    let hooks = session.recv_response(1, deadline(5)).unwrap();
    assert!(hooks["data"].is_array());
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn hang_times_out() {
    let (mut child, mut session) = spawn_shim("hang");
    session.send(&ClientMessage::Initialize).unwrap();
    let err = session
        .recv_response(0, Instant::now() + Duration::from_millis(300))
        .unwrap_err();
    assert_eq!(err, ProtocolError::Timeout);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn exit_immediately_is_host_unreachable() {
    let (mut child, mut session) = spawn_shim("exit_immediately");
    session.send(&ClientMessage::Initialize).unwrap();
    let err = session.recv_response(0, deadline(5)).unwrap_err();
    assert_eq!(err, ProtocolError::HostUnreachable);
    let _ = child.wait();
}

#[test]
fn malformed_line_fails_closed() {
    let (mut child, mut session) = spawn_shim("malformed");
    session.send(&ClientMessage::Initialize).unwrap();
    let err = session.recv_response(0, deadline(5)).unwrap_err();
    matches!(err, ProtocolError::HostResponseMalformed(_))
        .then_some(())
        .expect("malformed peer output must fail closed, not be silently ignored");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn truncated_response_fails_closed() {
    let (mut child, mut session) = spawn_shim("truncated");
    session.send(&ClientMessage::Initialize).unwrap();
    let err = session.recv_response(0, deadline(5)).unwrap_err();
    matches!(err, ProtocolError::HostResponseMalformed(_))
        .then_some(())
        .expect("a truncated response must never be silently accepted as complete");
    let _ = child.wait();
}

#[test]
fn oversized_response_fails_closed() {
    let (mut child, mut session) = spawn_shim("oversized");
    session.send(&ClientMessage::Initialize).unwrap();
    let err = session.recv_response(0, deadline(5)).unwrap_err();
    matches!(err, ProtocolError::HostResponseMalformed(_))
        .then_some(())
        .expect("an oversized line must be refused, never buffered without bound");
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn rpc_error_member_is_surfaced_not_swallowed() {
    let (mut child, mut session) = spawn_shim("rpc_error");
    session.send(&ClientMessage::Initialize).unwrap();
    let err = session.recv_response(0, deadline(5)).unwrap_err();
    assert_eq!(
        err,
        ProtocolError::HostRpcError {
            code: Some(-32601),
            message: "no such method".into()
        }
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn interleaved_notification_is_skipped_not_mistaken_for_the_response() {
    let (mut child, mut session) = spawn_shim("interleaved");
    session.send(&ClientMessage::Initialize).unwrap();
    let init = session.recv_response(0, deadline(5)).unwrap();
    assert_eq!(init["codexHome"], "/isolated");
    let _ = child.kill();
    let _ = child.wait();
}
