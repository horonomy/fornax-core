//! NDJSON JSON-RPC framing for talking to `codex app-server` over stdio.
//!
//! Confirmed live against `codex-cli` 0.160.0: one JSON object per line
//! (not LSP's `Content-Length`-prefixed framing). The handshake is
//! `initialize` (id 0) -> `initialized` notification -> `hooks/list`
//! (id 1). The server also sends unprompted notifications (e.g.
//! `remoteControl/status/changed`), which this module must skip without
//! treating them as a protocol violation.
//!
//! This module never spawns a process. It operates over whatever
//! `Read`/`Write` pair it is handed, which is what makes
//! `tests/session_streams.rs` able to exercise every failure mode (hang,
//! malformed, truncated, oversized, wrong id, interleaved notifications)
//! without a sandbox or a real Codex binary — the test spawns its own
//! shim and hands this module the pipes.

use std::collections::VecDeque;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Hard bound on a single NDJSON line, independent of the overall deadline.
/// A well-behaved `codex app-server` response is a few KiB; this exists to
/// stop a hostile/broken peer from exhausting memory.
pub const MAX_LINE_BYTES: usize = 1024 * 1024;
/// Hard bound on total bytes read for one `Session`'s lifetime.
pub const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// The client's entire outgoing vocabulary. Deliberately not a generic
/// `method: &str` + `params: Value` API -- this closed enum is how
/// internal-docs ADR-0015 R4/R5 (no trust/activation side effect, no
/// unapproved mutation) are enforced structurally: there is no way to
/// construct a `thread/*` or `turn/*` call, or anything else that could
/// cause Codex to run a hook or spend a model call, because no such
/// variant exists. `tests/boundary_invariants.rs`'s
/// `protocol_can_only_emit_allowlisted_methods` pins this enum's method
/// set so a future edit can't silently widen it.
#[derive(Debug, Clone)]
pub enum ClientMessage {
    /// id 0.
    Initialize,
    /// Notification; no id, no response expected.
    Initialized,
    /// id 1.
    HooksList { cwd: PathBuf },
}

impl ClientMessage {
    pub fn method(&self) -> &'static str {
        match self {
            ClientMessage::Initialize => "initialize",
            ClientMessage::Initialized => "initialized",
            ClientMessage::HooksList { .. } => "hooks/list",
        }
    }

    fn id(&self) -> Option<u64> {
        match self {
            ClientMessage::Initialize => Some(0),
            ClientMessage::Initialized => None,
            ClientMessage::HooksList { .. } => Some(1),
        }
    }

    fn to_line(&self) -> String {
        let method = self.method();
        let mut obj = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
        });
        match self {
            ClientMessage::Initialize => {
                obj["params"] = serde_json::json!({
                    "clientInfo": {"name": "fornax-host-trust-exec", "version": env!("CARGO_PKG_VERSION")},
                });
            }
            ClientMessage::Initialized => {}
            ClientMessage::HooksList { cwd } => {
                obj["params"] = serde_json::json!({ "cwds": [cwd] });
            }
        }
        if let Some(id) = self.id() {
            obj["id"] = serde_json::json!(id);
        }
        obj.to_string()
    }
}

/// A parsed `initialize` result. Only the fields this crate cross-checks
/// are named; everything else Codex sends is ignored (no
/// `deny_unknown_fields` -- Codex may add fields across versions, which
/// must never turn into a parse failure here).
#[derive(Debug, Clone, Deserialize)]
pub struct InitializeResult {
    #[serde(rename = "codexHome")]
    pub codex_home: PathBuf,
    #[serde(rename = "userAgent")]
    pub user_agent: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HooksListHook {
    pub key: String,
    #[serde(rename = "eventName")]
    pub event_name: String,
    pub command: String,
    #[serde(rename = "sourcePath")]
    pub source_path: PathBuf,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(rename = "currentHash")]
    pub current_hash: String,
    #[serde(rename = "trustStatus")]
    pub trust_status: String,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct HooksListEntry {
    #[serde(default)]
    pub hooks: Vec<HooksListHook>,
    #[serde(default)]
    pub errors: Vec<Value>,
    #[serde(default)]
    pub warnings: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HooksListResult {
    pub data: Vec<HooksListEntry>,
}

/// Every way a round-trip can fail. Each variant is a reason code by
/// another name -- `verdict.rs` maps these onto the aggregate verdict, but
/// never upgrades any of them to `trusted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolError {
    /// EOF before any usable response -- the peer is gone or never answered.
    HostUnreachable,
    /// Deadline elapsed waiting for the expected response.
    Timeout,
    /// A line parsed as JSON but not into the expected shape, or the
    /// stream ended mid-line.
    HostResponseMalformed(String),
    /// The peer returned a JSON-RPC `error` member.
    HostRpcError { code: Option<i64>, message: String },
}

enum ReaderEvent {
    Line(Value),
    Eof { had_partial: bool },
    Overflow,
    Io(String),
}

/// One JSON-RPC session over a pair of pipes. Never spawns anything --
/// the caller (`launch.rs` in production, a test harness in
/// `tests/session_streams.rs`) owns process lifetime entirely.
pub struct Session {
    stdin: Box<dyn Write + Send>,
    rx: mpsc::Receiver<ReaderEvent>,
    pending: VecDeque<Value>,
}

impl Session {
    /// `stdout` is consumed by a dedicated reader thread immediately; the
    /// caller must not read from it afterward.
    pub fn new(stdin: Box<dyn Write + Send>, stdout: Box<dyn Read + Send>) -> Self {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || reader_loop(stdout, tx));
        Session {
            stdin,
            rx,
            pending: VecDeque::new(),
        }
    }

    pub fn send(&mut self, msg: &ClientMessage) -> std::io::Result<()> {
        let mut line = msg.to_line();
        line.push('\n');
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.flush()
    }

    /// Closes stdin. Codex's app-server exits without answering on EOF, so
    /// this must only be called after every expected response has been
    /// received (or the caller has given up).
    pub fn close_stdin(&mut self) {
        // Dropping replaces `stdin` with a no-op sink; the real pipe's
        // Drop impl closes the fd.
        self.stdin = Box::new(std::io::sink());
    }

    /// Waits for a response/error with the given id, skipping and
    /// discarding any notification (a message carrying `method`) seen
    /// along the way. Returns the raw `Value` so the caller deserializes
    /// into the shape it expects (`InitializeResult`, `HooksListResult`).
    pub fn recv_response(
        &mut self,
        expected_id: u64,
        deadline: Instant,
    ) -> Result<Value, ProtocolError> {
        loop {
            if let Some(msg) = self.take_matching(expected_id) {
                return extract_result(msg);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProtocolError::Timeout);
            }
            match self.rx.recv_timeout(remaining) {
                Ok(ReaderEvent::Line(v)) => {
                    if v.get("method").is_some() {
                        continue; // notification or server->client request
                    }
                    if v.get("id") == Some(&serde_json::json!(expected_id)) {
                        return extract_result(v);
                    }
                    self.pending.push_back(v);
                }
                Ok(ReaderEvent::Eof { had_partial }) => {
                    return Err(if had_partial {
                        ProtocolError::HostResponseMalformed("truncated at EOF".into())
                    } else {
                        ProtocolError::HostUnreachable
                    });
                }
                Ok(ReaderEvent::Overflow) => {
                    return Err(ProtocolError::HostResponseMalformed(
                        "stream exceeded size bound".into(),
                    ));
                }
                Ok(ReaderEvent::Io(e)) => {
                    return Err(ProtocolError::HostResponseMalformed(format!(
                        "io error: {e}"
                    )));
                }
                Err(mpsc::RecvTimeoutError::Timeout) => return Err(ProtocolError::Timeout),
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(ProtocolError::HostUnreachable)
                }
            }
        }
    }

    fn take_matching(&mut self, expected_id: u64) -> Option<Value> {
        let pos = self
            .pending
            .iter()
            .position(|v| v.get("id") == Some(&serde_json::json!(expected_id)));
        pos.map(|i| self.pending.remove(i).unwrap())
    }
}

fn extract_result(v: Value) -> Result<Value, ProtocolError> {
    if let Some(err) = v.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64());
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("<no message>")
            .to_string();
        return Err(ProtocolError::HostRpcError { code, message });
    }
    v.get("result").cloned().ok_or_else(|| {
        ProtocolError::HostResponseMalformed("response has neither result nor error".into())
    })
}

fn reader_loop(stdout: Box<dyn Read + Send>, tx: mpsc::Sender<ReaderEvent>) {
    let mut reader = BufReader::new(stdout);
    let mut total: usize = 0;
    loop {
        let mut line = Vec::new();
        let mut had_any_byte_this_line = false;
        loop {
            let mut byte = [0u8; 1];
            match reader.read(&mut byte) {
                Ok(0) => {
                    let _ = tx.send(ReaderEvent::Eof {
                        had_partial: had_any_byte_this_line,
                    });
                    return;
                }
                Ok(_) => {
                    had_any_byte_this_line = true;
                    if byte[0] == b'\n' {
                        break;
                    }
                    line.push(byte[0]);
                    total += 1;
                    if line.len() > MAX_LINE_BYTES || total > MAX_TOTAL_BYTES {
                        let _ = tx.send(ReaderEvent::Overflow);
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(ReaderEvent::Io(e.to_string()));
                    return;
                }
            }
        }
        if line.is_empty() {
            continue; // tolerate blank lines
        }
        match serde_json::from_slice::<Value>(&line) {
            Ok(v) => {
                if tx.send(ReaderEvent::Line(v)).is_err() {
                    return; // receiver gone
                }
            }
            Err(_) => {
                let _ = tx.send(ReaderEvent::Overflow); // malformed, same closed handling
                return;
            }
        }
    }
}

/// `currentHash` must be exactly `sha256:<64 lowercase hex>`. Taken
/// verbatim from Codex, never recomputed (R7) -- this only validates shape,
/// it never participates in computing the hash itself.
pub fn looks_like_sha256_digest(s: &str) -> bool {
    match s.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }
        None => false,
    }
}

/// Canonicalizes `event_name` (camelCase, as Codex's RPC sends it) and the
/// snake_case spelling used inside a hooks.json/`key` field to one shared
/// form, so the two can be compared without caring which spelling a given
/// field used.
pub fn canonical_event_name(name: &str) -> Option<&'static str> {
    match name {
        "preToolUse" | "pre_tool_use" => Some("pre_tool_use"),
        "postToolUse" | "post_tool_use" => Some("post_tool_use"),
        "sessionStart" | "session_start" => Some("session_start"),
        _ => None,
    }
}

pub fn command_basename(command: &str) -> &str {
    Path::new(command.split_whitespace().next().unwrap_or(command))
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::Duration;

    fn session_from_bytes(input: &[u8]) -> (Session, Box<dyn Write + Send>) {
        let (writer_for_assert, _reader_unused) = (Vec::<u8>::new(), ());
        let _ = writer_for_assert;
        let stdout: Box<dyn Read + Send> = Box::new(Cursor::new(input.to_vec()));
        let stdin: Box<dyn Write + Send> = Box::new(std::io::sink());
        (Session::new(stdin, stdout), Box::new(std::io::sink()))
    }

    #[test]
    fn to_line_includes_jsonrpc_and_fixed_ids() {
        assert_eq!(ClientMessage::Initialize.id(), Some(0));
        assert_eq!(ClientMessage::Initialized.id(), None);
        assert_eq!(
            ClientMessage::HooksList {
                cwd: PathBuf::from("/tmp/x")
            }
            .id(),
            Some(1)
        );
        let line = ClientMessage::Initialize.to_line();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "initialize");
        assert_eq!(v["id"], 0);
    }

    #[test]
    fn initialized_is_a_notification_with_no_id() {
        let line = ClientMessage::Initialized.to_line();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert!(v.get("id").is_none());
    }

    #[test]
    fn recv_response_returns_result_and_skips_notifications() {
        let input = b"{\"method\":\"remoteControl/status/changed\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n";
        let (mut session, _) = session_from_bytes(input);
        let v = session
            .recv_response(1, Instant::now() + Duration::from_secs(2))
            .expect("should resolve");
        assert_eq!(v["ok"], true);
    }

    #[test]
    fn recv_response_handles_out_of_order_ids() {
        // id 1's response arrives before id 0's would have -- caller asks
        // for 1 first here, which must work without id 0 ever appearing.
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"hooks\":[]}}\n";
        let (mut session, _) = session_from_bytes(input);
        let v = session
            .recv_response(1, Instant::now() + Duration::from_secs(2))
            .unwrap();
        assert!(v.get("hooks").is_some());
    }

    #[test]
    fn recv_response_eof_with_no_bytes_is_host_unreachable() {
        let (mut session, _) = session_from_bytes(b"");
        let err = session
            .recv_response(0, Instant::now() + Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(err, ProtocolError::HostUnreachable);
    }

    #[test]
    fn recv_response_truncated_partial_line_is_malformed_not_unreachable() {
        let (mut session, _) = session_from_bytes(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"resu");
        let err = session
            .recv_response(0, Instant::now() + Duration::from_secs(1))
            .unwrap_err();
        matches!(err, ProtocolError::HostResponseMalformed(_))
            .then_some(())
            .expect("expected malformed, got something else");
    }

    #[test]
    fn recv_response_rpc_error_member_is_surfaced() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":-32601,\"message\":\"no such method\"}}\n";
        let (mut session, _) = session_from_bytes(input);
        let err = session
            .recv_response(0, Instant::now() + Duration::from_secs(1))
            .unwrap_err();
        assert_eq!(
            err,
            ProtocolError::HostRpcError {
                code: Some(-32601),
                message: "no such method".into()
            }
        );
    }

    #[test]
    fn recv_response_oversized_line_overflows_closed() {
        let mut input = br#"{"jsonrpc":"2.0","id":0,"result":{"pad":""#.to_vec();
        input.extend(std::iter::repeat_n(b'a', MAX_LINE_BYTES + 10));
        input.extend_from_slice(b"\"}}\n");
        let (mut session, _) = session_from_bytes(&input);
        let err = session
            .recv_response(0, Instant::now() + Duration::from_secs(1))
            .unwrap_err();
        matches!(err, ProtocolError::HostResponseMalformed(_))
            .then_some(())
            .expect(
                "oversized line must fail closed as malformed, never silently truncate-and-accept",
            );
    }

    #[test]
    fn recv_response_times_out_on_silence() {
        // Never writes anything, never closes -- a Cursor over empty bytes
        // behaves like EOF though, so use a channel-backed Read that never
        // yields anything instead, to genuinely exercise the timeout path
        // rather than the EOF path.
        struct Never;
        impl Read for Never {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_secs(5));
                Ok(0)
            }
        }
        let stdout: Box<dyn Read + Send> = Box::new(Never);
        let stdin: Box<dyn Write + Send> = Box::new(std::io::sink());
        let mut session = Session::new(stdin, stdout);
        let err = session
            .recv_response(0, Instant::now() + Duration::from_millis(50))
            .unwrap_err();
        assert_eq!(err, ProtocolError::Timeout);
    }

    #[test]
    fn digest_shape_validation() {
        assert!(looks_like_sha256_digest(
            "sha256:2ae4c5fdc7724fdbbe43666a04473064dba9f66f45627cab46087238555abaa2"
        ));
        assert!(!looks_like_sha256_digest("sha256:deadbeef"));
        assert!(!looks_like_sha256_digest("not-a-digest"));
        assert!(!looks_like_sha256_digest(
            "sha256:2AE4C5FDC7724FDBBE43666A04473064DBA9F66F45627CAB46087238555ABAA2"
        ));
    }

    #[test]
    fn event_name_canonicalization_matches_both_spellings() {
        assert_eq!(canonical_event_name("preToolUse"), Some("pre_tool_use"));
        assert_eq!(canonical_event_name("pre_tool_use"), Some("pre_tool_use"));
        assert_eq!(canonical_event_name("postToolUse"), Some("post_tool_use"));
        assert_eq!(canonical_event_name("sessionStart"), Some("session_start"));
        assert_eq!(canonical_event_name("notAnEvent"), None);
    }

    #[test]
    fn command_basename_strips_args_and_path() {
        assert_eq!(
            command_basename("/usr/local/bin/fornax-hook-codex-event"),
            "fornax-hook-codex-event"
        );
        assert_eq!(
            command_basename("fornax-hook-codex-event --flag"),
            "fornax-hook-codex-event"
        );
    }

    #[test]
    fn real_fixture_before_parses_as_all_untrusted() {
        let raw = include_str!("../tests/fixtures/fornax-hooks-list-before.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        let result: HooksListResult = serde_json::from_value(v["result"].clone()).unwrap();
        assert_eq!(result.data.len(), 1);
        assert_eq!(result.data[0].hooks.len(), 3);
        for hook in &result.data[0].hooks {
            assert_eq!(hook.trust_status, "untrusted");
            assert!(looks_like_sha256_digest(&hook.current_hash));
            assert_eq!(command_basename(&hook.command), "fornax-hook-codex-event");
            assert!(canonical_event_name(&hook.event_name).is_some());
        }
    }

    #[test]
    fn real_fixture_after_parses_as_all_trusted() {
        let raw = include_str!("../tests/fixtures/fornax-hooks-list-after.json");
        let v: Value = serde_json::from_str(raw).unwrap();
        let result: HooksListResult = serde_json::from_value(v["result"].clone()).unwrap();
        for hook in &result.data[0].hooks {
            assert_eq!(hook.trust_status, "trusted");
        }
    }
}
