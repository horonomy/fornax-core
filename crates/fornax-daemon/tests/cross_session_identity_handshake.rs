//! FORNX-339 regression: a Fornax client must be able to prove it is
//! talking to the daemon actually serving its own `$FORNAX_HOME`, and any
//! mismatch must fail closed (`UNAVAILABLE`-style error), never silently
//! return another session's stale/cross-attributed evidence.
//!
//! Real bug, reproduced here against the actual binaries: `fornax-daemon`'s
//! HTTP API binds a fixed `127.0.0.1:4317` unless `FORNAX_HTTP_PORT` is set
//! explicitly — only the Unix socket and SQLite path were ever scoped per
//! `$FORNAX_HOME`. Two concurrently running homes sharing that default port
//! meant whichever daemon won the bind silently served *both* clients' `fornax
//! status`/`detail` calls, attributing one session's verdict to the other.
//!
//! This test spins up two real, fully independent `fornax-daemon` processes
//! (distinct `$FORNAX_HOME`s, distinct ephemeral ports — this harness never
//! needs to actually fight over one port to prove the invariant) and proves:
//!
//! 1. each daemon's HTTP responses carry its own distinct `x-fornax-home-id`
//!    identity header;
//! 2. a `fornax` client resolving `$FORNAX_HOME` to daemon A's home, but
//!    pointed (via `FORNAX_HTTP_PORT`) at daemon B's port, refuses to trust
//!    the response — it fails closed rather than showing daemon B's data as
//!    if it were daemon A's;
//! 3. the same client pointed at the *correct* matching daemon/port succeeds
//!    normally — the fix does not turn a legitimate call into a false
//!    failure.
//!
//! Uses the same real-process-spawning pattern as
//! `adversarial_daemon_input.rs` (this crate's other integration test) —
//! duplicated locally rather than shared, matching this workspace's existing
//! convention of self-contained integration test files.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn workspace_bin(name: &str) -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> is two levels below the workspace root");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let path = workspace_root.join("target").join(profile).join(name);
    assert!(
        path.exists(),
        "expected workspace binary at {path:?} — run `cargo build --workspace` first"
    );
    path
}

struct DaemonHandle {
    child: Child,
    home: PathBuf,
    port: u16,
    log_path: PathBuf,
}

impl DaemonHandle {
    fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn log_contents(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::fs::remove_dir_all(&self.home).ok();
    }
}

async fn start_daemon(label: &str) -> DaemonHandle {
    // See adversarial_daemon_input.rs's identical comment: `/tmp` + a short
    // id, not `std::env::temp_dir()`, to stay well under `sockaddr_un`'s
    // `SUN_LEN` cap for `$FORNAX_HOME/fornax.sock`.
    let home = PathBuf::from("/tmp").join(format!("fnx-id-{label}-{}", short_id()));
    std::fs::create_dir_all(&home).expect("create scratch FORNAX_HOME");
    let port = free_tcp_port();
    let log_path = home.join("daemon.log");
    let log_file = std::fs::File::create(&log_path).expect("create daemon log file");
    let log_file_err = log_file.try_clone().expect("clone log file handle");

    let child = Command::new(workspace_bin("fornax-daemon"))
        .env("FORNAX_HOME", &home)
        .env("FORNAX_HTTP_PORT", port.to_string())
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn fornax-daemon");

    let mut handle = DaemonHandle {
        child,
        home,
        port,
        log_path,
    };

    wait_for(Duration::from_secs(10), || {
        let alive = handle.is_alive();
        if !alive {
            panic!(
                "daemon exited during startup; log:\n{}",
                handle.log_contents()
            );
        }
        let ready =
            fornax_status_output(&handle.home, handle.port) != "🛡 fornax: daemon unreachable";
        async move { ready }
    })
    .await;

    handle
}

async fn wait_for<F, Fut>(timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if check().await {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!("condition not met within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Run the real `fornax status` binary with an arbitrary (`home`, `port`)
/// pair — the crux of every assertion below is that these two values do not
/// have to actually belong to the same daemon.
fn fornax_status_output(home: &Path, port: u16) -> String {
    let out = Command::new(workspace_bin("fornax"))
        .arg("status")
        .env("FORNAX_HOME", home)
        .env("FORNAX_HTTP_PORT", port.to_string())
        .output()
        .expect("run fornax status");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn free_tcp_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn short_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

/// Minimal raw HTTP/1.1 GET against `127.0.0.1:<port>`, returning the
/// response headers as lowercase text. Deliberately avoids adding an HTTP
/// client dev-dependency this crate doesn't otherwise have — every other
/// integration test in this crate talks to the daemon exclusively through
/// the real `fornax` CLI binary; this is the one place a test needs the raw
/// header Cargo.toml's existing dependency set has no client for.
fn raw_get_headers(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to daemon HTTP port");
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .expect("write HTTP request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read HTTP response");
    response.to_lowercase()
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("{}:", name.to_lowercase());
    headers
        .lines()
        .find(|line| line.to_lowercase().starts_with(&needle))
        .map(|line| line.split_once(':').unwrap().1.trim())
}

#[tokio::test]
async fn each_daemon_reports_a_distinct_home_identity_header() {
    let daemon_a = start_daemon("a").await;
    let daemon_b = start_daemon("b").await;

    let headers_a = raw_get_headers(daemon_a.port, "/api/status");
    let headers_b = raw_get_headers(daemon_b.port, "/api/status");

    let id_a = header_value(&headers_a, "x-fornax-home-id")
        .expect("daemon A must send its home identity header");
    let id_b = header_value(&headers_b, "x-fornax-home-id")
        .expect("daemon B must send its home identity header");

    assert_ne!(
        id_a, id_b,
        "two distinct $FORNAX_HOMEs must never report the same daemon identity"
    );
}

#[tokio::test]
async fn client_fails_closed_when_pointed_at_the_wrong_daemon() {
    // This is the exact FORNX-339 scenario: a client resolves its own
    // $FORNAX_HOME (daemon_a's), but for whatever reason (a stale
    // FORNAX_HTTP_PORT left in the environment, a port collision resolved
    // in the other daemon's favor, ...) ends up talking to a daemon that is
    // actually serving a *different* home (daemon_b's). Before FORNX-339's
    // fix, `fornax status` had no way to detect this and would have printed
    // daemon_b's verdict as if it were daemon_a's own.
    let daemon_a = start_daemon("a").await;
    let daemon_b = start_daemon("b").await;

    let mismatched = fornax_status_output(&daemon_a.home, daemon_b.port);

    assert!(
        mismatched.contains("UNAVAILABLE") && mismatched.to_lowercase().contains("identity"),
        "a client whose $FORNAX_HOME doesn't match the daemon it actually reached must fail \
         closed with an explicit identity-mismatch message, not silently print that daemon's \
         data as if it belonged to the expected home. Got: {mismatched:?}"
    );
    // The critical negative assertion: whatever the failure text says, it
    // must never be a plausible-looking verdict icon that a user could
    // mistake for a real (mis-attributed) result.
    assert!(
        !mismatched.contains("🛡 ✓") && !mismatched.contains("🛡 ✕") && !mismatched.contains("🛡 ?"),
        "must never render a verdict icon for a cross-daemon response: {mismatched:?}"
    );
}

#[tokio::test]
async fn client_succeeds_normally_against_its_own_matching_daemon() {
    // The fix must not turn every legitimate call into a false failure —
    // matched (home, port) pairs still work exactly as before.
    let daemon_a = start_daemon("a").await;

    let matched = fornax_status_output(&daemon_a.home, daemon_a.port);

    assert_eq!(
        matched, "🛡 fornax: no findings yet",
        "a client correctly paired with its own daemon must see a normal response, not an \
         identity-mismatch error: {matched:?}"
    );
}
