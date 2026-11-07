//! FORNX-464: the corporate no-egress guarantee across every daemon transport,
//! proven on the REAL `fornax-daemon` and `fornax` binaries against counting
//! loopback listeners (one per path, so a count is attributable).
//!
//! Paths covered: audit checkpoint push, policy poll, `fornax upload run`, and
//! the daemon's scheduled monthly upload. The semantic judge is deliberately
//! excluded: it is loopback-exempt by design (`decide` allows it on a loopback
//! host in every profile), so a loopback listener cannot distinguish it.
//!
//! Every scenario runs in its own isolated `$HOME`/`$FORNAX_HOME` under the
//! system temp dir, with fake literal credentials in 0600 files.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::Utc;
use fornax_store::Store;
use fornax_types::{AgentEvent, EventKind, Provider};
use uuid::Uuid;

mod common;
use common::free_tcp_port;

fn workspace_bin(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> is two levels below the workspace root");
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let path = root.join("target").join(profile).join(name);
    assert!(
        path.exists(),
        "expected workspace binary at {path:?} -- run `cargo build -p fornax-cli` first"
    );
    path
}

/// A loopback listener that records the request line of every connection.
struct Counter {
    base: String,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Counter {
    fn start() -> Counter {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let (mut head_end, mut want) = (None, 0usize);
                loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if head_end.is_none() {
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            head_end = Some(i + 4);
                            let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                            want = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse().ok())
                                .unwrap_or(0);
                        }
                    }
                    if head_end.is_some_and(|h| buf.len() >= h + want) {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&buf)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                recorded.lock().unwrap().push(line);
                let _ = stream.write_all(
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });
        Counter {
            base: format!("http://{addr}"),
            seen,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// POSITIVE CONTROL: prove the listener records a request, then exclude
    /// the probe from `hits`, so a later zero is never a dead listener.
    fn probe(&self) {
        let addr = self.base.trim_start_matches("http://");
        let mut s = TcpStream::connect(addr).expect("listener accepts");
        s.write_all(b"GET /probe HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut sink = Vec::new();
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let _ = s.read_to_end(&mut sink);
        assert!(
            self.seen
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.starts_with("GET /probe")),
            "listener did not record the probe: it is not live"
        );
    }

    fn hits(&self) -> Vec<String> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|l| !l.starts_with("GET /probe"))
            .cloned()
            .collect()
    }
}

struct Paths {
    upload: Counter,
    checkpoint: Counter,
    poll: Counter,
}

impl Paths {
    fn start() -> Paths {
        let p = Paths {
            upload: Counter::start(),
            checkpoint: Counter::start(),
            poll: Counter::start(),
        };
        for c in [&p.upload, &p.checkpoint, &p.poll] {
            c.probe();
        }
        p
    }
    fn upload_url(&self) -> String {
        self.upload.url("/v1/metadata-batches")
    }
    fn checkpoint_url(&self) -> String {
        self.checkpoint.url("/v1/audit-checkpoints")
    }
    fn poll_url(&self) -> String {
        self.poll.url("/v1/policy")
    }
}

/// Env shared by the CLI and the daemon: isolated HOME, every transport
/// configured on loopback, the legacy kill switch ON (the point is that it
/// cannot override the corporate profile).
fn base_env(cmd: &mut Command, home: &Path, paths: &Paths) {
    cmd.env("HOME", home)
        .env("FORNAX_HOME", home)
        .env("FORNAX_CLOUD_SYNC_ENABLED", "1")
        .env("FORNX_DEVICE_ID", "device-test")
        .env("FORNAX_UPLOAD_BACKOFF_MS", "1")
        .env("FORNAX_AUDIT_CHECKPOINT_URL", paths.checkpoint_url())
        .env("FORNAX_POLICY_POLL_URL", paths.poll_url())
        .env(
            "FORNAX_DEVICE_CREDENTIAL_FILE",
            home.join("device-credential"),
        )
        .env("FORNAX_AUDIT_CHECKPOINT_INTERVAL_SECONDS", "60")
        .env("FORNAX_POLICY_POLL_INTERVAL_SECONDS", "60")
        .env("FORNAX_UPLOAD_SCHEDULE_INTERVAL_SECONDS", "60");
}

struct Scenario {
    home: PathBuf,
    paths: Paths,
}

impl Scenario {
    fn new() -> Scenario {
        let home = std::env::temp_dir().join(format!(
            "fnx-egt-{}",
            &Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::create_dir_all(&home).unwrap();
        let cred = home.join("device-credential");
        std::fs::write(&cred, "fnxd_v1_test-credential\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cred, std::fs::Permissions::from_mode(0o600)).unwrap();
        Scenario {
            home,
            paths: Paths::start(),
        }
    }

    fn cli(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(workspace_bin("fornax"));
        cmd.args(args);
        base_env(&mut cmd, &self.home, &self.paths);
        cmd.output().expect("run fornax")
    }

    fn cli_ok(&self, args: &[&str]) -> String {
        let out = self.cli(args);
        assert!(
            out.status.success(),
            "fornax {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Personal profile with allowlist + consent for every evidence path and
    /// the policy fetch allowlist entry.
    fn personal_authorized(&self, with_policy_allowlist: bool) {
        self.cli_ok(&["egress", "profile-set", "personal"]);
        let mut grants = vec![
            (
                "evidence_batch_upload",
                self.paths.upload_url(),
                "evidence_metadata,finding_verdicts",
            ),
            (
                "audit_checkpoint",
                self.paths.checkpoint_url(),
                "evidence_metadata",
            ),
        ];
        if with_policy_allowlist {
            self.cli_ok(&[
                "egress",
                "allow-add",
                "--purpose",
                "policy_fetch",
                &self.paths.poll_url(),
            ]);
        }
        for (purpose, url, classes) in grants.drain(..) {
            self.cli_ok(&["egress", "allow-add", "--purpose", purpose, &url]);
            self.cli_ok(&[
                "egress",
                "consent-grant",
                "--purpose",
                purpose,
                "--destination",
                &url,
                "--classes",
                classes,
            ]);
        }
    }

    /// One closed month of old events and a consent old enough to cover it,
    /// so the schedule has real work due (otherwise zero would be vacuous).
    async fn make_upload_due(&self) {
        let store = Store::open(self.home.join("fornax.db")).await.unwrap();
        store
            .insert_event(&AgentEvent {
                id: Uuid::new_v4(),
                session_id: "s-old".into(),
                provider: Provider::ClaudeCode,
                kind: EventKind::PostToolUse,
                observed_at: (Utc::now() - chrono::Duration::days(40)).to_rfc3339(),
                tool_name: Some("Bash".into()),
                tool_input: Some(serde_json::json!({"command": "CANARY-SECRET"})),
                tool_response: None,
                raw: serde_json::json!({}),
            })
            .await
            .unwrap();
        drop(store);
        let sixty = (Utc::now() - chrono::Duration::days(60)).to_rfc3339();
        let pool = sqlx::SqlitePool::connect(&format!(
            "sqlite://{}",
            self.home.join("fornax.db").display()
        ))
        .await
        .unwrap();
        for sql in [
            "UPDATE egress_consents SET granted_at = ?1",
            "UPDATE egress_profile_log SET changed_at = ?1",
        ] {
            sqlx::query(sql).bind(&sixty).execute(&pool).await.unwrap();
        }
        pool.close().await;
    }

    fn start_daemon(&self) -> Daemon {
        let log_path = self.home.join("daemon.log");
        let log = std::fs::File::create(&log_path).unwrap();
        let log_err = log.try_clone().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fornax-daemon"));
        base_env(&mut cmd, &self.home, &self.paths);
        let child = cmd
            .env("FORNAX_HTTP_PORT", free_tcp_port().to_string())
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(log_err))
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn fornax-daemon");
        Daemon { child, log_path }
    }
}

struct Daemon {
    child: Child,
    log_path: PathBuf,
}

impl Daemon {
    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log_path).unwrap_or_default()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Sleeps until `deadline` or until `done()`.
async fn wait_until(secs: u64, mut done: impl FnMut() -> bool) {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < end && !done() {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Runs for about 75-100 s of wall time (the upload schedule's 60 s interval
/// floor, plus the 0-30 s startup jitter of the checkpoint and poll tasks), so
/// it is `#[ignore]`d from the default run. Run it explicitly with
/// `cargo test -p fornax-daemon --test egress_transport_e2e -- --ignored`
/// after `cargo build -p fornax-cli -p fornax-daemon`.
///
/// Three isolated installs run concurrently: a personal control with every
/// path authorized, a fresh corporate install, and an install that was
/// personal with consents and allowlist entries and then switched to
/// corporate. All have the legacy `FORNAX_CLOUD_SYNC_ENABLED=1` switch on, a
/// credential, every transport URL configured, and a closed month due.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "takes ~75-100 s: waits for the daemon's 60 s schedule interval floor"]
async fn corporate_opens_no_connection_on_any_path_and_the_personal_control_does() {
    // Personal control: everything authorized, work due.
    let personal = Scenario::new();
    personal.personal_authorized(true);
    personal.make_upload_due().await;

    // Fresh corporate: allowlist entries for the evidence paths exist, but
    // no consent can (and the profile is local-only). The policy_fetch
    // allowlist is left out on purpose, see the note below.
    let fresh = Scenario::new();
    fresh.cli_ok(&["egress", "profile-set", "corporate"]);
    for (purpose, url) in [
        ("evidence_batch_upload", fresh.paths.upload_url()),
        ("audit_checkpoint", fresh.paths.checkpoint_url()),
    ] {
        fresh.cli_ok(&["egress", "allow-add", "--purpose", purpose, &url]);
    }
    fresh.make_upload_due().await;

    // Personal with consents, then switched to corporate.
    let switched = Scenario::new();
    switched.personal_authorized(false);
    switched.make_upload_due().await;
    switched.cli_ok(&["egress", "profile-set", "corporate"]);

    // Personal with consents AND a policy_fetch allowlist entry, then
    // corporate: only the evidence-free policy poll may still connect.
    let with_policy = Scenario::new();
    with_policy.personal_authorized(true);
    with_policy.make_upload_due().await;
    with_policy.cli_ok(&["egress", "profile-set", "corporate"]);

    // Connections on the evidence-carrying paths only.
    let evidence_hits =
        |s: &Scenario| s.paths.upload.hits().len() + s.paths.checkpoint.hits().len();

    // `fornax upload run` on both corporate installs: refused, no connection.
    for s in [&fresh, &switched, &with_policy] {
        let out = s.cli(&["upload", "run"]);
        assert!(!out.status.success(), "corporate `upload run` must fail");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("no live consent"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            evidence_hits(s),
            0,
            "corporate `upload run` opened a connection"
        );
    }

    let mut daemons = [
        personal.start_daemon(),
        fresh.start_daemon(),
        switched.start_daemon(),
        with_policy.start_daemon(),
    ];

    // Give the personal control time to exercise every path, then hold the
    // corporate daemons for the same wall time.
    wait_until(100, || {
        !personal.paths.upload.hits().is_empty()
            && !personal.paths.checkpoint.hits().is_empty()
            && !personal.paths.poll.hits().is_empty()
            && !with_policy.paths.poll.hits().is_empty()
    })
    .await;
    // A little extra so a late corporate attempt on any path would show up.
    tokio::time::sleep(Duration::from_secs(5)).await;

    for d in &mut daemons {
        assert!(d.alive(), "daemon died:\n{}", d.log());
    }

    // POSITIVE CONTROL: every path connected under the personal profile.
    let mut control: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    control.insert("upload", personal.paths.upload.hits());
    control.insert("checkpoint", personal.paths.checkpoint.hits());
    control.insert("poll", personal.paths.poll.hits());
    for (name, hits) in &control {
        assert!(
            !hits.is_empty(),
            "personal control: the {name} path never connected; log:\n{}",
            daemons[0].log()
        );
    }
    assert!(control["upload"][0].starts_with("POST /v1/metadata-batches"));
    assert!(control["checkpoint"][0].starts_with("POST /v1/audit-checkpoints"));
    assert!(control["poll"][0].starts_with("GET /v1/policy"));
    assert!(daemons[0]
        .log()
        .contains("monthly upload schedule task enabled"));

    // The corporate daemons ran the same tasks for the same time.
    for (i, s) in [&fresh, &switched].into_iter().enumerate() {
        let d = &daemons[i + 1];
        assert!(
            d.log().contains("monthly upload schedule task enabled"),
            "{}",
            d.log()
        );
        assert_eq!(
            s.paths.upload.hits(),
            Vec::<String>::new(),
            "corporate scheduled upload connected"
        );
        assert_eq!(
            s.paths.checkpoint.hits(),
            Vec::<String>::new(),
            "corporate checkpoint push connected"
        );
        assert_eq!(
            s.paths.poll.hits(),
            Vec::<String>::new(),
            "corporate policy poll connected"
        );
    }

    // Corporate WITH a policy_fetch allowlist entry: the evidence-free poll
    // connects (positive control that the poll wiring is live in corporate),
    // while upload and checkpoint stay at zero.
    let d = &daemons[3];
    assert!(d.log().contains("monthly upload schedule task enabled"));
    let poll_hits = with_policy.paths.poll.hits();
    assert!(
        !poll_hits.is_empty() && poll_hits[0].starts_with("GET /v1/policy"),
        "corporate + policy_fetch allowlist: the poll should connect; log:\n{}",
        d.log()
    );
    assert_eq!(with_policy.paths.upload.hits(), Vec::<String>::new());
    assert_eq!(with_policy.paths.checkpoint.hits(), Vec::<String>::new());

    // And `fornax upload run` after the daemon ran, still nothing.
    for s in [&fresh, &switched, &with_policy] {
        assert!(!s.cli(&["upload", "run"]).status.success());
        assert_eq!(evidence_hits(s), 0);
    }

    drop(daemons);
    for s in [&personal, &fresh, &switched, &with_policy] {
        std::fs::remove_dir_all(&s.home).ok();
    }
}
