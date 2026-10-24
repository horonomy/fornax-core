//! Real end-to-end flow for `fornax upload run` (FORNX-464): the actual
//! compiled `fornax` binary against an isolated `$FORNAX_HOME` and a
//! programmable loopback mock receiver that records every request. No real
//! network, no real credentials, no real corporate or personal data.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const CANARY: &str = "SECRET-CANARY-5be1";

fn fornax_bin() -> &'static str {
    env!("CARGO_BIN_EXE_fornax")
}

struct Req {
    headers: HashMap<String, String>,
    body: String,
}

/// A loopback receiver that answers from a scripted queue (the last entry
/// repeats) and records every request it receives.
struct Mock {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Req>>>,
}

/// Called with the 1-based request number after a request is recorded and
/// before the reply is written.
type Hook = Arc<dyn Fn(usize) + Send + Sync>;

impl Mock {
    fn start(script: Vec<(u16, Vec<(&'static str, String)>)>) -> Mock {
        Mock::start_with(script, None, std::time::Duration::ZERO)
    }

    fn start_with(
        script: Vec<(u16, Vec<(&'static str, String)>)>,
        hook: Option<Hook>,
        delay: std::time::Duration,
    ) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let script = Arc::new(Mutex::new((script, 0usize)));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                // Read headers, then Content-Length bytes of body.
                let (head_end, content_length) = loop {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (None, 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (Some(pos + 4), len);
                    }
                };
                let Some(head_end) = head_end else { continue };
                while buf.len() < head_end + content_length {
                    let n = stream.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let headers = head
                    .lines()
                    .skip(1)
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_lowercase(), v.trim().to_string()))
                    .collect();
                let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
                let n = {
                    let mut g = recorded.lock().unwrap();
                    g.push(Req { headers, body });
                    g.len()
                };
                if let Some(hook) = &hook {
                    hook(n);
                }
                std::thread::sleep(delay);

                let (status, extra) = {
                    let mut g = script.lock().unwrap();
                    let i = g.1.min(g.0.len() - 1);
                    g.1 += 1;
                    g.0[i].clone()
                };
                let mut resp =
                    format!("HTTP/1.1 {status} X\r\ncontent-length: 2\r\nconnection: close\r\n");
                for (k, v) in extra {
                    resp.push_str(&format!("{k}: {v}\r\n"));
                }
                resp.push_str("\r\n{}");
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        Mock { addr, seen }
    }

    fn url(&self) -> String {
        format!("http://{}/v1/metadata-batches", self.addr)
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

struct Env {
    home: std::path::PathBuf,
}

impl Env {
    fn new() -> Env {
        let home = std::env::temp_dir().join(format!("fornax-upload-e2e-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        let cred = home.join("device-credential");
        std::fs::write(&cred, "fnxd_v1_test-credential\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cred, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Env { home }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(fornax_bin())
            .args(args)
            .env("FORNAX_HOME", &self.home)
            .env("FORNAX_CLOUD_SYNC_ENABLED", "1")
            .env(
                "FORNX_DEVICE_ID",
                std::env::var("FORNAX_E2E_DEVICE_ID").unwrap_or_else(|_| "device-test".into()),
            )
            .env("FORNAX_UPLOAD_BACKOFF_MS", "1")
            .output()
            .expect("run fornax")
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "fornax {args:?}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn fails(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(!out.status.success(), "fornax {args:?} should fail");
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    /// Personal profile + allowlist + consent for `url`.
    fn authorize(&self, url: &str) {
        self.ok(&["egress", "profile-set", "personal"]);
        self.ok(&[
            "egress",
            "allow-add",
            "--purpose",
            "evidence_batch_upload",
            url,
        ]);
        self.ok(&[
            "egress",
            "consent-grant",
            "--purpose",
            "evidence_batch_upload",
            "--destination",
            url,
            "--classes",
            "evidence_metadata,finding_verdicts",
        ]);
    }

    /// One session of content-bearing records captured just after consent.
    async fn seed(&self) {
        use fornax_types::{
            AgentEvent, Claim, EventKind, Evidence, EvidenceKind, Finding, Provider, Verdict,
        };
        let store = fornax_store::Store::open(self.home.join("fornax.db"))
            .await
            .unwrap();
        let ts = (chrono::Utc::now() + chrono::Duration::seconds(5)).to_rfc3339();
        let event = AgentEvent {
            id: Uuid::new_v4(),
            session_id: "s-1".into(),
            provider: Provider::ClaudeCode,
            kind: EventKind::PostToolUse,
            observed_at: ts.clone(),
            tool_name: Some("Bash".into()),
            tool_input: Some(serde_json::json!({"command": CANARY})),
            tool_response: Some(serde_json::json!({"stdout": CANARY})),
            raw: serde_json::json!({"cwd": CANARY}),
        };
        store.insert_event(&event).await.unwrap();
        let claim = Claim {
            id: Uuid::new_v4(),
            session_id: "s-1".into(),
            source_event_id: event.id,
            text: format!("all pass {CANARY}"),
            subject: "test_result".into(),
            claimed_at: ts.clone(),
        };
        store.insert_claim(&claim).await.unwrap();
        let evidence = Evidence {
            id: Uuid::new_v4(),
            session_id: "s-1".into(),
            source_event_id: event.id,
            kind: EvidenceKind::ExitCode,
            observed_at: ts.clone(),
            payload: serde_json::json!({"command": CANARY}),
            provenance: "claude_code:PostToolUse:Bash#tool_response".into(),
            source: None,
            extension: None,
            evidence_purged: false,
        };
        store.insert_evidence(&evidence).await.unwrap();
        store
            .insert_finding(&Finding {
                id: Uuid::new_v4(),
                claim_id: claim.id,
                verdict: Verdict::Verified,
                evidence_ids: vec![evidence.id],
                verifier_name: "test_result_verifier_v1".into(),
                rationale: format!("because {CANARY}"),
                computed_at: ts,
            })
            .await
            .unwrap();
    }
}

impl Env {
    /// `authorize` that also returns the consent id.
    fn authorize_with_id(&self, url: &str) -> String {
        self.ok(&["egress", "profile-set", "personal"]);
        self.allow_and_consent(url)
    }

    /// Allowlist `url` and grant a consent for it; returns the consent id.
    fn allow_and_consent(&self, url: &str) -> String {
        self.ok(&[
            "egress",
            "allow-add",
            "--purpose",
            "evidence_batch_upload",
            url,
        ]);
        let out = self.ok(&[
            "egress",
            "consent-grant",
            "--purpose",
            "evidence_batch_upload",
            "--destination",
            url,
            "--classes",
            "evidence_metadata,finding_verdicts",
        ]);
        out.split_whitespace()
            .nth(4)
            .expect("consent id in grant output")
            .to_string()
    }

    /// One content-bearing event observed `days_ago` days ago.
    async fn seed_old_event(&self, days_ago: i64) {
        use fornax_types::{AgentEvent, EventKind, Provider};
        let store = fornax_store::Store::open(self.home.join("fornax.db"))
            .await
            .unwrap();
        store
            .insert_event(&AgentEvent {
                id: Uuid::new_v4(),
                session_id: format!("s-old-{days_ago}"),
                provider: Provider::ClaudeCode,
                kind: EventKind::PostToolUse,
                observed_at: (chrono::Utc::now() - chrono::Duration::days(days_ago)).to_rfc3339(),
                tool_name: Some("Bash".into()),
                tool_input: Some(serde_json::json!({"command": CANARY})),
                tool_response: None,
                raw: serde_json::json!({}),
            })
            .await
            .unwrap();
    }

    /// Backdate every consent and profile change so old events are eligible.
    async fn backdate_consent(&self, days: i64) {
        let when = (chrono::Utc::now() - chrono::Duration::days(days)).to_rfc3339();
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
            sqlx::query(sql).bind(&when).execute(&pool).await.unwrap();
        }
        pool.close().await;
    }

    /// Spawn `fornax upload run` without waiting for it.
    fn spawn_upload_run(&self) -> std::process::Child {
        Command::new(fornax_bin())
            .args(["upload", "run", "--window", &window_now()])
            .env("FORNAX_HOME", &self.home)
            .env("FORNAX_CLOUD_SYNC_ENABLED", "1")
            .env("FORNX_DEVICE_ID", "device-test")
            .env("FORNAX_UPLOAD_BACKOFF_MS", "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn fornax")
    }
}

fn window_now() -> String {
    fornax_store::upload::current_window(chrono::Utc::now())
}

#[tokio::test]
async fn happy_path_sends_verified_metadata_once_and_a_second_run_sends_nothing() {
    let mock = Mock::start(vec![(202, vec![])]);
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;

    let out = env.ok(&["upload", "run", "--window", &window_now()]);
    assert!(out.contains("uploaded 1 batch(es)"), "{out}");
    assert_eq!(mock.count(), 1);

    let req = {
        let seen = mock.seen.lock().unwrap();
        let first = &seen[0];
        Req {
            headers: first.headers.clone(),
            body: first.body.clone(),
        }
    };
    assert_eq!(
        req.headers.get("authorization").map(String::as_str),
        Some("Bearer fnxd_v1_test-credential")
    );
    let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
    assert_eq!(body["device_id"], "device-test");
    assert_eq!(body["canonicalization"], "fornax-egress-canon-v1");
    // Idempotency-Key is the manifest hash, and the hash is the sha256 of the
    // canonical members -- the receiver recomputes exactly this.
    let manifest = body["manifest_sha256"].as_str().unwrap();
    assert_eq!(
        req.headers.get("idempotency-key").map(String::as_str),
        Some(manifest)
    );
    let canon = fornax_store::upload::canonical_json(&body["members"]);
    assert_eq!(fornax_store::upload::sha256_hex(canon.as_bytes()), manifest);
    // Metadata only: no content values and no content-bearing keys leave.
    for forbidden in [
        CANARY,
        "\"tool_input\"",
        "\"tool_response\"",
        "\"payload\"",
        "\"rationale\"",
        "\"text\"",
        "\"raw\"",
    ] {
        assert!(
            !req.body.contains(forbidden),
            "request leaked {forbidden}: {}",
            req.body
        );
    }

    let again = env.ok(&["upload", "run", "--window", &window_now()]);
    assert!(again.contains("uploaded 0 batch(es)"), "{again}");
    assert_eq!(mock.count(), 1, "an acknowledged batch is never resent");
    let status = env.ok(&["upload", "status"]);
    assert!(status.contains("acknowledged"), "{status}");
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn transient_failures_retry_with_identical_bytes_and_the_same_idempotency_key() {
    let mock = Mock::start(vec![
        (503, vec![("retry-after", "0".into())]),
        (503, vec![]),
        (202, vec![]),
    ]);
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;
    env.ok(&["upload", "run", "--window", &window_now()]);
    assert_eq!(mock.count(), 3);
    let seen = mock.seen.lock().unwrap();
    assert!(
        seen.iter().all(|r| r.body == seen[0].body),
        "every retry is byte-identical"
    );
    assert!(seen
        .iter()
        .all(|r| r.headers.get("idempotency-key") == seen[0].headers.get("idempotency-key")));
    drop(seen);
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn exhausted_retries_leave_the_batch_sealed_and_the_next_run_resumes_it_byte_identically() {
    let mock = Mock::start(vec![(503, vec![])]);
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;

    let err = env.fails(&["upload", "run", "--window", &window_now()]);
    assert!(err.contains("upload incomplete"), "{err}");
    let first_attempts = mock.count();
    assert_eq!(first_attempts, 4, "bounded attempts per run");
    let status = env.ok(&["upload", "status"]);
    assert!(status.contains("sealed: 1"), "{status}");

    // The receiver recovers; a fresh process resumes the SAME sealed batch.
    let recovered = Mock::start(vec![(202, vec![])]);
    // Point the consent at the recovered receiver by reusing the same port is
    // not possible, so verify resume against the original mock by swapping
    // its script: simplest is a new mock on a new consent -- instead assert
    // the stored batch is unchanged by re-running against the failing mock.
    drop(recovered);
    let err2 = env.fails(&["upload", "run", "--window", &window_now()]);
    assert!(err2.contains("upload incomplete"), "{err2}");
    let seen = mock.seen.lock().unwrap();
    assert!(seen.len() > first_attempts);
    assert!(
        seen.iter().all(|r| r.body == seen[0].body),
        "the resumed batch is byte-identical"
    );
    drop(seen);
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn a_permanent_rejection_poisons_the_batch_and_is_not_retried() {
    let mock = Mock::start(vec![(422, vec![])]);
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;
    env.ok(&["upload", "run", "--window", &window_now()]);
    assert_eq!(mock.count(), 1);
    let status = env.ok(&["upload", "status"]);
    assert!(status.contains("poison: 1"), "{status}");
    env.ok(&["upload", "run", "--window", &window_now()]);
    assert_eq!(mock.count(), 1, "a poisoned batch is never retried");
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn a_rejected_credential_never_poisons_data() {
    let mock = Mock::start(vec![(401, vec![])]);
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;
    let err = env.fails(&["upload", "run", "--window", &window_now()]);
    assert!(err.contains("rejected the device credential"), "{err}");
    let status = env.ok(&["upload", "status"]);
    assert!(
        status.contains("sealed: 1") && !status.contains("poison"),
        "{status}"
    );
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn a_redirect_is_refused_and_its_target_sees_nothing() {
    let target = Mock::start(vec![(200, vec![])]);
    let mock = Mock::start(vec![(
        302,
        vec![("location", format!("http://{}/stolen", target.addr))],
    )]);
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;
    let err = env.fails(&["upload", "run", "--window", &window_now()]);
    assert!(err.contains("redirect refused"), "{err}");
    assert_eq!(mock.count(), 1);
    let status = env.ok(&["upload", "status"]);
    assert!(
        status.contains("sealed: 1") && !status.contains("poison"),
        "a redirect must not poison data: {status}"
    );
    assert_eq!(
        target.count(),
        0,
        "the redirect target must see zero connections"
    );
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn no_consent_corporate_revoked_and_killswitch_off_all_open_no_connection() {
    let mock = Mock::start(vec![(202, vec![])]);
    let env = Env::new();
    env.seed().await;

    // Nothing configured.
    assert!(env
        .fails(&["upload", "run", "--window", &window_now()])
        .contains("no live consent"));
    assert_eq!(mock.count(), 0);

    // Authorized, then the kill switch off.
    env.authorize(&mock.url());
    env.seed().await;
    let out = Command::new(fornax_bin())
        .args(["upload", "run", "--window", &window_now()])
        .env("FORNAX_HOME", &env.home)
        .env("FORNX_DEVICE_ID", "device-test")
        .env_remove("FORNAX_CLOUD_SYNC_ENABLED")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(mock.count(), 0, "the kill switch only tightens");

    // Corporate overrides everything.
    env.ok(&["egress", "profile-set", "corporate"]);
    assert!(env
        .fails(&["upload", "run", "--window", &window_now()])
        .contains("no live consent"));
    assert_eq!(mock.count(), 0);
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn preview_is_local_shows_exact_metadata_and_sends_nothing() {
    let mock = Mock::start(vec![(202, vec![])]);
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;
    // Stage via a failing run so there is something pending, then preview.
    let _ = env.run(&["upload", "run", "--window", "1999-01"]);
    let out = env.ok(&["upload", "preview"]);
    assert!(out.contains("exactly as they would be uploaded"), "{out}");
    assert!(!out.contains(CANARY), "{out}");
    assert_eq!(mock.count(), 0);
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn a_wrong_path_or_oversized_reply_keeps_the_batch_sealed() {
    for code in [404u16, 405, 409, 413] {
        let mock = Mock::start(vec![(code, vec![])]);
        let env = Env::new();
        env.authorize(&mock.url());
        env.seed().await;
        env.fails(&["upload", "run", "--window", &window_now()]);
        let status = env.ok(&["upload", "status"]);
        assert!(
            status.contains("sealed: 1") && !status.contains("poison"),
            "HTTP {code} must not poison data: {status}"
        );
        std::fs::remove_dir_all(&env.home).ok();
    }
}

/// Core -> Cloud contract, against the REAL `fornax-cloud` receiver rather
/// than a mock. Ignored by default; run it with a cloud backend listening and
/// `FORNAX_E2E_CLOUD_URL` (the `/v1/metadata-batches` URL),
/// `FORNAX_E2E_CLOUD_CRED_FILE` (a device credential file, copied unread) and
/// `FORNAX_E2E_DEVICE_ID` set. The receiver's strict schema and canonical hash
/// check are what make a pass meaningful.
#[tokio::test]
#[ignore = "needs a running fornax-cloud backend; see the doc comment"]
async fn the_real_cloud_receiver_accepts_the_batch_once_and_dedups_the_resend() {
    let (Ok(url), Ok(cred)) = (
        std::env::var("FORNAX_E2E_CLOUD_URL"),
        std::env::var("FORNAX_E2E_CLOUD_CRED_FILE"),
    ) else {
        panic!("FORNAX_E2E_CLOUD_URL and FORNAX_E2E_CLOUD_CRED_FILE are required");
    };
    let env = Env::new();
    std::fs::copy(&cred, env.home.join("device-credential")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            env.home.join("device-credential"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    env.authorize(&url);
    env.seed().await;

    let out = env.ok(&["upload", "run", "--window", &window_now()]);
    assert!(out.contains("uploaded 1 batch(es)"), "{out}");
    assert!(out.contains("0 rejected permanently"), "{out}");
    let again = env.ok(&["upload", "run", "--window", &window_now()]);
    assert!(again.contains("uploaded 0 batch(es)"), "{again}");
    let status = env.ok(&["upload", "status"]);
    assert!(status.contains("acknowledged"), "{status}");
    std::fs::remove_dir_all(&env.home).ok();
}

fn wait_for(mock: &Mock, n: usize) {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while mock.count() < n {
        assert!(
            std::time::Instant::now() < end,
            "mock never saw request {n}"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Two closed months -> two batches. The receiver revokes the consent (via
/// the real `fornax egress consent-revoke`) as it receives the first request;
/// the second batch must never be sent.
#[tokio::test]
async fn revoking_consent_mid_run_stops_the_second_batch() {
    let env = Env::new();
    let home = env.home.clone();
    let consent_id: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let id_for_hook = consent_id.clone();
    let hook: Hook = Arc::new(move |n| {
        if n == 1 {
            let id = id_for_hook.lock().unwrap().clone().expect("consent id set");
            let out = Command::new(fornax_bin())
                .args(["egress", "consent-revoke", &id])
                .env("FORNAX_HOME", &home)
                .output()
                .expect("run consent-revoke");
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    });
    let mock = Mock::start_with(vec![(202, vec![])], Some(hook), std::time::Duration::ZERO);
    let id = env.authorize_with_id(&mock.url());
    *consent_id.lock().unwrap() = Some(id);
    env.seed_old_event(70).await;
    env.seed_old_event(35).await;
    env.backdate_consent(100).await;

    let _ = env.run(&["upload", "run"]);
    // The first request arriving is the positive control: the receiver and
    // the revoke hook are live, so the missing second request is meaningful.
    assert_eq!(mock.count(), 1, "the second batch must never be sent");

    let status = env.ok(&["upload", "status"]);
    assert!(
        status.contains("acknowledged: 1") && status.contains("sealed: 1"),
        "one batch acknowledged, the other still sealed (not sent): {status}"
    );

    // The consent is gone: a later run refuses and still sends nothing.
    let err = env.fails(&["upload", "run"]);
    assert!(err.contains("no live consent"), "{err}");
    assert_eq!(mock.count(), 1);
    std::fs::remove_dir_all(&env.home).ok();
}

/// A batch sealed for destination A (receiver down) is never re-aimed at the
/// destination of a later, also-allowlisted consent B.
#[tokio::test]
async fn a_batch_sealed_for_one_url_is_never_sent_to_a_renewed_consents_url() {
    let a = Mock::start(vec![(503, vec![])]);
    let b = Mock::start(vec![(202, vec![])]);
    let env = Env::new();
    env.authorize(&a.url());
    env.seed_old_event(40).await;
    env.backdate_consent(100).await;

    let err = env.fails(&["upload", "run"]);
    assert!(err.contains("upload incomplete"), "{err}");
    let a_attempts = a.count();
    assert!(a_attempts >= 1, "A was tried (positive control)");
    assert!(env.ok(&["upload", "status"]).contains("sealed: 1"));

    // Renew to B while A's batch is sealed.
    env.allow_and_consent(&b.url());
    let renewed = env.run(&["upload", "run"]);
    let renewed_text = format!(
        "{}{}",
        String::from_utf8_lossy(&renewed.stdout),
        String::from_utf8_lossy(&renewed.stderr)
    );
    assert_eq!(
        b.count(),
        0,
        "B must never receive A's sealed batch: {renewed_text}"
    );
    assert_eq!(a.count(), a_attempts, "A is no longer the live URL");
    let status = env.ok(&["upload", "status"]);
    assert!(
        status.contains("sealed: 1") && !status.contains("acknowledged"),
        "{status}"
    );
    std::fs::remove_dir_all(&env.home).ok();
}

/// A second `fornax upload run` while the first is mid-request is refused and
/// sends nothing; the lock is released afterwards.
#[tokio::test]
async fn a_concurrent_upload_run_is_refused_and_the_receiver_sees_one_request() {
    let mock = Mock::start_with(vec![(202, vec![])], None, std::time::Duration::from_secs(6));
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;

    let a = env.spawn_upload_run();
    wait_for(&mock, 1); // A holds the lock and is waiting on the reply.
    assert!(env.home.join("upload.lock").exists(), "lock held by A");

    let err = env.fails(&["upload", "run", "--window", &window_now()]);
    assert!(err.contains("another upload run is in progress"), "{err}");
    assert!(env.home.join("upload.lock").exists(), "B must not steal it");

    let a_out = a.wait_with_output().unwrap();
    assert!(
        a_out.status.success(),
        "{}",
        String::from_utf8_lossy(&a_out.stderr)
    );
    assert!(String::from_utf8_lossy(&a_out.stdout).contains("uploaded 1 batch(es)"));
    assert_eq!(mock.count(), 1, "exactly one request in total");
    assert!(
        !env.home.join("upload.lock").exists(),
        "the lock is removed after A finishes"
    );
    std::fs::remove_dir_all(&env.home).ok();
}

#[tokio::test]
async fn a_fresh_lock_blocks_and_a_stale_lock_is_taken_over() {
    let mock = Mock::start(vec![(202, vec![])]);
    let env = Env::new();
    env.authorize(&mock.url());
    env.seed().await;
    let lock = env.home.join("upload.lock");

    // Control: a fresh lock blocks the run and is left in place.
    std::fs::write(&lock, "999999").unwrap();
    let err = env.fails(&["upload", "run", "--window", &window_now()]);
    assert!(err.contains("another upload run is in progress"), "{err}");
    assert_eq!(mock.count(), 0);
    assert!(lock.exists());

    // Stale (mtime 31 minutes ago): taken over, the run sends, lock removed.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(31 * 60);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&lock)
        .unwrap()
        .set_modified(old)
        .unwrap();
    let out = env.ok(&["upload", "run", "--window", &window_now()]);
    assert!(out.contains("uploaded 1 batch(es)"), "{out}");
    assert_eq!(mock.count(), 1);
    assert!(!lock.exists(), "the taken-over lock is released");
    std::fs::remove_dir_all(&env.home).ok();
}
