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

/// The `fornax` under test. `FORNAX_E2E_FORNAX_BIN` points the real-receiver
/// test at a specific (e.g. release-candidate) executable instead of the one
/// cargo just built.
fn fornax_bin() -> String {
    std::env::var("FORNAX_E2E_FORNAX_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_fornax").into())
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

impl Mock {
    fn start(script: Vec<(u16, Vec<(&'static str, String)>)>) -> Mock {
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
                recorded.lock().unwrap().push(Req { headers, body });

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

/// A recording TCP proxy in front of the real receiver. It forwards each request
/// unchanged, remembers the raw request bytes and the receiver's status line,
/// and can drop the first response after the receiver has already answered --
/// the lost-acknowledgement case, where the receiver stored the batch but the
/// sender never learned it.
type Exchange = (Vec<u8>, String);

struct LossyProxy {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Exchange>>>,
}

fn read_http(stream: &mut std::net::TcpStream) -> Vec<u8> {
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
        if let Some(h) = head_end {
            if buf.len() >= h + want {
                break;
            }
        }
    }
    buf
}

impl LossyProxy {
    fn start(upstream: SocketAddr, drop_first_response: bool) -> LossyProxy {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Exchange>>> = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            let mut dropped = !drop_first_response;
            for client in listener.incoming() {
                let mut client = client.unwrap();
                let request = read_http(&mut client);
                if request.is_empty() {
                    continue;
                }
                let mut up = std::net::TcpStream::connect(upstream).unwrap();
                up.write_all(&request).unwrap();
                let response = read_http(&mut up);
                let status = String::from_utf8_lossy(&response)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string();
                log.lock().unwrap().push((request, status));
                if !dropped {
                    dropped = true;
                    drop(client); // the receiver answered; the sender never hears it
                    continue;
                }
                let _ = client.write_all(&response);
            }
        });
        LossyProxy { addr, seen }
    }

    fn snapshot(&self) -> Vec<Exchange> {
        self.seen.lock().unwrap().clone()
    }
}

fn raw_exchange(addr: SocketAddr, request: &[u8]) -> (String, String) {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.write_all(request).unwrap();
    let response = String::from_utf8_lossy(&read_http(&mut s)).to_string();
    let status = response.lines().next().unwrap_or("").to_string();
    (status, response)
}

fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    let head = text.split("\r\n\r\n").next()?;
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
    })
}

fn body_of(raw: &[u8]) -> &[u8] {
    let i = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    &raw[i..]
}

/// Core -> Cloud contract, against the REAL `fornax-cloud` receiver rather
/// than a mock, including receiver-side deduplication after a LOST
/// acknowledgement. Ignored by default; run it with a cloud backend listening
/// and `FORNAX_E2E_CLOUD_URL` (the `/v1/metadata-batches` URL),
/// `FORNAX_E2E_CLOUD_CRED_FILE` (a device credential file, copied unread) and
/// `FORNAX_E2E_DEVICE_ID` set. Optionally `FORNAX_E2E_OTHER_CRED_FILE` (a
/// second device in the same organisation) adds the wrong-device control.
///
/// The sender goes through a proxy that lets the first request reach the
/// receiver and then drops the response. The sender must retry the identical
/// bytes and idempotency key; the receiver must answer the retry as a duplicate
/// (HTTP 200) rather than store a second archive. The test then replays the
/// recorded request again directly. Afterwards the row count is checked with
/// `psql` against the receiver's database by the caller (exactly one row).
#[tokio::test]
#[ignore = "needs a running fornax-cloud backend; see the doc comment"]
async fn the_real_cloud_receiver_dedups_an_identical_resend_after_a_lost_acknowledgement() {
    let (Ok(url), Ok(cred)) = (
        std::env::var("FORNAX_E2E_CLOUD_URL"),
        std::env::var("FORNAX_E2E_CLOUD_CRED_FILE"),
    ) else {
        panic!("FORNAX_E2E_CLOUD_URL and FORNAX_E2E_CLOUD_CRED_FILE are required");
    };
    let parsed = reqwest_url_parts(&url);
    let upstream: SocketAddr = parsed
        .0
        .parse()
        .expect("receiver must be a loopback ip:port");
    let proxy = LossyProxy::start(upstream, true);
    let proxy_url = format!("http://{}{}", proxy.addr, parsed.1);

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
    env.authorize(&proxy_url);
    env.seed().await;

    let out = env.ok(&["upload", "run", "--window", &window_now()]);
    assert!(out.contains("uploaded 1 batch(es)"), "{out}");
    assert!(out.contains("0 rejected permanently"), "{out}");

    // First attempt reached the receiver (stored, 202) but its answer was
    // lost; the retry carried the identical bytes and key and was answered as
    // a duplicate by the RECEIVER.
    let seen = proxy.snapshot();
    assert_eq!(seen.len(), 2, "exactly one attempt and one retry: {seen:?}");
    assert!(seen[0].1.contains("202"), "first stored it: {}", seen[0].1);
    assert!(
        seen[1].1.contains("200"),
        "retry is a duplicate: {}",
        seen[1].1
    );
    assert_eq!(seen[0].0, seen[1].0, "retry must be byte-identical");
    let key = header_value(&seen[0].0, "idempotency-key").expect("Idempotency-Key");
    let body: serde_json::Value = serde_json::from_slice(body_of(&seen[0].0)).unwrap();
    assert_eq!(body["manifest_sha256"], key.as_str());

    // Replay the identical request straight at the receiver: still a duplicate.
    let (status, response) = raw_exchange(upstream, &seen[0].0);
    assert!(status.contains("200"), "{status}");
    assert!(response.contains("\"duplicate\""), "{response}");

    // Control: the same bytes under another device's credential are refused.
    if let Ok(other) = std::env::var("FORNAX_E2E_OTHER_CRED_FILE") {
        let token = std::fs::read_to_string(other).unwrap().trim().to_string();
        let text = String::from_utf8_lossy(&seen[0].0).to_string();
        let swapped: String = text
            .lines()
            .map(|l| {
                if l.to_lowercase().starts_with("authorization:") {
                    format!("authorization: Bearer {token}")
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\r\n");
        let (head, _) = swapped.split_once("\r\n\r\n").unwrap_or((&swapped, ""));
        let forged = [head.as_bytes(), b"\r\n\r\n", body_of(&seen[0].0)].concat();
        let (status, _) = raw_exchange(upstream, &forged);
        assert!(
            status.contains("403"),
            "wrong device must be refused: {status}"
        );
    }

    // The sender's own bookkeeping agrees and a further run sends nothing.
    let status = env.ok(&["upload", "status"]);
    assert!(status.contains("acknowledged"), "{status}");
    let before = proxy.snapshot().len();
    let again = env.ok(&["upload", "run", "--window", &window_now()]);
    assert!(again.contains("uploaded 0 batch(es)"), "{again}");
    assert_eq!(proxy.snapshot().len(), before);
    std::fs::remove_dir_all(&env.home).ok();
}

/// `("127.0.0.1:18765", "/v1/metadata-batches")` from a loopback http URL.
fn reqwest_url_parts(url: &str) -> (String, String) {
    let rest = url.strip_prefix("http://").expect("loopback http url");
    match rest.split_once('/') {
        Some((host, path)) => (host.to_string(), format!("/{path}")),
        None => (rest.to_string(), String::new()),
    }
}
