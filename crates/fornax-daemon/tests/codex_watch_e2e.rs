//! FORNX-468: the daemon captures Codex rollouts itself (no manual tailer),
//! only when `codex-watch.json` opts in, only for new activity, once, and
//! through the ingest redaction path. Real daemon binary, isolated
//! `$FORNAX_HOME`, OS-assigned port, bounded polling.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fornax_store::Store;
use serde_json::{json, Value};

mod common;
use common::free_tcp_port;

const SECRET: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

struct Env {
    root: PathBuf,
    home: PathBuf,
    sessions: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Self {
        let root = PathBuf::from("/tmp").join(format!(
            "fnx-cw-{tag}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let home = root.join("fornax");
        let sessions = root.join("codex/sessions/2026/10/25");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&sessions).unwrap();
        Env {
            root,
            home,
            sessions,
        }
    }

    fn opt_in(&self) {
        std::fs::write(
            self.home.join("codex-watch.json"),
            json!({"sessions_dir": self.root.join("codex/sessions")}).to_string(),
        )
        .unwrap();
    }

    fn rollout(&self, name: &str) -> PathBuf {
        self.sessions.join(format!("rollout-{name}.jsonl"))
    }

    fn start_daemon(&self) -> Daemon {
        let port = free_tcp_port();
        let log = std::fs::File::options()
            .create(true)
            .append(true)
            .open(self.home.join("daemon.log"))
            .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_fornax-daemon"))
            .env("FORNAX_HOME", &self.home)
            .env("FORNAX_HTTP_PORT", port.to_string())
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .stdin(Stdio::null())
            .spawn()
            .expect("spawn fornax-daemon");
        let d = Daemon(child);
        let sock = self.home.join("fornax.sock");
        wait_for("daemon socket", Duration::from_secs(15), || sock.exists());
        d
    }

    async fn store(&self) -> Store {
        Store::open(self.home.join("fornax.db")).await.unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).ok();
    }
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_for(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn append_lines(path: &Path, lines: &[Value]) {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    for l in lines {
        writeln!(f, "{l}").unwrap();
    }
}

fn session_meta(id: &str) -> Value {
    json!({"type": "session_meta", "payload": {"id": id, "session_id": id}})
}

fn passing_pair(call_id: &str, extra_output: &str) -> Vec<Value> {
    vec![
        json!({"type": "response_item", "payload": {
            "type": "custom_tool_call", "call_id": call_id, "name": "exec",
            "input": "const r = await tools.shell_command({command:\"pytest -q\",workdir:\"/workspace\",timeout_ms:120000}); text(r)\n"}}),
        json!({"type": "response_item", "payload": {
            "type": "custom_tool_call_output", "call_id": call_id,
            "output": [
                {"type": "input_text", "text": "Script completed\nWall time 0.4 seconds\nOutput:\n"},
                {"type": "input_text", "text": format!("Exit code: 0\n2 passed in 0.02s\n{extra_output}")}]}}),
    ]
}

fn task_complete(text: &str) -> Value {
    json!({"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": text}})
}

async fn findings(env: &Env, session: &str) -> Vec<fornax_store::FindingRow> {
    env.store()
        .await
        .findings_for_session(session)
        .await
        .unwrap_or_default()
}

async fn wait_for_finding(env: &Env, session: &str, count: usize) -> Vec<fornax_store::FindingRow> {
    let start = Instant::now();
    loop {
        let f = findings(env, session).await;
        if f.len() >= count {
            return f;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "no finding for {session} in 20s (have {})",
            f.len()
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Long enough for at least one 5 s scan plus several tail ticks.
async fn settle() {
    tokio::time::sleep(Duration::from_secs(8)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_inert_without_marker() {
    let env = Env::new("inert");
    let _d = env.start_daemon();
    let mut lines = vec![session_meta("cw-inert")];
    lines.extend(passing_pair("c1", ""));
    lines.push(task_complete("All tests passed."));
    append_lines(&env.rollout("inert"), &lines);
    settle().await;
    let store = env.store().await;
    assert_eq!(store.observed_counts().await.unwrap(), (0, 0, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_new_rollout_produces_a_verified_finding_not_review() {
    let env = Env::new("verified");
    env.opt_in();
    let _d = env.start_daemon();
    let mut lines = vec![session_meta("cw-verified")];
    lines.extend(passing_pair("c1", ""));
    lines.push(task_complete("All tests passed."));
    append_lines(&env.rollout("verified"), &lines);
    let f = wait_for_finding(&env, "cw-verified", 1).await;
    assert_eq!(f.len(), 1);
    assert_eq!(
        f[0].verdict, "verified",
        "no hook, no tailer, no handoff downgrade: {}",
        f[0].rationale
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_never_forwards_before_session_meta() {
    let env = Env::new("nometa");
    env.opt_in();
    let _d = env.start_daemon();
    let mut lines = passing_pair("c1", "");
    lines.push(task_complete("All tests passed."));
    append_lines(&env.rollout("nometa"), &lines);
    settle().await;
    assert_eq!(
        env.store().await.observed_counts().await.unwrap(),
        (0, 0, 0)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_does_not_backfill_history_but_follows_the_session_on() {
    let env = Env::new("history");
    env.opt_in();
    // History that exists before the daemon ever ran.
    let mut history = vec![session_meta("cw-history")];
    history.extend(passing_pair("old", ""));
    history.push(task_complete("All tests passed."));
    append_lines(&env.rollout("history"), &history);

    let _d = env.start_daemon();
    settle().await;
    assert!(
        findings(&env, "cw-history").await.is_empty(),
        "pre-existing history must not be ingested"
    );

    // The session continues: identity comes from the replayed prefix.
    let mut next = passing_pair("new", "");
    next.push(task_complete("All tests passed."));
    append_lines(&env.rollout("history"), &next);
    let f = wait_for_finding(&env, "cw-history", 1).await;
    settle().await;
    assert_eq!(f.len(), 1, "exactly the new turn's claim");
    assert_eq!(findings(&env, "cw-history").await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_history_ending_in_an_unterminated_giant_line_is_not_backfilled() {
    let env = Env::new("giantline");
    env.opt_in();
    let mut history = vec![session_meta("cw-giant")];
    history.extend(passing_pair("old", ""));
    history.push(task_complete("All tests passed."));
    let path = env.rollout("giantline");
    append_lines(&path, &history);
    // A line still being written: no newline anywhere in the last 8 MiB.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&vec![b'x'; 9 * 1024 * 1024]).unwrap();
    }

    let _d = env.start_daemon();
    settle().await;
    assert!(
        findings(&env, "cw-giant").await.is_empty(),
        "history before the giant line must not be backfilled"
    );

    // The giant line finishes, then the session goes on.
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"\n").unwrap();
    }
    let mut next = passing_pair("new", "");
    next.push(task_complete("All tests passed."));
    append_lines(&path, &next);
    let f = wait_for_finding(&env, "cw-giant", 1).await;
    settle().await;
    assert_eq!(f.len(), 1, "exactly the new turn's claim");
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_restart_resumes_from_cursor_without_duplicates() {
    let env = Env::new("restart");
    env.opt_in();
    let d = env.start_daemon();
    let mut lines = vec![session_meta("cw-restart")];
    lines.extend(passing_pair("c1", ""));
    lines.push(task_complete("All tests passed."));
    append_lines(&env.rollout("restart"), &lines);
    wait_for_finding(&env, "cw-restart", 1).await;
    // Let the cursor reach disk before the stop.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let before = env.store().await.observed_counts().await.unwrap();
    drop(d);

    let _d2 = env.start_daemon();
    settle().await;
    assert_eq!(findings(&env, "cw-restart").await.len(), 1);
    assert_eq!(env.store().await.observed_counts().await.unwrap(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_redacts_a_secret_before_storage() {
    let env = Env::new("redact");
    env.opt_in();
    let _d = env.start_daemon();
    let mut lines = vec![session_meta("cw-redact")];
    lines.extend(passing_pair("c1", &format!("GITHUB_TOKEN={SECRET}\n")));
    lines.push(task_complete("All tests passed."));
    append_lines(&env.rollout("redact"), &lines);
    wait_for_finding(&env, "cw-redact", 1).await;
    let store = env.store().await;
    let events =
        serde_json::to_string(&store.events_for_session("cw-redact").await.unwrap()).unwrap();
    let evidence = serde_json::to_string(
        &store
            .evidence_for_session("cw-redact")
            .await
            .unwrap()
            .evidence,
    )
    .unwrap();
    assert!(!events.contains(SECRET), "secret reached agent_events");
    assert!(!evidence.contains(SECRET), "secret reached evidence");
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_missing_sessions_dir_is_retried_not_fatal() {
    let env = Env::new("missing");
    std::fs::write(
        env.home.join("codex-watch.json"),
        json!({"sessions_dir": env.root.join("not-yet/sessions")}).to_string(),
    )
    .unwrap();
    let mut d = env.start_daemon();
    settle().await;
    assert!(d.0.try_wait().unwrap().is_none(), "daemon must stay up");
    let late = env.root.join("not-yet/sessions/2026/10/25");
    std::fs::create_dir_all(&late).unwrap();
    let mut lines = vec![session_meta("cw-late")];
    lines.extend(passing_pair("c1", ""));
    lines.push(task_complete("All tests passed."));
    append_lines(&late.join("rollout-late.jsonl"), &lines);
    wait_for_finding(&env, "cw-late", 1).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_reinstall_does_not_backfill_what_happened_while_off() {
    let env = Env::new("reinstall");
    env.opt_in();
    let _d = env.start_daemon();
    let rollout = env.rollout("reinstall");
    let mut turn1 = vec![session_meta("cw-reinstall")];
    turn1.extend(passing_pair("t1", ""));
    turn1.push(task_complete("All tests passed."));
    append_lines(&rollout, &turn1);
    wait_for_finding(&env, "cw-reinstall", 1).await;

    // Capture off (uninstall), a turn happens, capture on again.
    std::fs::remove_file(env.home.join("codex-watch.json")).unwrap();
    settle().await;
    let mut turn2 = passing_pair("t2", "");
    turn2.push(task_complete("All tests passed."));
    append_lines(&rollout, &turn2);
    env.opt_in();
    settle().await;
    assert_eq!(
        findings(&env, "cw-reinstall").await.len(),
        1,
        "the turn written while capture was off must not be ingested"
    );

    let mut turn3 = passing_pair("t3", "");
    turn3.push(task_complete("All tests passed."));
    append_lines(&rollout, &turn3);
    wait_for_finding(&env, "cw-reinstall", 2).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn codex_watch_ignores_a_relative_sessions_dir() {
    let env = Env::new("relative");
    std::fs::write(
        env.home.join("codex-watch.json"),
        json!({"sessions_dir": "codex/sessions"}).to_string(),
    )
    .unwrap();
    let _d = env.start_daemon();
    let mut lines = vec![session_meta("cw-relative")];
    lines.extend(passing_pair("c1", ""));
    lines.push(task_complete("All tests passed."));
    append_lines(&env.rollout("relative"), &lines);
    settle().await;
    assert_eq!(
        env.store().await.observed_counts().await.unwrap(),
        (0, 0, 0)
    );
}
