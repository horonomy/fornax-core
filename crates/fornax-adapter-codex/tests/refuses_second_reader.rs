//! FORNX-468: the standalone tailer must not run beside the daemon's own
//! Codex capture (double ingest + Review downgrade) unless forced.

use std::process::{Command, Stdio};
use std::time::Duration;

fn tmp(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("fornax-second-reader-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn tailer(home: &std::path::Path, extra: &[&str]) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_fornax-hook-codex"))
        .args(["--file", "/nonexistent/rollout.jsonl"])
        .args(extra)
        .env("FORNAX_HOME", home)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn tailer_refuses_while_the_daemon_capture_marker_exists() {
    let home = tmp("marker");
    std::fs::write(home.join("codex-watch.json"), "{}").unwrap();
    let out = tailer(&home, &[]).wait_with_output().unwrap();
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("already captures Codex sessions"), "{err}");
    std::fs::remove_dir_all(&home).ok();
}

#[test]
fn tailer_runs_without_the_marker_and_with_force() {
    for (tag, marker, extra) in [
        ("nomarker", false, vec![]),
        ("force", true, vec!["--force"]),
    ] {
        let home = tmp(tag);
        if marker {
            std::fs::write(home.join("codex-watch.json"), "{}").unwrap();
        }
        let mut child = tailer(&home, &extra);
        std::thread::sleep(Duration::from_millis(600));
        assert!(
            child.try_wait().unwrap().is_none(),
            "{tag}: tailer should keep running"
        );
        child.kill().unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("tailing"),
            "{tag}"
        );
        std::fs::remove_dir_all(&home).ok();
    }
}
