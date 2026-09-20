//! Codex CLI adapter binary (FORNX-29). Codex's hook system is opt-in/
//! unstable and admin-suppressible (docs/research/adapter-capability-matrix.md),
//! so this binary tails the always-on rollout JSONL transcript at
//! `~/.codex/sessions/**/*.jsonl` and forwards normalized messages
//! (via `fornax_adapter_codex::CodexAdapter`, the `fornax_types::AgentAdapter`
//! contract, FORNX-156) to the daemon over the Unix Domain Socket. This
//! binary is transport plumbing only — no translation logic lives here
//! (D5, ADR 0001).
//!
//! Usage: `fornax-hook-codex [--file <rollout.jsonl>]` (defaults to the most
//! recently modified rollout file), runs until interrupted, tailing new lines.

use fornax_adapter_codex::{stamped_capabilities, CodexAdapter};
use fornax_types::{AgentAdapter, IngestMessage, NormalizationOutcome};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

fn sock_path() -> PathBuf {
    let home = std::env::var("FORNAX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".fornax")
        });
    home.join("fornax.sock")
}

fn default_rollout_file() -> Option<PathBuf> {
    let sessions_dir = PathBuf::from(std::env::var("HOME").ok()?).join(".codex/sessions");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in walk_jsonl(&sessions_dir) {
        if let Ok(meta) = std::fs::metadata(&entry) {
            if let Ok(modified) = meta.modified() {
                if newest.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
                    newest = Some((modified, entry));
                }
            }
        }
    }
    newest.map(|(_, p)| p)
}

fn walk_jsonl(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_jsonl(&path));
        } else if path.extension().map(|e| e == "jsonl").unwrap_or(false) {
            out.push(path);
        }
    }
    out
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let file = args
        .iter()
        .position(|a| a == "--file")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .or_else(default_rollout_file);

    let Some(file) = file else {
        eprintln!("fornax-hook-codex: no rollout file found under ~/.codex/sessions");
        return Ok(());
    };
    eprintln!("fornax-hook-codex: tailing {}", file.display());

    let mut adapter = CodexAdapter::new();
    let mut stream: Option<UnixStream> = None;
    let mut caps_sent = false;
    let mut offset: u64 = 0;

    loop {
        if stream.is_none() {
            stream = UnixStream::connect(sock_path()).await.ok();
        }

        let content = tokio::fs::read_to_string(&file).await.unwrap_or_default();
        if (content.len() as u64) > offset {
            let new_part = &content[offset as usize..];
            for line in new_part.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
                    continue;
                };

                let Some(s) = stream.as_mut() else { continue };

                let session_hint = file.display().to_string();
                let outcome = adapter.normalize(&session_hint, &entry);

                if !caps_sent {
                    // Sent once per connection (contrast
                    // fornax-adapter-claude, which announces on every event
                    // because it has no long-lived process to gate on —
                    // both are conforming, see `AgentAdapter::probe`'s doc
                    // on repeated-announcement idempotency).
                    let sid = adapter
                        .known_session_id()
                        .unwrap_or(&session_hint)
                        .to_string();
                    let caps = stamped_capabilities(&adapter, &sid);
                    send(s, &IngestMessage::Capabilities(caps)).await;
                    caps_sent = true;
                }

                match outcome {
                    NormalizationOutcome::Messages(msgs) => {
                        for m in msgs {
                            send(s, &m).await;
                        }
                    }
                    NormalizationOutcome::Ignored { .. } => {}
                    NormalizationOutcome::Unrecognized { discriminator } => {
                        eprintln!(
                            "fornax-hook-codex: unrecognized rollout line shape {discriminator:?}, skipping"
                        );
                    }
                }
            }
            offset = content.len() as u64;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn send(stream: &mut UnixStream, msg: &IngestMessage) {
    if let Ok(mut line) = serde_json::to_string(msg) {
        line.push('\n');
        let _ = stream.write_all(line.as_bytes()).await;
    }
}
