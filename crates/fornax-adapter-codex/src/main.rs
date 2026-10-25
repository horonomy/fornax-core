//! Codex CLI adapter binary (FORNX-29). Codex's hook system is opt-in/
//! unstable and admin-suppressible (docs/research/adapter-capability-matrix.md),
//! so this binary tails the always-on rollout JSONL transcript at
//! `~/.codex/sessions/**/*.jsonl` and forwards normalized messages
//! (via `fornax_adapter_codex::CodexAdapter`, the `fornax_types::AgentAdapter`
//! contract, FORNX-156) to the daemon over the Unix Domain Socket. This
//! binary is transport plumbing only — no translation logic lives here
//! (D5, ADR 0001).
//!
//! Usage: `fornax-hook-codex [--file <rollout.jsonl>] [--force]` (defaults to the most
//! recently modified rollout file), runs until interrupted, tailing new lines.

use fornax_adapter_codex::rollout_tail::{read_new_lines, Start, TailCursor};
use fornax_adapter_codex::{stamped_capabilities, CodexAdapter};
use fornax_types::{AgentAdapter, IngestMessage, NormalizationOutcome};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

/// Longest rollout line the tailer will buffer; a longer one is skipped.
const MAX_LINE_BYTES: u64 = 8 * 1024 * 1024;

fn sock_path() -> PathBuf {
    let home = std::env::var("FORNAX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".fornax")
        });
    home.join("fornax.sock")
}

fn default_rollout_file() -> Option<PathBuf> {
    let codex_home = match std::env::var("CODEX_HOME") {
        Ok(h) if !h.is_empty() => PathBuf::from(h),
        _ => PathBuf::from(std::env::var("HOME").ok()?).join(".codex"),
    };
    let sessions_dir = codex_home.join("sessions");
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

    // FORNX-468: when the daemon captures Codex rollouts itself (opt-in marker
    // written by `fornax install codex`), a second reader would store every
    // line twice and, because it holds a long-lived connection, downgrade that
    // session's verdicts to Review.
    if sock_path().with_file_name("codex-watch.json").exists()
        && !args.iter().any(|a| a == "--force")
    {
        eprintln!(
            "fornax-hook-codex: the daemon already captures Codex sessions (codex-watch.json exists); \
             not starting a second reader. Pass --force to run anyway."
        );
        return Ok(());
    }
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
    let mut warned_no_session_id = false;
    let mut cursor: Option<TailCursor> = None;

    loop {
        // FORNX-468: bounded, newline-delimited reads. A half-written last
        // line is left for the next tick instead of being skipped forever, a
        // shrunk/replaced file restarts at 0, and one invalid-UTF-8 line no
        // longer hides the whole file.
        if let Ok(read) = read_new_lines(&file, cursor.as_ref(), Start::Beginning, MAX_LINE_BYTES) {
            cursor = Some(read.cursor);
            for line in read.lines {
                let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) else {
                    continue;
                };

                // FORNX-462: never invent an identity. The rollout path is not
                // a provider-native session id (it embeds the OS username and
                // would split the session from the hook path's UUID), so pass
                // no hint and forward nothing until the stream's own
                // `session_meta` has supplied one. The adapter observes every
                // line whether or not the daemon is reachable, so the id is
                // learned even if the socket is down when `session_meta` is
                // read, and format latching and call correlation are kept.
                let outcome = adapter.normalize("", &entry);
                let Some(sid) = adapter.known_session_id().map(str::to_string) else {
                    if !warned_no_session_id {
                        eprintln!(
                            "fornax-hook-codex: no native session id seen yet; not forwarding until the rollout's session_meta supplies one"
                        );
                        warned_no_session_id = true;
                    }
                    continue;
                };

                // Connect only once an identity exists: a connection that
                // never sends anything makes the daemon treat every session's
                // evidence as possibly incomplete and downgrade their verdicts
                // (HORO-1712 handoff tracking).
                if stream.is_none() {
                    stream = UnixStream::connect(sock_path()).await.ok();
                    caps_sent = false;
                }
                let Some(s) = stream.as_mut() else { continue };

                if !caps_sent {
                    // Sent once per connection (contrast
                    // fornax-adapter-claude, which announces on every event
                    // because it has no long-lived process to gate on —
                    // both are conforming, see `AgentAdapter::probe`'s doc
                    // on repeated-announcement idempotency).
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
