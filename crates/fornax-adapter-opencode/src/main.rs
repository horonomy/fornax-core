//! opencode adapter binary (FORNX-161). Unlike `fornax-hook-claude`
//! (one-shot per hook invocation, stdin) or `fornax-hook-codex` (long-lived,
//! polls/tails a rollout file), this binary is a third connection pattern:
//! a long-lived process, spawned once by the companion JS plugin
//! (`plugin/fornax-capture.js`) at opencode startup, that reads one NDJSON
//! line per real hook invocation from its stdin for the life of the opencode
//! process and forwards normalized `IngestMessage`s to the daemon over the
//! Unix Domain Socket. This binary is transport plumbing only — no
//! translation logic lives here (D5, ADR 0001).
//!
//! Wire the plugin into an opencode project's `opencode.json`:
//! ```json
//! { "plugin": ["./path/to/fornax-capture.js"] }
//! ```
//! and ensure `fornax-hook-opencode` is on `PATH` — the plugin spawns it as
//! a child process and pipes every hook payload to its stdin.

use fornax_adapter_opencode::OpenCodeAdapter;
use fornax_types::{AgentAdapter, NormalizationOutcome};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn sock_path() -> std::path::PathBuf {
    let home = std::env::var("FORNAX_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".fornax")
        });
    home.join("fornax.sock")
}

#[tokio::main]
async fn main() {
    let mut adapter = OpenCodeAdapter::new();
    let mut lines = BufReader::new(tokio::io::stdin()).lines();

    // Best-effort: a daemon that isn't running (or that goes away mid-session)
    // must never block/fail the agent's own turn. Reconnect lazily on demand
    // rather than holding the process open on a failed initial connect.
    let mut stream: Option<UnixStream> = UnixStream::connect(sock_path()).await.ok();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.trim().is_empty() {
            continue;
        }
        let raw: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let messages = match adapter.normalize("unknown", &raw) {
            NormalizationOutcome::Messages(msgs) => msgs,
            NormalizationOutcome::Ignored { reason: _ } => continue,
            NormalizationOutcome::Unrecognized { discriminator } => {
                eprintln!("fornax-hook-opencode: unrecognized hook {discriminator:?}, skipping");
                continue;
            }
        };
        if messages.is_empty() {
            continue;
        }

        if stream.is_none() {
            stream = UnixStream::connect(sock_path()).await.ok();
        }
        if let Some(s) = stream.as_mut() {
            for msg in &messages {
                if let Ok(mut json_line) = serde_json::to_string(msg) {
                    json_line.push('\n');
                    if s.write_all(json_line.as_bytes()).await.is_err() {
                        stream = None;
                        break;
                    }
                }
            }
        }
    }
}
