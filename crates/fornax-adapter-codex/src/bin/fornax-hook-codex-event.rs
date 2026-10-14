//! Codex lifecycle-hook adapter binary (HORO-1712 part B). Invoked once per
//! hook event by Codex itself (registered via `~/.codex/hooks.json`); reads
//! the hook's stdin JSON, normalizes it via
//! `fornax_adapter_codex::CodexHookAdapter` (the `fornax_types::AgentAdapter`
//! contract), and forwards the result to the daemon over the Unix Domain
//! Socket. This binary is transport plumbing only — no translation logic
//! lives here (D5, ADR 0001), same discipline as `fornax-hook-claude`.
//!
//! Deliberately a SEPARATE binary from `fornax-hook-codex` (the long-lived
//! rollout tailer), not a mode flag on it: the two have entirely different
//! process lifecycles (one-shot-per-hook-event vs. long-lived-tail-loop)
//! and, per `fornax_adapter_codex::hook`'s module docs, this binary must
//! NEVER send a `Capabilities` announcement — mixing that invariant into
//! the tailer's own long-running loop would risk a future edit accidentally
//! sending one from the wrong code path.
//!
//! This binary writes nothing to stdout and always exits 0, regardless of
//! outcome — Codex's hook contract may read a `PreToolUse` hook's stdout as
//! an allow/block decision for the tool call; this adapter has no opinion
//! on that and must never accidentally express one.
//!
//! Registered into `~/.codex/hooks.json` by `fornax install codex`
//! (`fornax-cli`'s `codex_hooks` module, HORO-1712 part B) alongside the
//! pre-existing `notify` wiring — additive-only, position-preserving, since
//! that file is shared with other tools (confirmed live: `libra-governor`
//! already has entries there). Installing does not make Codex trust the
//! new hooks automatically; the user approves them via Codex's own
//! `/hooks` command.

use fornax_adapter_codex::CodexHookAdapter;
use fornax_types::{AgentAdapter, NormalizationOutcome};
use std::io::Read;
use tokio::io::AsyncWriteExt;
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
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() || input.trim().is_empty() {
        return; // No stdin payload — nothing to report, exit 0 quietly.
    }
    let raw: serde_json::Value = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => return,
    };

    let mut adapter = CodexHookAdapter;
    let messages = match adapter.normalize("unknown", &raw) {
        NormalizationOutcome::Messages(msgs) => msgs,
        NormalizationOutcome::Ignored { reason: _ } => return,
        NormalizationOutcome::Unrecognized { discriminator } => {
            eprintln!(
                "fornax-hook-codex-event: unrecognized hook payload {discriminator:?}, skipping"
            );
            return;
        }
    };
    if messages.is_empty() {
        return;
    }

    // Best-effort: a daemon that isn't running must never block/fail the
    // agent's own turn, same policy as `fornax-hook-claude`.
    if let Ok(mut stream) = UnixStream::connect(sock_path()).await {
        for msg in messages {
            if let Ok(mut line) = serde_json::to_string(&msg) {
                line.push('\n');
                let _ = stream.write_all(line.as_bytes()).await;
            }
        }
    }
}
