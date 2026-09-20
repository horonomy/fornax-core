//! Claude Code hook adapter binary (FORNX-28). Invoked as a hook command;
//! reads the hook's stdin JSON, normalizes it via `fornax_adapter_claude::ClaudeAdapter`
//! (the `fornax_types::AgentAdapter` contract, FORNX-156), and forwards the
//! result to the daemon over the Unix Domain Socket. This binary is
//! transport plumbing only — no translation logic lives here (D5, ADR 0001).
//!
//! Wire into `~/.claude/settings.json` by running `fornax install-claude`
//! (FORNX-15) — it idempotently adds the hook entries below without
//! touching any other hook or setting already in that file. Run
//! `fornax uninstall-claude` to remove them again and return Claude Code to
//! a clean state. The resulting shape:
//! ```json
//! "PreToolUse":       [{ "hooks": [{ "type": "command", "command": "fornax-hook-claude" }] }],
//! "PostToolUse":      [{ "hooks": [{ "type": "command", "command": "fornax-hook-claude" }] }],
//! "Stop":             [{ "hooks": [{ "type": "command", "command": "fornax-hook-claude" }] }],
//! "SessionStart":     [{ "hooks": [{ "type": "command", "command": "fornax-hook-claude" }] }],
//! "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "fornax-hook-claude" }] }]
//! ```

use fornax_adapter_claude::ClaudeAdapter;
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

    let mut adapter = ClaudeAdapter;
    let messages = match adapter.normalize("unknown", &raw) {
        NormalizationOutcome::Messages(msgs) => msgs,
        NormalizationOutcome::Ignored { reason: _ } => {
            return;
        }
        NormalizationOutcome::Unrecognized { discriminator } => {
            eprintln!(
                "fornax-hook-claude: unrecognized hook_event_name {discriminator:?}, skipping"
            );
            return;
        }
    };
    if messages.is_empty() {
        return;
    }

    // Best-effort: a daemon that isn't running must never block/fail the
    // agent's own turn. Fire-and-forget, swallow connection errors.
    if let Ok(mut stream) = UnixStream::connect(sock_path()).await {
        for msg in messages {
            if let Ok(mut line) = serde_json::to_string(&msg) {
                line.push('\n');
                let _ = stream.write_all(line.as_bytes()).await;
            }
        }
    }
}
