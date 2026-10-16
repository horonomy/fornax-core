//! The Fornax-hook identity predicate, duplicated (not imported) from
//! `crates/fornax-cli/src/codex_hooks.rs`, plus the `hooks.json` reader
//! this crate needs to compute its own *expected* set of hooks before
//! calling `hooks/list`.
//!
//! Deliberately duplicated rather than factored into a shared crate: this
//! crate must depend on no `fornax-*` crate at all (see `Cargo.toml`'s
//! comment and `tests/boundary_invariants.rs`), and `codex_hooks.rs`'s own
//! install path stays untouched (internal-docs ADR-0015 R7). A golden
//! fixture in `crates/fornax-cli/tests/` cross-checks that this duplicate
//! has not drifted looser than the original (`tests/boundary_invariants.rs`
//! documents which test does this).

use std::path::{Path, PathBuf};

/// Must match `crates/fornax-cli/src/codex_hooks.rs::HOOK_BIN` exactly.
pub const HOOK_BIN: &str = "fornax-hook-codex-event";

/// Must match `crates/fornax-cli/src/codex_hooks.rs::EVENTS` exactly —
/// note these are the PascalCase spellings `hooks.json` itself uses, not
/// the RPC's camelCase `eventName` or the `key` field's snake_case.
pub const EVENTS: [&str; 3] = ["PreToolUse", "PostToolUse", "SessionStart"];

/// The snake_case spelling `hooks/list`'s `key` field uses for each of
/// [`EVENTS`], in the same order.
pub const EVENTS_SNAKE: [&str; 3] = ["pre_tool_use", "post_tool_use", "session_start"];

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}: hooks.json is not valid JSON")]
    InvalidJson(PathBuf),
    #[error("{0}: hooks.json root is not a JSON object")]
    NotAnObject(PathBuf),
}

/// One Fornax handler this crate expects `hooks/list` to report on, derived
/// purely from reading `hooks.json` — never from assuming Codex will agree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedHook {
    /// PascalCase, as `hooks.json` spells it (`"PreToolUse"`).
    pub event_pascal: &'static str,
    /// snake_case, as the RPC `key` field spells it (`"pre_tool_use"`).
    pub event_snake: &'static str,
    pub group_idx: usize,
    pub handler_idx: usize,
}

impl ExpectedHook {
    /// The exact `key` string `hooks/list` is expected to report for this
    /// handler, given the canonicalized `hooks.json` path.
    pub fn expected_key(&self, hooks_json_path: &Path) -> String {
        format!(
            "{}:{}:{}:{}",
            hooks_json_path.display(),
            self.event_snake,
            self.group_idx,
            self.handler_idx
        )
    }
}

/// True if `handler`'s `command` resolves (by basename of its first
/// whitespace-separated token) to [`HOOK_BIN`] — same rule as
/// `codex_hooks.rs::handler_is_fornax`.
pub fn handler_is_fornax(handler: &serde_json::Value) -> bool {
    if handler.get("type").and_then(|t| t.as_str()) != Some("command") {
        return false;
    }
    handler
        .get("command")
        .and_then(|c| c.as_str())
        .and_then(|s| s.split_whitespace().next())
        .and_then(|first| Path::new(first).file_name())
        .and_then(|f| f.to_str())
        == Some(HOOK_BIN)
}

/// Reads `hooks_json_path` and returns every Fornax handler found across
/// [`EVENTS`], with its exact positional indices. An absent file, or a
/// file with none of [`EVENTS`] present, is not an error here — it
/// returns an empty list, and the caller (`verdict.rs`) maps that to
/// `fornax_hooks_not_installed`, never to a vacuous `trusted`.
pub fn read_expected_hooks(hooks_json_path: &Path) -> Result<Vec<ExpectedHook>, IdentityError> {
    if !hooks_json_path.exists() {
        return Ok(Vec::new());
    }
    let contents =
        std::fs::read_to_string(hooks_json_path).map_err(|source| IdentityError::Io {
            path: hooks_json_path.to_path_buf(),
            source,
        })?;
    if contents.trim().is_empty() {
        return Ok(Vec::new());
    }
    let root: serde_json::Value = serde_json::from_str(&contents)
        .map_err(|_| IdentityError::InvalidJson(hooks_json_path.to_path_buf()))?;
    let obj = root
        .as_object()
        .ok_or_else(|| IdentityError::NotAnObject(hooks_json_path.to_path_buf()))?;
    let Some(hooks) = obj.get("hooks").and_then(|h| h.as_object()) else {
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for (event_pascal, event_snake) in EVENTS.iter().zip(EVENTS_SNAKE.iter()) {
        let Some(groups) = hooks.get(*event_pascal).and_then(|g| g.as_array()) else {
            continue;
        };
        for (group_idx, group) in groups.iter().enumerate() {
            let Some(handlers) = group.get("hooks").and_then(|h| h.as_array()) else {
                continue;
            };
            for (handler_idx, handler) in handlers.iter().enumerate() {
                if handler_is_fornax(handler) {
                    out.push(ExpectedHook {
                        event_pascal,
                        event_snake,
                        group_idx,
                        handler_idx,
                    });
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_hooks_json(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("hooks.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn missing_file_is_empty_not_an_error() {
        let dir = std::env::temp_dir().join(format!("fht-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hooks.json");
        assert_eq!(read_expected_hooks(&path).unwrap(), Vec::new());
    }

    #[test]
    fn finds_fornax_handler_at_correct_indices() {
        let dir = std::env::temp_dir().join(format!("fht-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_hooks_json(
            &dir,
            r#"{
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"type": "command", "command": "some-other-tool", "timeout": 10}]},
                        {"hooks": [{"type": "command", "command": "fornax-hook-codex-event", "timeout": 5}]}
                    ],
                    "PostToolUse": [
                        {"hooks": [{"type": "command", "command": "fornax-hook-codex-event", "timeout": 5}]}
                    ]
                }
            }"#,
        );
        let found = read_expected_hooks(&path).unwrap();
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].event_pascal, "PreToolUse");
        assert_eq!(found[0].group_idx, 1);
        assert_eq!(found[0].handler_idx, 0);
        assert_eq!(found[1].event_pascal, "PostToolUse");
        assert_eq!(found[1].group_idx, 0);
    }

    #[test]
    fn rejects_lookalike_and_rollout_tailer_commands() {
        let dir = std::env::temp_dir().join(format!("fht-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_hooks_json(
            &dir,
            r#"{
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [
                            {"type": "command", "command": "fornax-hook-codex", "timeout": 5},
                            {"type": "command", "command": "/opt/evil/fornax-hook-codex-event-lookalike", "timeout": 5},
                            {"type": "command", "command": "/usr/local/bin/fornax-hook-codex-event", "timeout": 5}
                        ]}
                    ]
                }
            }"#,
        );
        let found = read_expected_hooks(&path).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].handler_idx, 2);
    }

    #[test]
    fn expected_key_matches_rpc_key_shape() {
        let hook = ExpectedHook {
            event_pascal: "PreToolUse",
            event_snake: "pre_tool_use",
            group_idx: 0,
            handler_idx: 0,
        };
        let path = Path::new("/home/op/.codex/hooks.json");
        assert_eq!(
            hook.expected_key(path),
            "/home/op/.codex/hooks.json:pre_tool_use:0:0"
        );
    }

    #[test]
    fn not_an_object_root_errors() {
        let dir = std::env::temp_dir().join(format!("fht-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_hooks_json(&dir, "[]");
        assert!(matches!(
            read_expected_hooks(&path),
            Err(IdentityError::NotAnObject(_))
        ));
    }

    #[test]
    fn invalid_json_errors() {
        let dir = std::env::temp_dir().join(format!("fht-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = write_hooks_json(&dir, "{not json");
        assert!(matches!(
            read_expected_hooks(&path),
            Err(IdentityError::InvalidJson(_))
        ));
    }
}
