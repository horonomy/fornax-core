//! Codex `~/.codex/hooks.json` install/uninstall for the lifecycle-hook
//! binding (HORO-1712 part B, `fornax-hook-codex-event`).
//!
//! `hooks.json` is shared with other tools — confirmed live on this machine:
//! `libra-governor` already has entries in `PostToolUse`, `Stop` and
//! `UserPromptSubmit`. Codex's `HooksFile` struct denies unknown top-level
//! fields, so there is no marker field this module can add without risking
//! breaking every other tool's hooks the moment Codex refuses to load the
//! file. Instead, a handler is recognized as Fornax's own purely by the
//! basename of its `command` — the same rule `codex_adapter::notify_is_fornax`
//! already uses for `notify`.
//!
//! Codex's hook trust is positional: `~/.codex/config.toml` records
//! `trusted_hash` under a key keyed by `(event, group_idx, handler_idx)`,
//! and the hash itself covers only the hook's own normalized fields (command,
//! timeout, async, …), not file formatting or key order. So install must
//! only ever *append* a new group to each event's array — inserting,
//! reordering, or renumbering would silently invalidate another tool's
//! already-trusted hook. Uninstall mirrors this: removing a Fornax group
//! that sits before a foreign one would shift the foreign group's index and
//! untrust it, so uninstall leaves a `"hooks": []` tombstone in that case
//! instead of removing the array entry.

use crate::adapter_registry::AdapterActionResult;
use crate::guarded_write::{digest_of_bytes, write_guarded, ContentDigest};

/// Basename `codex_owns_handler` matches against — the binary
/// `fornax-hook-codex-event` (not the long-lived rollout tailer
/// `fornax-hook-codex`, which this module never touches).
const HOOK_BIN: &str = "fornax-hook-codex-event";

/// Hook events `CodexHookAdapter::translate` actually turns into an
/// `AgentEvent` (see `crates/fornax-adapter-codex/src/hook.rs`) — every other
/// event (`Stop`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`,
/// `Notification`) is `Ignored` there, so registering Fornax for them would
/// only cost the user a trust prompt for a hook that always no-ops.
const EVENTS: [&str; 3] = ["PreToolUse", "PostToolUse", "SessionStart"];

pub fn default_path() -> std::path::PathBuf {
    crate::dirs_home().join(".codex").join("hooks.json")
}

/// The one group `install` appends to each of [`EVENTS`].
///
/// Fields are chosen deliberately — Codex's trust hash covers them, so
/// changing any of these later forces every already-installed user to
/// re-trust:
/// - bare command name, not an absolute path: the hash stays valid across
///   rebuilds/checkouts (same precedent as Claude's `fornax-hook-claude`,
///   resolved via `sh -lc` PATH lookup);
/// - no `matcher`: matches every tool/source;
/// - `timeout: 5`: Codex's own default is 600s, and this binary only opens a
///   Unix socket and writes — a hung daemon socket must not stall a tool
///   call for up to ten minutes;
/// - synchronous (no `async: true`): keeps PreToolUse/PostToolUse observed
///   in call order.
fn fornax_group() -> serde_json::Value {
    serde_json::json!({
        "hooks": [{ "type": "command", "command": HOOK_BIN, "timeout": 5 }]
    })
}

/// True if `handler`'s `command` resolves (by basename of its first
/// whitespace-separated token) to [`HOOK_BIN`] — accepts both a bare
/// `fornax-hook-codex-event` and an absolute path ending in it, rejects the
/// rollout tailer `fornax-hook-codex` and any other foreign command whose
/// path merely contains this string as a substring.
fn handler_is_fornax(handler: &serde_json::Value) -> bool {
    if handler.get("type").and_then(|t| t.as_str()) != Some("command") {
        return false;
    }
    handler
        .get("command")
        .and_then(|c| c.as_str())
        .and_then(|s| s.split_whitespace().next())
        .and_then(|first| std::path::Path::new(first).file_name())
        .and_then(|f| f.to_str())
        == Some(HOOK_BIN)
}

/// True if `group`'s `hooks` array contains at least one Fornax handler.
fn group_has_fornax_handler(group: &serde_json::Value) -> bool {
    group
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|entries| entries.iter().any(handler_is_fornax))
        .unwrap_or(false)
}

/// True if every handler in `group`'s `hooks` array is Fornax's (an empty
/// array counts as "not all Fornax" — nothing to remove).
fn group_is_all_fornax(group: &serde_json::Value) -> bool {
    group
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|entries| !entries.is_empty() && entries.iter().all(handler_is_fornax))
        .unwrap_or(false)
}

fn load_hooks(path: &std::path::Path) -> anyhow::Result<serde_json::Value> {
    load_hooks_with_digest(path).map(|(value, _)| value)
}

/// As `load_hooks`, also returning the digest of the very bytes that were
/// parsed, so `save_hooks` can refuse if the file changed before it writes.
fn load_hooks_with_digest(
    path: &std::path::Path,
) -> anyhow::Result<(serde_json::Value, ContentDigest)> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((serde_json::json!({}), ContentDigest::absent()));
        }
        Err(e) => return Err(e.into()),
    };
    let digest = digest_of_bytes(&bytes);
    let contents = String::from_utf8(bytes)
        .map_err(|e| anyhow::anyhow!("{} is not valid UTF-8: {e}", path.display()))?;
    if contents.trim().is_empty() {
        return Ok((serde_json::json!({}), digest));
    }
    let value: serde_json::Value = serde_json::from_str(&contents)?;
    anyhow::ensure!(
        value.is_object(),
        "{} does not contain a JSON object at its root — refusing to touch it",
        path.display()
    );
    Ok((value, digest))
}

/// Replaces `path` with `hooks` through [`write_guarded`]: refuses, changing
/// nothing, if the file differs from what `expected` was taken from; stages
/// in a uniquely named exclusive sibling; keeps the existing rwx bits (new
/// files are 0600); and syncs the file and its directory.
///
/// A symlinked `hooks.json` (e.g. dotfiles-managed) is resolved first so the
/// link survives and its target is what gets replaced. The limits documented
/// on `write_guarded` otherwise apply unchanged: the final-check-to-rename
/// window, and no ACL/xattr/ownership carry-over.
fn save_hooks(
    path: &std::path::Path,
    hooks: &serde_json::Value,
    expected: &ContentDigest,
) -> anyhow::Result<()> {
    let real_path = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut json = serde_json::to_string_pretty(hooks)?;
    json.push('\n');
    write_guarded(&real_path, &json, expected)
}

/// Idempotently ensures each event in [`EVENTS`] has one group running
/// [`HOOK_BIN`], appending only — never inserting, reordering, or touching
/// any existing group/event already present in `root`.
///
/// `root` must already be a JSON object (guaranteed by `load_hooks`). If an
/// existing `"hooks"` value, or an existing per-event value, is present but
/// not the shape Codex expects (object / array respectively), this refuses
/// to clobber it and returns an error instead.
fn install_hooks(root: &mut serde_json::Value) -> anyhow::Result<()> {
    let obj = root
        .as_object_mut()
        .expect("caller guarantees root is a JSON object");
    let hooks = obj.entry("hooks").or_insert_with(|| serde_json::json!({}));
    anyhow::ensure!(
        hooks.is_object(),
        "existing \"hooks\" value in hooks.json is not an object — refusing to overwrite it"
    );
    let hooks_obj = hooks.as_object_mut().expect("just checked is_object");

    for event in EVENTS {
        let arr = hooks_obj
            .entry(event)
            .or_insert_with(|| serde_json::json!([]));
        anyhow::ensure!(
            arr.is_array(),
            "existing \"hooks.{event}\" value in hooks.json is not an array — refusing to overwrite it"
        );
        let arr = arr.as_array_mut().expect("just checked is_array");
        let already_installed = arr.iter().any(group_has_fornax_handler);
        if !already_installed {
            arr.push(fornax_group());
        }
    }
    Ok(())
}

/// Reports whether an uninstall left any event's remaining foreign groups
/// shifted down by index — this happens only when the user had hand-merged
/// a Fornax handler into a group that also carries a foreign handler after
/// it, and removing just Fornax's handler collapses that group's own
/// internal handler list (never the top-level group array, so no other
/// group's `group_idx` moves — but the affected group's own handler
/// positions still shift).
#[derive(Default)]
pub struct UninstallReport {
    pub shifted: Vec<&'static str>,
}

/// Removes only Fornax's own groups/handlers from `root`, leaving every
/// other group, event, and top-level key exactly as it was — including
/// foreign groups/events that were already empty, which (unlike the Claude
/// adapter's uninstall) must survive untouched here, since Codex's
/// positional trust means an already-empty foreign group still occupies a
/// real `group_idx`.
fn uninstall_hooks(root: &mut serde_json::Value) -> UninstallReport {
    let mut report = UninstallReport::default();
    let Some(hooks_obj) = root.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return report;
    };

    for event in EVENTS {
        let Some(arr) = hooks_obj.get_mut(event).and_then(|e| e.as_array_mut()) else {
            continue;
        };
        let last_idx = arr.len().saturating_sub(1);
        let mut to_remove: Vec<usize> = Vec::new();
        let mut mutated = false;
        for (idx, group) in arr.iter_mut().enumerate() {
            if !group_has_fornax_handler(group) {
                continue;
            }
            mutated = true;
            if group_is_all_fornax(group) {
                if idx == last_idx {
                    to_remove.push(idx);
                } else {
                    // A foreign group sits after this one — removing the
                    // array entry would shift that foreign group's own
                    // group_idx and untrust it. Tombstone instead.
                    group["hooks"] = serde_json::json!([]);
                }
            } else {
                // Hand-merged: a foreign handler shares this group with
                // ours. Remove only our handler(s); the group itself (and
                // every foreign handler's own handler_idx before ours)
                // survives, but a foreign handler positioned after ours in
                // the same group shifts down.
                let had_foreign_after_ours = {
                    let handlers = group["hooks"].as_array().expect("checked is array above");
                    let our_positions: Vec<usize> = handlers
                        .iter()
                        .enumerate()
                        .filter(|(_, h)| handler_is_fornax(h))
                        .map(|(i, _)| i)
                        .collect();
                    let max_ours = *our_positions.iter().max().unwrap_or(&0);
                    handlers
                        .iter()
                        .skip(max_ours + 1)
                        .any(|h| !handler_is_fornax(h))
                };
                if let Some(handlers) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                    handlers.retain(|h| !handler_is_fornax(h));
                }
                if had_foreign_after_ours {
                    report.shifted.push(event);
                }
            }
        }
        for idx in to_remove.into_iter().rev() {
            arr.remove(idx);
        }
        // Only drop the event key if this function actually removed a
        // Fornax group from it and it is now empty as a result — a foreign
        // event we never touched (including one that was already an empty
        // array) keeps its array exactly as found.
        if mutated && arr.is_empty() {
            hooks_obj.remove(event);
        }
    }

    if hooks_obj.is_empty() {
        root.as_object_mut()
            .expect("checked object above")
            .remove("hooks");
    }
    report
}

pub fn plan_install_at(path: &std::path::Path) -> anyhow::Result<AdapterActionResult> {
    let before = load_hooks(path)?;
    let mut after = before.clone();
    install_hooks(&mut after)?;
    let changed = after != before;
    let message = if changed {
        format!(
            "Would install Fornax Codex hooks in {} (PreToolUse, PostToolUse, SessionStart)",
            path.display()
        )
    } else {
        format!("Fornax Codex hooks already installed in {}", path.display())
    };
    Ok(mk("plan", path, changed, message))
}

fn mk(action: &str, path: &std::path::Path, changed: bool, message: String) -> AdapterActionResult {
    AdapterActionResult {
        adapter: "codex".to_string(),
        action: action.to_string(),
        changed,
        message,
        path: path.display().to_string(),
    }
}

/// Wires Fornax's lifecycle-hook entries into `path`. Returns an error, and
/// writes nothing, if an existing `"hooks"` or per-event value is present
/// but not the shape Codex expects.
pub fn install_at(path: &std::path::Path) -> anyhow::Result<AdapterActionResult> {
    install_at_with(path, || {})
}

/// `before_write` runs between planning and writing; tests use it to change
/// the file inside the window the digest guard must catch.
fn install_at_with(
    path: &std::path::Path,
    before_write: impl FnOnce(),
) -> anyhow::Result<AdapterActionResult> {
    let (before, digest) = load_hooks_with_digest(path)?;
    let mut hooks = before.clone();
    install_hooks(&mut hooks)?;
    if hooks == before {
        return Ok(mk(
            "install",
            path,
            false,
            format!("Fornax Codex hooks already installed in {}", path.display()),
        ));
    }
    before_write();
    save_hooks(path, &hooks, &digest)?;
    let on_path = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|dir| dir.join(HOOK_BIN).is_file()))
        .unwrap_or(false);
    let mut message = format!(
        "Installed Fornax Codex hooks in {} (PreToolUse, PostToolUse, SessionStart). \
         Codex will skip them until you trust them via `/hooks`.",
        path.display()
    );
    if !on_path {
        message.push_str(&format!(
            " Warning: `{HOOK_BIN}` was not found on PATH — hook invocations will fail until it is."
        ));
    }
    Ok(mk("install", path, true, message))
}

/// Removes only Fornax's own entries from `path`, per [`uninstall_hooks`]'s
/// tombstone/hand-merge rules. Never deletes `path` itself, and never
/// touches a `path` that was never installed into.
pub fn uninstall_at(path: &std::path::Path) -> anyhow::Result<AdapterActionResult> {
    uninstall_at_with(path, || {})
}

fn uninstall_at_with(
    path: &std::path::Path,
    before_write: impl FnOnce(),
) -> anyhow::Result<AdapterActionResult> {
    if !path.exists() {
        return Ok(mk(
            "uninstall",
            path,
            false,
            format!(
                "No Fornax Codex hooks to remove ({} does not exist)",
                path.display()
            ),
        ));
    }
    let (before, digest) = load_hooks_with_digest(path)?;
    let mut hooks = before.clone();
    let report = uninstall_hooks(&mut hooks);
    if hooks == before {
        return Ok(mk(
            "uninstall",
            path,
            false,
            format!("No Fornax Codex hooks found in {}", path.display()),
        ));
    }
    before_write();
    save_hooks(path, &hooks, &digest)?;
    let mut message = format!("Removed Fornax Codex hooks from {}", path.display());
    if !report.shifted.is_empty() {
        message.push_str(&format!(
            " (note: {:?} had a Fornax hook hand-merged alongside a foreign one; only Fornax's handler was removed)",
            report.shifted
        ));
    }
    Ok(mk("uninstall", path, true, message))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_hooks_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-cli-test-codex-hooks-{name}-{}.json",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn install_adds_all_documented_events_to_fresh_file() {
        let path = tmp_hooks_path("fresh-install");
        let result = install_at(&path).expect("install");
        assert!(result.changed);
        let hooks = load_hooks(&path).expect("load");
        for event in EVENTS {
            assert!(
                hooks["hooks"][event]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(group_has_fornax_handler),
                "missing hook group for {event}"
            );
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn install_is_idempotent_no_duplicate_groups() {
        let path = tmp_hooks_path("idempotent");
        install_at(&path).expect("first install");
        let before_bytes = std::fs::read(&path).unwrap();
        let second = install_at(&path).expect("second install");
        assert!(!second.changed);
        let after_bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            before_bytes, after_bytes,
            "idempotent install must not rewrite the file"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn plan_matches_install_without_writing() {
        let path = tmp_hooks_path("plan-no-write");
        let plan = plan_install_at(&path).expect("plan");
        assert!(plan.changed);
        assert!(!path.exists(), "plan must not create the file");
        install_at(&path).expect("install");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_on_never_installed_file_is_a_safe_noop() {
        let path = tmp_hooks_path("never-installed");
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed);
        assert!(!path.exists());
    }

    fn canonical_fixture() -> serde_json::Value {
        serde_json::json!({
            "description": "codex hooks",
            "hooks": {
                "PostToolUse": [{
                    "hooks": [{
                        "type": "command",
                        "command": "/opt/libra/bin/libra-governor-hook",
                        "async": true,
                        "timeout": 15
                    }]
                }],
                "Stop": [{ "hooks": [{ "type": "command", "command": "libra-governor-stop" }] }],
                "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "libra-governor-prompt" }] }],
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{ "type": "command", "command": "some-other-tool-hook" }]
                }]
            }
        })
    }

    #[test]
    fn canonical_fixture_foreign_handlers_survive_install_at_same_index() {
        let path = tmp_hooks_path("canonical");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&canonical_fixture()).unwrap(),
        )
        .unwrap();
        install_at(&path).expect("install");
        let after = load_hooks(&path).expect("load");

        assert_eq!(
            after["hooks"]["PostToolUse"][0],
            canonical_fixture()["hooks"]["PostToolUse"][0]
        );
        assert_eq!(after["hooks"]["Stop"], canonical_fixture()["hooks"]["Stop"]);
        assert_eq!(
            after["hooks"]["UserPromptSubmit"],
            canonical_fixture()["hooks"]["UserPromptSubmit"]
        );
        assert_eq!(
            after["hooks"]["PreToolUse"][0],
            canonical_fixture()["hooks"]["PreToolUse"][0]
        );
        assert!(after["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == HOOK_BIN);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn install_refuses_instead_of_clobbering_an_edit_made_after_the_read() {
        let path = tmp_hooks_path("install-clobber");
        std::fs::write(&path, "{}").unwrap();
        let edit = "{\"model\": \"edited-by-user\"}";

        let err = install_at_with(&path, || std::fs::write(&path, edit).unwrap())
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edit);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_refuses_instead_of_clobbering_an_edit_made_after_the_read() {
        let path = tmp_hooks_path("uninstall-clobber");
        install_at(&path).expect("install");
        let edit = "{\"model\": \"edited-by-user\"}";

        let err = uninstall_at_with(&path, || std::fs::write(&path, edit).unwrap())
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), edit);
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn install_and_uninstall_keep_an_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mode_of =
            |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let path = tmp_hooks_path("owner-only");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        install_at(&path).expect("install");
        assert_eq!(mode_of(&path), 0o600);
        uninstall_at(&path).expect("uninstall");
        assert_eq!(mode_of(&path), 0o600);
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn install_never_writes_through_a_symlink_planted_at_the_old_temp_name() {
        let path = tmp_hooks_path("symlink-tmp");
        let victim = tmp_hooks_path("symlink-victim");
        std::fs::write(&victim, "untouched").unwrap();
        let old_tmp = path.with_extension("json.fornax.tmp");
        std::os::unix::fs::symlink(&victim, &old_tmp).unwrap();

        install_at(&path).expect("install");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(std::fs::read_to_string(&path).unwrap().contains("hooks"));
        std::fs::remove_file(&old_tmp).ok();
        std::fs::remove_file(&victim).ok();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_restores_canonical_fixture_exactly() {
        let path = tmp_hooks_path("canonical-roundtrip");
        let original = serde_json::to_string_pretty(&canonical_fixture()).unwrap();
        std::fs::write(&path, &original).unwrap();
        install_at(&path).expect("install");
        uninstall_at(&path).expect("uninstall");
        let restored = std::fs::read_to_string(&path).unwrap();
        let restored_value: serde_json::Value = serde_json::from_str(&restored).unwrap();
        assert_eq!(restored_value, canonical_fixture());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_tombstones_when_foreign_group_appended_after_fornax() {
        let path = tmp_hooks_path("tombstone");
        install_at(&path).expect("install");
        {
            let (mut hooks, digest) = load_hooks_with_digest(&path).expect("load");
            hooks["hooks"]["PreToolUse"].as_array_mut().unwrap().push(
                serde_json::json!({ "hooks": [{ "type": "command", "command": "foreign-tool" }] }),
            );
            save_hooks(&path, &hooks, &digest).unwrap();
        }
        uninstall_at(&path).expect("uninstall");
        let after = load_hooks(&path).expect("load");
        let arr = after["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "foreign group's index must not shift");
        assert_eq!(
            arr[0]["hooks"].as_array().unwrap().len(),
            0,
            "fornax's slot tombstoned, not removed"
        );
        assert_eq!(arr[1]["hooks"][0]["command"], "foreign-tool");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_hand_merged_group_removes_only_fornax_handler() {
        let path = tmp_hooks_path("hand-merged");
        let mut hooks = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [
                        { "type": "command", "command": "foreign-before" },
                        { "type": "command", "command": HOOK_BIN, "timeout": 5 },
                        { "type": "command", "command": "foreign-after" },
                    ]
                }]
            }
        });
        let before = hooks.clone();
        let report = uninstall_hooks(&mut hooks);
        let handlers = hooks["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
        assert_eq!(handlers.len(), 2);
        assert_eq!(handlers[0]["command"], "foreign-before");
        assert_eq!(handlers[1]["command"], "foreign-after");
        assert!(report.shifted.contains(&"PreToolUse"));
        assert_ne!(hooks, before);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_leaves_foreign_only_file_untouched() {
        let path = tmp_hooks_path("foreign-only");
        let original = serde_json::to_string_pretty(&canonical_fixture()).unwrap();
        std::fs::write(&path, &original).unwrap();
        let before_bytes = std::fs::read(&path).unwrap();
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed);
        let after_bytes = std::fs::read(&path).unwrap();
        assert_eq!(before_bytes, after_bytes);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_root_is_a_hard_error_and_file_is_untouched() {
        let path = tmp_hooks_path("malformed");
        std::fs::write(&path, "[]").unwrap();
        let err = install_at(&path).expect_err("must refuse non-object root");
        assert!(err.to_string().contains("does not contain a JSON object"));
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "[]");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn malformed_hooks_value_is_a_hard_error() {
        let path = tmp_hooks_path("malformed-hooks-value");
        std::fs::write(&path, r#"{"hooks": "not-an-object"}"#).unwrap();
        let err = install_at(&path).expect_err("must refuse non-object hooks value");
        assert!(err.to_string().contains("refusing to overwrite it"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn handler_identity_accepts_bare_and_absolute_rejects_rollout_tailer_and_lookalike() {
        let bare = serde_json::json!({ "type": "command", "command": HOOK_BIN });
        let absolute =
            serde_json::json!({ "type": "command", "command": format!("/abs/path/{HOOK_BIN}") });
        let rollout_tailer =
            serde_json::json!({ "type": "command", "command": "fornax-hook-codex" });
        let lookalike = serde_json::json!({ "type": "command", "command": format!("/opt/my-{HOOK_BIN}-wrapper") });

        assert!(handler_is_fornax(&bare));
        assert!(handler_is_fornax(&absolute));
        assert!(!handler_is_fornax(&rollout_tailer));
        assert!(!handler_is_fornax(&lookalike));
    }
}
