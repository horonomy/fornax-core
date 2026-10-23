//! Claude Code adapter install/uninstall (FORNX-15), now routed through the
//! `adapter_registry` (HORO-1621) instead of being a standalone pair of
//! top-level CLI commands. Behavior is unchanged from the original
//! `install-claude`/`uninstall-claude` implementation — this module is a
//! straight extraction, not a rewrite, plus one addition
//! (`plan_install_at`) that both the registry's `plan`/`doctor` operations
//! and `install_at` itself call, so there is exactly one place that decides
//! "would installing change anything", never two implementations that could
//! silently disagree.

use crate::adapter_registry::AdapterActionResult;
use crate::guarded_write::{digest_of_bytes, write_guarded, ContentDigest};

/// The `command` value the `fornax-adapter-claude` doc comment documents for
/// wiring into `~/.claude/settings.json` hooks.
const FORNAX_HOOK_COMMAND: &str = "fornax-hook-claude";

/// Hook event names the `fornax-adapter-claude` doc comment documents as
/// the wired set. Kept in sync with that doc comment — see
/// `crates/fornax-adapter-claude/src/main.rs`.
const CLAUDE_HOOK_EVENTS: [&str; 5] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
];

pub fn default_path() -> std::path::PathBuf {
    crate::dirs_home().join(".claude").join("settings.json")
}

fn load_settings(path: &std::path::Path) -> anyhow::Result<serde_json::Value> {
    load_settings_with_digest(path).map(|(value, _)| value)
}

/// Parses `path` and returns the digest of the very bytes that were parsed,
/// so `save_settings` can refuse if the file changed before it writes.
fn load_settings_with_digest(
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
    let contents = String::from_utf8(bytes)?;
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

/// Replaces `path` with `settings` through `write_guarded`: refuses if the
/// file changed since `expected` was taken, never writes through a planted
/// temp path, keeps the file's permissions, and fsyncs (FORNX-420).
fn save_settings(
    path: &std::path::Path,
    settings: &serde_json::Value,
    expected: &ContentDigest,
) -> anyhow::Result<()> {
    let mut json = serde_json::to_string_pretty(settings)?;
    json.push('\n');
    write_guarded(path, &json, expected)
}

/// True if this hook group already carries a Fornax command entry.
fn group_has_fornax_command(group: &serde_json::Value) -> bool {
    group
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|entries| {
            entries
                .iter()
                .any(|h| h.get("command").and_then(|c| c.as_str()) == Some(FORNAX_HOOK_COMMAND))
        })
        .unwrap_or(false)
}

/// Idempotently ensures each hook in `CLAUDE_HOOK_EVENTS` has one group
/// running `fornax-hook-claude`, without touching any other group/event
/// already present in `settings`.
///
/// `settings` must already be a JSON object (guaranteed by `load_settings`).
/// If an existing `"hooks"` value, or an existing per-event value, is
/// present but not the shape Claude Code expects (object / array
/// respectively), this refuses to clobber it and returns an error instead —
/// per the "safe failure mode rather than corrupting Claude Code config"
/// constraint.
fn install_claude_hooks(settings: &mut serde_json::Value) -> anyhow::Result<()> {
    let root = settings
        .as_object_mut()
        .expect("caller guarantees settings is a JSON object");
    let hooks = root.entry("hooks").or_insert_with(|| serde_json::json!({}));
    anyhow::ensure!(
        hooks.is_object(),
        "existing \"hooks\" value in settings.json is not an object — refusing to overwrite it"
    );
    let hooks_obj = hooks.as_object_mut().expect("just checked is_object");

    for event in CLAUDE_HOOK_EVENTS {
        let entries = hooks_obj
            .entry(event)
            .or_insert_with(|| serde_json::json!([]));
        anyhow::ensure!(
            entries.is_array(),
            "existing \"hooks.{event}\" value in settings.json is not an array — refusing to overwrite it"
        );
        let entries_arr = entries.as_array_mut().expect("just checked is_array");
        let already_installed = entries_arr.iter().any(group_has_fornax_command);
        if !already_installed {
            entries_arr.push(serde_json::json!({
                "hooks": [{ "type": "command", "command": FORNAX_HOOK_COMMAND }]
            }));
        }
    }
    Ok(())
}

/// Removes only Fornax hook entries from `settings`, leaving every other
/// hook group, hook event, and top-level setting exactly as it was. Cleans
/// up only what the removal of a Fornax entry itself emptied: a group, event
/// or `hooks` object that was already empty before (or an event this build
/// does not know) belongs to the user or another tool and is preserved.
fn uninstall_claude_hooks(settings: &mut serde_json::Value) {
    let Some(hooks_obj) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return;
    };

    let mut removed_any = false;
    for event in CLAUDE_HOOK_EVENTS {
        let Some(entries) = hooks_obj.get_mut(event).and_then(|e| e.as_array_mut()) else {
            continue;
        };
        let mut removed_here = false;
        entries.retain_mut(|group| {
            let Some(group_hooks) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) else {
                return true;
            };
            let before = group_hooks.len();
            group_hooks
                .retain(|h| h.get("command").and_then(|c| c.as_str()) != Some(FORNAX_HOOK_COMMAND));
            let removed = group_hooks.len() < before;
            removed_here |= removed;
            !(removed && group_hooks.is_empty())
        });
        if removed_here && entries.is_empty() {
            hooks_obj.remove(event);
        }
        removed_any |= removed_here;
    }

    if removed_any && hooks_obj.is_empty() {
        settings
            .as_object_mut()
            .expect("checked object above")
            .remove("hooks");
    }
}

/// Computes what `install_at` would do, without writing anything.
pub fn plan_install_at(path: &std::path::Path) -> anyhow::Result<AdapterActionResult> {
    let before = load_settings(path)?;
    let mut after = before.clone();
    install_claude_hooks(&mut after)?;
    let changed = after != before;
    let message = if changed {
        format!(
            "Would install Fornax Claude Code hooks in {}",
            path.display()
        )
    } else {
        format!(
            "Fornax Claude Code hooks already installed in {}",
            path.display()
        )
    };
    Ok(mk(path, changed, message))
}

fn mk(path: &std::path::Path, changed: bool, message: String) -> AdapterActionResult {
    AdapterActionResult {
        adapter: "claude-code".to_string(),
        action: "plan".to_string(),
        changed,
        message,
        path: path.display().to_string(),
    }
}

pub fn install_at(path: &std::path::Path) -> anyhow::Result<AdapterActionResult> {
    install_at_with(path, || {})
}

/// `install_at` with a hook that runs after the file is read and the new
/// document is planned, immediately before the write -- the window in which
/// another editor can change the file. Tests use it to prove the writer
/// refuses rather than clobbers.
fn install_at_with(
    path: &std::path::Path,
    before_write: impl FnOnce(),
) -> anyhow::Result<AdapterActionResult> {
    let (before, digest) = load_settings_with_digest(path)?;
    let mut settings = before.clone();
    install_claude_hooks(&mut settings)?;
    if settings == before {
        return Ok(AdapterActionResult {
            adapter: "claude-code".to_string(),
            action: "install".to_string(),
            changed: false,
            message: format!(
                "Fornax Claude Code hooks already installed in {}",
                path.display()
            ),
            path: path.display().to_string(),
        });
    }
    before_write();
    save_settings(path, &settings, &digest)?;
    Ok(AdapterActionResult {
        adapter: "claude-code".to_string(),
        action: "install".to_string(),
        changed: true,
        message: format!("Installed Fornax Claude Code hooks in {}", path.display()),
        path: path.display().to_string(),
    })
}

pub fn uninstall_at(path: &std::path::Path) -> anyhow::Result<AdapterActionResult> {
    uninstall_at_with(path, || {})
}

fn uninstall_at_with(
    path: &std::path::Path,
    before_write: impl FnOnce(),
) -> anyhow::Result<AdapterActionResult> {
    if !path.exists() {
        // Nothing was ever installed — leave the machine exactly as it was
        // rather than creating a settings.json the user never had.
        return Ok(AdapterActionResult {
            adapter: "claude-code".to_string(),
            action: "uninstall".to_string(),
            changed: false,
            message: format!(
                "No Fornax Claude Code hooks to remove ({} does not exist)",
                path.display()
            ),
            path: path.display().to_string(),
        });
    }
    let (before, digest) = load_settings_with_digest(path)?;
    let mut settings = before.clone();
    uninstall_claude_hooks(&mut settings);
    if settings == before {
        return Ok(AdapterActionResult {
            adapter: "claude-code".to_string(),
            action: "uninstall".to_string(),
            changed: false,
            message: format!("No Fornax Claude Code hooks found in {}", path.display()),
            path: path.display().to_string(),
        });
    }
    before_write();
    save_settings(path, &settings, &digest)?;
    Ok(AdapterActionResult {
        adapter: "claude-code".to_string(),
        action: "uninstall".to_string(),
        changed: true,
        message: format!("Removed Fornax Claude Code hooks from {}", path.display()),
        path: path.display().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_settings_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-cli-test-{name}-{}.json",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn install_adds_all_documented_hooks_to_fresh_file() {
        let path = tmp_settings_path("fresh-install");
        let result = install_at(&path).expect("install");
        assert!(result.changed);
        let settings = load_settings(&path).expect("load");
        for event in CLAUDE_HOOK_EVENTS {
            assert!(
                settings["hooks"][event]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(group_has_fornax_command),
                "missing hook group for {event}"
            );
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn install_is_idempotent_no_duplicate_entries() {
        let path = tmp_settings_path("idempotent-install");
        install_at(&path).expect("first install");
        let second = install_at(&path).expect("second install");
        assert!(!second.changed);
        let settings = load_settings(&path).expect("load");
        let count = settings["hooks"]["Stop"].as_array().unwrap().len();
        assert_eq!(count, 1, "install must not duplicate the Stop hook group");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn plan_matches_install_without_writing() {
        let path = tmp_settings_path("plan-no-write");
        let plan = plan_install_at(&path).expect("plan");
        assert!(plan.changed);
        assert!(!path.exists(), "plan must not create the file");
        let install = install_at(&path).expect("install");
        assert!(install.changed);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_on_never_installed_file_is_a_safe_noop() {
        let path = tmp_settings_path("never-installed");
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed);
        assert!(!path.exists());
    }

    #[test]
    fn install_refuses_instead_of_clobbering_an_edit_made_after_the_read() {
        let path = tmp_settings_path("clobber");
        std::fs::write(&path, r#"{"model":"opus"}"#).unwrap();
        let err = install_at_with(&path, || {
            std::fs::write(&path, r#"{"model":"opus","env":{"USER_EDIT":"1"}}"#).unwrap();
        })
        .expect_err("must refuse");
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            r#"{"model":"opus","env":{"USER_EDIT":"1"}}"#
        );
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn install_and_uninstall_keep_an_owner_only_settings_file_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp_settings_path("mode");
        std::fs::write(&path, r#"{"env":{"K":"v"}}"#).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        install_at(&path).expect("install");
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        uninstall_at(&path).expect("uninstall");
        assert_eq!(mode(&path), 0o600);
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn install_never_writes_through_a_symlink_planted_at_the_old_temp_name() {
        let dir =
            std::env::temp_dir().join(format!("fornax-cli-test-symlink-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "untouched").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("settings.json.tmp")).unwrap();
        install_at(&path).expect("install");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(load_settings(&path).unwrap()["hooks"]["Stop"].is_array());
        std::fs::remove_dir_all(&dir).ok();
    }

    // FW-EMPTY-01: uninstall must only remove what an owned Fornax entry's
    // removal empties. Pre-existing empty events/groups belong to the user
    // or to other tools (including events a newer Claude Code adds).
    fn fornax_group() -> serde_json::Value {
        serde_json::json!({ "hooks": [{ "type": "command", "command": FORNAX_HOOK_COMMAND }] })
    }

    fn write_settings(path: &std::path::Path, value: &serde_json::Value) -> Vec<u8> {
        let bytes = serde_json::to_vec_pretty(value).unwrap();
        std::fs::write(path, &bytes).unwrap();
        bytes
    }

    #[test]
    fn uninstall_without_an_owned_entry_leaves_unowned_empties_byte_identical() {
        let path = tmp_settings_path("fw-empty-none-owned");
        let before = write_settings(
            &path,
            &serde_json::json!({
                "hooks": { "FutureEvent": [], "PreToolUse": [], "Stop": [{ "hooks": [] }] },
                "model": "keep"
            }),
        );
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed, "nothing owned, so nothing to change");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_without_an_owned_entry_keeps_an_empty_hooks_object() {
        let path = tmp_settings_path("fw-empty-hooks-object");
        let before = write_settings(&path, &serde_json::json!({ "hooks": {}, "model": "keep" }));
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_removes_only_the_owned_entry_and_keeps_foreign_and_empty_data() {
        let path = tmp_settings_path("fw-empty-mixed");
        let foreign = serde_json::json!({ "matcher": "Bash", "hooks": [{ "type": "command", "command": "other-tool" }] });
        write_settings(
            &path,
            &serde_json::json!({
                "hooks": {
                    "FutureEvent": [],
                    "PreToolUse": [{ "hooks": [] }, fornax_group()],
                    "PostToolUse": [foreign.clone(), fornax_group()],
                    "Stop": [fornax_group()]
                },
                "model": "keep"
            }),
        );
        let result = uninstall_at(&path).expect("uninstall");
        assert!(result.changed);
        let after = load_settings(&path).unwrap();
        assert_eq!(
            after,
            serde_json::json!({
                "hooks": {
                    "FutureEvent": [],
                    "PreToolUse": [{ "hooks": [] }],
                    "PostToolUse": [foreign]
                },
                "model": "keep"
            })
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_after_install_still_cleans_up_what_the_owned_removal_emptied() {
        let path = tmp_settings_path("fw-empty-roundtrip");
        write_settings(&path, &serde_json::json!({ "model": "keep" }));
        install_at(&path).expect("install");
        uninstall_at(&path).expect("uninstall");
        assert_eq!(
            load_settings(&path).unwrap(),
            serde_json::json!({ "model": "keep" })
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_keeps_unowned_empties_when_the_owned_removal_empties_hooks_otherwise() {
        let path = tmp_settings_path("fw-empty-hooks-key");
        write_settings(
            &path,
            &serde_json::json!({ "hooks": { "Stop": [fornax_group()] }, "model": "keep" }),
        );
        uninstall_at(&path).expect("uninstall");
        assert_eq!(
            load_settings(&path).unwrap(),
            serde_json::json!({ "model": "keep" })
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_keeps_the_hooks_object_when_only_an_unowned_empty_event_remains() {
        let path = tmp_settings_path("fw-empty-hooks-key-kept");
        write_settings(
            &path,
            &serde_json::json!({
                "hooks": { "FutureEvent": [], "Stop": [fornax_group()] },
                "model": "keep"
            }),
        );
        uninstall_at(&path).expect("uninstall");
        assert_eq!(
            load_settings(&path).unwrap(),
            serde_json::json!({ "hooks": { "FutureEvent": [] }, "model": "keep" })
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_removes_every_owned_command_but_keeps_a_foreign_hook_in_the_same_group() {
        let path = tmp_settings_path("fw-empty-shared-group");
        let foreign = serde_json::json!({ "type": "command", "command": "other-tool" });
        let owned = serde_json::json!({ "type": "command", "command": FORNAX_HOOK_COMMAND });
        write_settings(
            &path,
            &serde_json::json!({
                "hooks": {
                    "Stop": [
                        { "matcher": "x", "hooks": [owned.clone(), foreign.clone(), owned.clone()] },
                        fornax_group()
                    ]
                }
            }),
        );
        uninstall_at(&path).expect("uninstall");
        assert_eq!(
            load_settings(&path).unwrap(),
            serde_json::json!({ "hooks": { "Stop": [{ "matcher": "x", "hooks": [foreign] }] } })
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_leaves_odd_shapes_untouched() {
        let path = tmp_settings_path("fw-empty-odd-shapes");
        let before = write_settings(
            &path,
            &serde_json::json!({
                "hooks": {
                    "PreToolUse": null,
                    "PostToolUse": "not-an-array",
                    "Stop": [null, 7, { "matcher": "only" }, { "hooks": "nope" }]
                }
            }),
        );
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        std::fs::remove_file(&path).ok();
    }
}
