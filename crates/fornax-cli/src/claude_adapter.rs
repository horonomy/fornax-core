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
    if !path.exists() {
        return Ok(serde_json::json!({}));
    }
    let contents = std::fs::read_to_string(path)?;
    if contents.trim().is_empty() {
        return Ok(serde_json::json!({}));
    }
    let value: serde_json::Value = serde_json::from_str(&contents)?;
    anyhow::ensure!(
        value.is_object(),
        "{} does not contain a JSON object at its root — refusing to touch it",
        path.display()
    );
    Ok(value)
}

/// Atomically overwrites `path` with `settings` (write-to-temp then rename)
/// so a crash or concurrent read never observes a half-written
/// `~/.claude/settings.json`.
fn save_settings(path: &std::path::Path, settings: &serde_json::Value) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut json = serde_json::to_string_pretty(settings)?;
    json.push('\n');
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
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
/// up groups/events left empty by the removal, but never removes a group
/// that still carries another tool's hook entry.
fn uninstall_claude_hooks(settings: &mut serde_json::Value) {
    let Some(hooks_obj) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) else {
        return;
    };

    for event in CLAUDE_HOOK_EVENTS {
        let Some(entries) = hooks_obj.get_mut(event).and_then(|e| e.as_array_mut()) else {
            continue;
        };
        for group in entries.iter_mut() {
            if let Some(group_hooks) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) {
                group_hooks.retain(|h| {
                    h.get("command").and_then(|c| c.as_str()) != Some(FORNAX_HOOK_COMMAND)
                });
            }
        }
        entries.retain(|group| {
            group
                .get("hooks")
                .and_then(|h| h.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(true)
        });
    }

    hooks_obj.retain(|_, v| v.as_array().map(|a| !a.is_empty()).unwrap_or(true));
    if hooks_obj.is_empty() {
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
    let before = load_settings(path)?;
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
    save_settings(path, &settings)?;
    Ok(AdapterActionResult {
        adapter: "claude-code".to_string(),
        action: "install".to_string(),
        changed: true,
        message: format!("Installed Fornax Claude Code hooks in {}", path.display()),
        path: path.display().to_string(),
    })
}

pub fn uninstall_at(path: &std::path::Path) -> anyhow::Result<AdapterActionResult> {
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
    let before = load_settings(path)?;
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
    save_settings(path, &settings)?;
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
}
