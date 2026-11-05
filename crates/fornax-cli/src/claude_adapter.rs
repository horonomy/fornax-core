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

/// The bare `command` name the `fornax-adapter-claude` doc comment documents
/// for wiring into `~/.claude/settings.json` hooks. It is also the file name
/// of the installed hook binary, which is how an absolute-path entry is
/// recognised as Fornax's.
const FORNAX_HOOK_COMMAND: &str = "fornax-hook-claude";

/// True if `command` is a hook command Fornax wrote: the bare name, or an
/// absolute path whose file name is the bare name (an install beside the
/// binary, current or from an earlier install location).
fn is_fornax_command(command: &str) -> bool {
    // An absolute form must be a single shell word, so a wrapper such as
    // `/usr/bin/audit ; /x/fornax-hook-claude` is never mistaken for ours.
    command == FORNAX_HOOK_COMMAND
        || (std::path::Path::new(command).is_absolute()
            && is_shell_safe_path(command)
            && std::path::Path::new(command)
                .file_name()
                .is_some_and(|n| n == FORNAX_HOOK_COMMAND))
}

/// The hook `command` an install will write, and why it is not the preferred form.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ResolvedHook {
    pub command: String,
    /// Set when the bare name is written because no usable sibling was found.
    pub warning: Option<String>,
}

impl ResolvedHook {
    pub fn bare_for(reason: String) -> Self {
        Self {
            command: FORNAX_HOOK_COMMAND.to_string(),
            warning: Some(format!(
                "warning: wrote the bare `{FORNAX_HOOK_COMMAND}` hook command because {reason}; \
                 the hooks only work if `{FORNAX_HOOK_COMMAND}` is on Claude Code's PATH"
            )),
        }
    }

    /// On a bare-name fallback, keeps a working absolute Fornax command already
    /// in `settings_path` rather than downgrading it to a PATH-dependent one.
    pub fn keeping_working_entry(self, settings_path: &std::path::Path) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let Some(warning) = &self.warning else {
            return self;
        };
        let existing = load_settings(settings_path)
            .ok()
            .and_then(|s| configured_command(&s))
            .filter(|c| std::path::Path::new(c).is_absolute());
        match existing {
            Some(c)
                if std::fs::metadata(&c)
                    .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false)
                    && hook_target_problem(std::path::Path::new(&c)).is_none() =>
            {
                Self {
                    warning: Some(format!(
                        "warning: kept the existing hook command {c}; no usable \
                         `{FORNAX_HOOK_COMMAND}` was found beside this binary ({})",
                        warning.trim_start_matches("warning: ")
                    )),
                    command: c,
                }
            }
            _ => self,
        }
    }

    /// Appends the warning, if any, to an install/plan message.
    pub fn annotate(&self, message: String) -> String {
        match &self.warning {
            Some(w) => format!("{message}\n{w}"),
            None => message,
        }
    }
}

/// Claude Code runs a hook command through a shell without quoting, so only
/// characters that no shell treats specially are accepted in an absolute path.
fn is_shell_safe_path(path: &str) -> bool {
    !path.is_empty()
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+@:,=".contains(c))
}

/// Why `path` must not be pinned as a hook command, or `None` if it may be.
/// The file and its directory must be owned by this user or root and not
/// group/world-writable (the `adapter_store` policy), judged on the resolved
/// target, so a swapped binary cannot be run by every Claude Code hook.
pub(crate) fn hook_target_problem(path: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let euid = rustix::process::geteuid().as_raw();
    let check = |p: &std::path::Path, what: &str| -> Option<String> {
        let m = std::fs::symlink_metadata(p).ok()?;
        if m.uid() != euid && m.uid() != 0 {
            return Some(format!("{what} {} is owned by another user", p.display()));
        }
        if m.permissions().mode() & 0o022 != 0 {
            return Some(format!(
                "{what} {} is group- or world-writable",
                p.display()
            ));
        }
        None
    };
    let Ok(real) = path.canonicalize() else {
        return Some(format!("{} cannot be resolved", path.display()));
    };
    if let Some(parent) = real.parent() {
        if let Some(p) = check(parent, "directory") {
            return Some(p);
        }
    }
    check(&real, "file")
}

/// Prefers the `fornax-hook-claude` that sits beside the running (canonical)
/// `fornax` binary, so a downloaded release works without being on PATH.
/// Falls back to the bare name, with a warning, when that sibling is missing,
/// not executable, or has a path a shell would split or expand.
pub(crate) fn resolve_hook_command(current_exe: &std::path::Path) -> ResolvedHook {
    use std::os::unix::fs::PermissionsExt;
    let Some(sibling) = current_exe.parent().map(|d| d.join(FORNAX_HOOK_COMMAND)) else {
        return ResolvedHook::bare_for("the running binary has no directory".to_string());
    };
    let runnable = std::fs::metadata(&sibling)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if !runnable {
        return ResolvedHook::bare_for(format!(
            "no executable `{FORNAX_HOOK_COMMAND}` was found beside {}",
            current_exe.display()
        ));
    }
    if let Some(problem) = hook_target_problem(&sibling) {
        return ResolvedHook::bare_for(format!("it is not safe to pin: {problem}"));
    }
    match sibling.to_str() {
        Some(s) if is_shell_safe_path(s) => ResolvedHook {
            command: s.to_string(),
            warning: None,
        },
        _ => ResolvedHook::bare_for(format!(
            "{} contains whitespace or shell metacharacters that Claude Code would not pass \
             through its shell intact",
            sibling.display()
        )),
    }
}

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
/// file changed since `expected` was taken, stages in an exclusive unique
/// sibling, keeps the rwx bits, and fsyncs (FORNX-420).
///
/// Limits (see `write_guarded`): a symlinked `settings.json` is replaced by a
/// regular file rather than written through, because resolving it could land
/// the write outside `~/.claude`; ownership, ACLs and xattrs are not carried
/// over.
fn save_settings(
    path: &std::path::Path,
    settings: &serde_json::Value,
    expected: &ContentDigest,
) -> anyhow::Result<()> {
    let mut json = serde_json::to_string_pretty(settings)?;
    json.push('\n');
    write_guarded(path, &json, expected)
}

/// The first Fornax command string in this hook group, if any.
fn group_fornax_command(group: &serde_json::Value) -> Option<&str> {
    group
        .get("hooks")?
        .as_array()?
        .iter()
        .filter_map(|h| h.get("command").and_then(|c| c.as_str()))
        .find(|c| is_fornax_command(c))
}

/// True if this hook group already carries a Fornax command entry.
fn group_has_fornax_command(group: &serde_json::Value) -> bool {
    group_fornax_command(group).is_some()
}

/// What `settings.json` says about Fornax's Claude Code hooks, read-only.
/// This is configuration only -- it cannot show that Claude Code ever ran a hook.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Wiring {
    /// No file, or no Fornax hook in it.
    Absent,
    /// The file exists but cannot be read as a JSON object.
    Unreadable(String),
    /// Some, not all, of the wired events carry the Fornax hook.
    Partial { missing: Vec<&'static str> },
    /// Every wired event carries a Fornax hook; `command` is what the first
    /// event's entry runs, which doctor resolves the way Claude Code would.
    Full { command: String },
}

pub(crate) fn wiring_at(path: &std::path::Path) -> Wiring {
    let settings = match load_settings(path) {
        Ok(v) => v,
        Err(e) => return Wiring::Unreadable(e.to_string()),
    };
    let wired = |event: &str| {
        settings
            .get("hooks")
            .and_then(|h| h.get(event))
            .and_then(|e| e.as_array())
            .is_some_and(|groups| groups.iter().any(group_has_fornax_command))
    };
    let missing: Vec<&'static str> = CLAUDE_HOOK_EVENTS
        .iter()
        .copied()
        .filter(|e| !wired(e))
        .collect();
    match missing.len() {
        0 => Wiring::Full {
            command: configured_command(&settings)
                .unwrap_or_else(|| FORNAX_HOOK_COMMAND.to_string()),
        },
        n if n == CLAUDE_HOOK_EVENTS.len() => Wiring::Absent,
        _ => Wiring::Partial { missing },
    }
}

fn configured_command(settings: &serde_json::Value) -> Option<String> {
    CLAUDE_HOOK_EVENTS.iter().find_map(|event| {
        settings
            .get("hooks")?
            .get(event)?
            .as_array()?
            .iter()
            .find_map(group_fornax_command)
            .map(str::to_string)
    })
}

/// The bare command name, which is also the hook binary's file name.
#[cfg(test)]
pub(crate) const fn hook_command() -> &'static str {
    FORNAX_HOOK_COMMAND
}

/// Pre-existing empty structures that `install` found in `settings.json` and
/// that `uninstall` must therefore leave in place if removing the Fornax entry
/// leaves them empty again. Install pushes into a user's empty `Stop: []` (or
/// creates entries inside their `"hooks": {}`), after which nothing in the file
/// can tell that empty array from one Fornax created -- so install remembers.
///
/// This is a keep-list, never a created-list: a missing, stale or corrupt
/// record only means a structure is cleaned up as before, it can never cause a
/// deletion. The record lives in `state_path` next to the settings file and
/// exists only while there is something to remember.
#[derive(Debug, Default, PartialEq, Eq)]
struct KeepEmpty {
    hooks: bool,
    events: std::collections::BTreeSet<String>,
}

impl KeepEmpty {
    fn is_empty(&self) -> bool {
        !self.hooks && self.events.is_empty()
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "hooks": self.hooks, "events": self.events })
    }

    /// Only the documented events are honoured, so a hand-edited record cannot
    /// name anything else.
    fn from_json(value: &serde_json::Value) -> Self {
        Self {
            hooks: value
                .get("hooks")
                .and_then(|h| h.as_bool())
                .unwrap_or(false),
            events: value
                .get("events")
                .and_then(|e| e.as_array())
                .into_iter()
                .flatten()
                .filter_map(|e| e.as_str())
                .filter(|e| CLAUDE_HOOK_EVENTS.contains(e))
                .map(str::to_string)
                .collect(),
        }
    }
}

/// `<dir>/.<file name>.fornax-state` for the settings file at `settings_path`.
fn state_path(settings_path: &std::path::Path) -> std::path::PathBuf {
    let name = settings_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "settings.json".to_string());
    settings_path.with_file_name(format!(".{name}.fornax-state"))
}

/// Reads the record; anything unreadable, oversized or malformed is "nothing
/// to keep", so uninstall can never be blocked by it.
fn load_keep(settings_path: &std::path::Path) -> KeepEmpty {
    const MAX_RECORD_BYTES: u64 = 64 * 1024;
    let path = state_path(settings_path);
    let Ok(meta) = std::fs::metadata(&path) else {
        return KeepEmpty::default();
    };
    if meta.len() > MAX_RECORD_BYTES {
        return KeepEmpty::default();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .map(|v| KeepEmpty::from_json(&v))
        .unwrap_or_default()
}

/// What `before` (the document as install found it) says to keep, merged into
/// the `prior` record. Events that already carry a Fornax group were observed
/// by an earlier install and are left as recorded; every other known event is
/// re-observed, so a stale entry for an event the user has since changed is
/// corrected rather than trusted.
fn observe_keep(before: &serde_json::Value, prior: KeepEmpty) -> KeepEmpty {
    let hooks_obj = before.get("hooks").and_then(|h| h.as_object());
    let has_owned = |event: &str| {
        hooks_obj
            .and_then(|h| h.get(event))
            .and_then(|e| e.as_array())
            .is_some_and(|groups| groups.iter().any(group_has_fornax_command))
    };
    let mut keep = prior;
    if !CLAUDE_HOOK_EVENTS.iter().any(|e| has_owned(e)) {
        keep.hooks = hooks_obj.is_some_and(|h| h.is_empty());
    }
    for event in CLAUDE_HOOK_EVENTS {
        if has_owned(event) {
            continue;
        }
        let empty_array = hooks_obj
            .and_then(|h| h.get(event))
            .and_then(|e| e.as_array())
            .is_some_and(|a| a.is_empty());
        if empty_array {
            keep.events.insert(event.to_string());
        } else {
            keep.events.remove(event);
        }
    }
    keep
}

/// Writes the record, or removes it when there is nothing to remember.
fn store_keep(settings_path: &std::path::Path, keep: &KeepEmpty) -> anyhow::Result<()> {
    let path = state_path(settings_path);
    if keep.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        };
    }
    let expected = crate::guarded_write::digest_of(&path)?;
    let mut json = serde_json::to_string(&keep.to_json())?;
    json.push('\n');
    write_guarded(&path, &json, &expected)
}

/// Idempotently ensures each hook in `CLAUDE_HOOK_EVENTS` runs `command`
/// exactly once, without touching any other group/event already present in
/// `settings`. A Fornax entry with a different command (the bare name, or an
/// earlier install location) is updated in place, and further Fornax entries
/// in the same event are dropped, so an upgrade never fires a hook twice.
///
/// `settings` must already be a JSON object (guaranteed by `load_settings`).
/// If an existing `"hooks"` value, or an existing per-event value, is
/// present but not the shape Claude Code expects (object / array
/// respectively), this refuses to clobber it and returns an error instead —
/// per the "safe failure mode rather than corrupting Claude Code config"
/// constraint.
fn install_claude_hooks(settings: &mut serde_json::Value, command: &str) -> anyhow::Result<()> {
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
        let mut seen = false;
        entries_arr.retain_mut(|group| {
            let Some(group_hooks) = group.get_mut("hooks").and_then(|h| h.as_array_mut()) else {
                return true;
            };
            let had_fornax = group_hooks.iter().any(is_fornax_entry);
            group_hooks.retain_mut(|h| {
                if !is_fornax_entry(h) {
                    return true;
                }
                if seen {
                    return false;
                }
                seen = true;
                if h.get("command").and_then(|c| c.as_str()) != Some(command) {
                    h["command"] = serde_json::Value::String(command.to_string());
                }
                true
            });
            // Only a group this dedupe emptied is dropped; a user's own empty
            // group is not a Fornax entry and is kept.
            !(had_fornax && group_hooks.is_empty())
        });
        if !seen {
            entries_arr.push(serde_json::json!({
                "hooks": [{ "type": "command", "command": command }]
            }));
        }
    }
    Ok(())
}

fn is_fornax_entry(hook: &serde_json::Value) -> bool {
    hook.get("command")
        .and_then(|c| c.as_str())
        .is_some_and(is_fornax_command)
}

/// Removes only Fornax hook entries from `settings`, leaving every other
/// hook group, hook event, and top-level setting exactly as it was. Cleans
/// up only what the removal of a Fornax entry itself emptied: a group, event
/// or `hooks` object that was already empty before (or an event this build
/// does not know) belongs to the user or another tool and is preserved.
/// Containers that were already empty when `install` ran are named in `keep`
/// and stay, so install followed by uninstall restores what the user had.
fn uninstall_claude_hooks(settings: &mut serde_json::Value, keep: &KeepEmpty) {
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
            group_hooks.retain(|h| !is_fornax_entry(h));
            let removed = group_hooks.len() < before;
            removed_here |= removed;
            !(removed && group_hooks.is_empty())
        });
        if removed_here && entries.is_empty() && !keep.events.contains(event) {
            hooks_obj.remove(event);
        }
        removed_any |= removed_here;
    }

    if removed_any && hooks_obj.is_empty() && !keep.hooks {
        settings
            .as_object_mut()
            .expect("checked object above")
            .remove("hooks");
    }
}

/// Computes what `install_at` would do, without writing anything.
pub fn plan_install_at(
    path: &std::path::Path,
    command: &str,
) -> anyhow::Result<AdapterActionResult> {
    let before = load_settings(path)?;
    let mut after = before.clone();
    install_claude_hooks(&mut after, command)?;
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

pub fn install_at(path: &std::path::Path, command: &str) -> anyhow::Result<AdapterActionResult> {
    install_at_with(path, command, || {})
}

/// `install_at` with a hook that runs after the file is read and the new
/// document is planned, immediately before the write -- the window in which
/// another editor can change the file. Tests use it to prove the writer
/// refuses rather than clobbers.
fn install_at_with(
    path: &std::path::Path,
    command: &str,
    before_write: impl FnOnce(),
) -> anyhow::Result<AdapterActionResult> {
    let (before, digest) = load_settings_with_digest(path)?;
    let mut settings = before.clone();
    install_claude_hooks(&mut settings, command)?;
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
    // After the settings write, so a refused write leaves no record; failing to
    // write it is not an install failure -- uninstall then simply cleans up as
    // it did before the record existed.
    let recorded = store_keep(path, &observe_keep(&before, load_keep(path)));
    let note = match recorded {
        Ok(()) => String::new(),
        Err(e) => format!(
            " (could not record pre-existing empty hook structures, uninstall will not restore them: {e})"
        ),
    };
    Ok(AdapterActionResult {
        adapter: "claude-code".to_string(),
        action: "install".to_string(),
        changed: true,
        message: format!(
            "Installed Fornax Claude Code hooks in {}{note}",
            path.display()
        ),
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
    let keep = load_keep(path);
    uninstall_claude_hooks(&mut settings, &keep);
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
    // The hooks are gone, so the record has served its purpose; a leftover one
    // is harmless (the next install re-observes) and not worth failing for.
    let _ = store_keep(path, &KeepEmpty::default());
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
        let result = install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
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
        install_at(&path, FORNAX_HOOK_COMMAND).expect("first install");
        let second = install_at(&path, FORNAX_HOOK_COMMAND).expect("second install");
        assert!(!second.changed);
        let settings = load_settings(&path).expect("load");
        let count = settings["hooks"]["Stop"].as_array().unwrap().len();
        assert_eq!(count, 1, "install must not duplicate the Stop hook group");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn plan_matches_install_without_writing() {
        let path = tmp_settings_path("plan-no-write");
        let plan = plan_install_at(&path, FORNAX_HOOK_COMMAND).expect("plan");
        assert!(plan.changed);
        assert!(!path.exists(), "plan must not create the file");
        let install = install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
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
        let err = install_at_with(&path, FORNAX_HOOK_COMMAND, || {
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
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
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
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
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
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
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

    // FORNX-460: install -> uninstall restores pre-existing empty structures.

    fn cleanup(path: &std::path::Path) {
        std::fs::remove_file(path).ok();
        std::fs::remove_file(state_path(path)).ok();
    }

    fn read_json(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn roundtrip_restores(name: &str, original: serde_json::Value) {
        let path = tmp_settings_path(name);
        write_settings(&path, &original);
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        assert!(uninstall_at(&path).expect("uninstall").changed);
        assert_eq!(read_json(&path), original, "{name}: structure not restored");
        assert!(!state_path(&path).exists(), "{name}: record left behind");
        cleanup(&path);
    }

    #[test]
    fn roundtrip_restores_a_preexisting_empty_known_event() {
        roundtrip_restores(
            "keep-empty-known",
            serde_json::json!({ "hooks": { "Stop": [] }, "model": "keep" }),
        );
    }

    #[test]
    fn roundtrip_restores_a_preexisting_empty_hooks_object() {
        roundtrip_restores(
            "keep-empty-hooks",
            serde_json::json!({ "hooks": {}, "model": "keep" }),
        );
    }

    #[test]
    fn roundtrip_restores_every_kind_of_preexisting_empty_together_with_foreign_data() {
        roundtrip_restores(
            "keep-everything",
            serde_json::json!({
                "model": "keep",
                "hooks": {
                    "Stop": [],
                    "PreToolUse": [{ "hooks": [] }],
                    "FutureEvent": [],
                    "SessionStart": [{ "hooks": [{ "type": "command", "command": "other-tool" }] }]
                }
            }),
        );
    }

    #[test]
    fn roundtrip_on_a_file_with_nothing_empty_writes_no_record_and_restores_it() {
        let path = tmp_settings_path("keep-nothing");
        let original = serde_json::json!({ "model": "keep" });
        write_settings(&path, &original);
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        assert!(
            !state_path(&path).exists(),
            "nothing to remember, so no record"
        );
        uninstall_at(&path).expect("uninstall");
        assert_eq!(read_json(&path), original);
        cleanup(&path);
    }

    #[test]
    fn repeated_cycles_and_a_repeated_install_keep_restoring_the_original() {
        let path = tmp_settings_path("keep-cycles");
        let original = serde_json::json!({ "hooks": { "Stop": [] }, "model": "keep" });
        write_settings(&path, &original);
        for _ in 0..3 {
            install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
            let record = std::fs::read(state_path(&path)).expect("record while installed");
            assert!(
                !install_at(&path, FORNAX_HOOK_COMMAND)
                    .expect("repeat install")
                    .changed
            );
            assert_eq!(std::fs::read(state_path(&path)).unwrap(), record);
            uninstall_at(&path).expect("uninstall");
            assert_eq!(read_json(&path), original);
        }
        cleanup(&path);
    }

    #[test]
    fn missing_record_falls_back_to_cleaning_up_what_the_removal_emptied() {
        let path = tmp_settings_path("keep-no-record");
        write_settings(&path, &serde_json::json!({ "hooks": { "Stop": [] } }));
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        std::fs::remove_file(state_path(&path)).unwrap();
        uninstall_at(&path).expect("uninstall");
        assert_eq!(read_json(&path), serde_json::json!({}));
        cleanup(&path);
    }

    #[test]
    fn corrupt_oversized_or_foreign_record_never_blocks_uninstall_or_deletes_anything() {
        for (name, record) in [
            ("garbage", b"not json {{{".to_vec()),
            ("wrong-shape", br#"["Stop"]"#.to_vec()),
            ("oversized", vec![b' '; 70 * 1024]),
            (
                "unknown-events",
                br#"{"hooks":false,"events":["Bogus","Stop"]}"#.to_vec(),
            ),
        ] {
            let path = tmp_settings_path(&format!("keep-bad-{name}"));
            let foreign = serde_json::json!({ "hooks": [{ "type": "command", "command": "x" }] });
            write_settings(
                &path,
                &serde_json::json!({ "model": "keep", "hooks": { "PreToolUse": [{ "hooks": [{ "type": "command", "command": "x" }] }] } }),
            );
            install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
            std::fs::write(state_path(&path), &record).unwrap();
            assert!(uninstall_at(&path).expect("uninstall").changed, "{name}");
            let after = read_json(&path);
            assert_eq!(after["model"], "keep", "{name}");
            assert_eq!(
                after["hooks"]["PreToolUse"],
                serde_json::json!([foreign]),
                "{name}"
            );
            assert!(
                after["hooks"].get("Stop").is_none() || name == "unknown-events",
                "{name}"
            );
            cleanup(&path);
        }
    }

    #[test]
    fn a_record_naming_an_event_that_still_holds_foreign_data_deletes_nothing() {
        let path = tmp_settings_path("keep-record-vs-foreign");
        write_settings(&path, &serde_json::json!({ "hooks": { "Stop": [] } }));
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        let mut settings = read_json(&path);
        settings["hooks"]["Stop"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!(
                { "hooks": [{ "type": "command", "command": "other-tool" }] }
            ));
        write_settings(&path, &settings);
        uninstall_at(&path).expect("uninstall");
        assert_eq!(
            read_json(&path)["hooks"]["Stop"],
            serde_json::json!([{ "hooks": [{ "type": "command", "command": "other-tool" }] }])
        );
        cleanup(&path);
    }

    #[test]
    fn an_event_the_user_deleted_after_install_is_not_resurrected() {
        let path = tmp_settings_path("keep-user-deleted");
        write_settings(&path, &serde_json::json!({ "hooks": { "Stop": [] } }));
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        let mut settings = read_json(&path);
        settings["hooks"].as_object_mut().unwrap().remove("Stop");
        write_settings(&path, &settings);
        uninstall_at(&path).expect("uninstall");
        assert_eq!(read_json(&path), serde_json::json!({}));
        cleanup(&path);
    }

    #[test]
    fn a_stale_record_is_corrected_by_the_next_install_not_trusted() {
        let path = tmp_settings_path("keep-stale");
        write_settings(&path, &serde_json::json!({ "hooks": { "Stop": [] } }));
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        // The user wipes the file entirely; the old record (Stop) is now stale.
        write_settings(&path, &serde_json::json!({}));
        install_at(&path, FORNAX_HOOK_COMMAND).expect("reinstall");
        uninstall_at(&path).expect("uninstall");
        assert_eq!(
            read_json(&path),
            serde_json::json!({}),
            "Stop was not pre-existing the second time"
        );
        cleanup(&path);
    }

    #[test]
    fn a_stale_record_does_not_touch_a_file_with_no_owned_entry() {
        let path = tmp_settings_path("keep-stale-noop");
        let bytes = write_settings(
            &path,
            &serde_json::json!({ "hooks": { "FutureEvent": [] } }),
        );
        std::fs::write(state_path(&path), br#"{"hooks":true,"events":["Stop"]}"#).unwrap();
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(
            state_path(&path).exists(),
            "a no-op uninstall touches nothing"
        );
        cleanup(&path);
    }

    #[test]
    fn partial_install_from_an_older_build_keeps_newly_observed_empties_only() {
        let path = tmp_settings_path("keep-partial");
        // An earlier build installed Stop only (no record); PreToolUse is the user's empty array.
        write_settings(
            &path,
            &serde_json::json!({ "hooks": { "Stop": [fornax_group()], "PreToolUse": [] } }),
        );
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        uninstall_at(&path).expect("uninstall");
        assert_eq!(
            read_json(&path),
            serde_json::json!({ "hooks": { "PreToolUse": [] } })
        );
        cleanup(&path);
    }

    #[test]
    fn plan_and_a_no_op_install_write_no_record() {
        let path = tmp_settings_path("keep-plan");
        write_settings(&path, &serde_json::json!({ "hooks": { "Stop": [] } }));
        plan_install_at(&path, FORNAX_HOOK_COMMAND).expect("plan");
        assert!(!state_path(&path).exists());
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        std::fs::remove_file(state_path(&path)).unwrap();
        assert!(
            !install_at(&path, FORNAX_HOOK_COMMAND)
                .expect("no-op install")
                .changed
        );
        assert!(!state_path(&path).exists());
        cleanup(&path);
    }

    #[test]
    fn a_refused_install_write_leaves_no_record() {
        let path = tmp_settings_path("keep-refused");
        write_settings(&path, &serde_json::json!({ "hooks": { "Stop": [] } }));
        let racing = path.clone();
        let err = install_at_with(&path, FORNAX_HOOK_COMMAND, move || {
            std::fs::write(&racing, b"{\"edited\":true}").unwrap();
        });
        assert!(err.is_err());
        assert!(!state_path(&path).exists());
        cleanup(&path);
    }

    #[test]
    fn a_stale_hooks_flag_is_corrected_by_the_next_install_not_trusted() {
        let path = tmp_settings_path("keep-stale-hooks-flag");
        write_settings(&path, &serde_json::json!({ "hooks": {} }));
        install_at(&path, FORNAX_HOOK_COMMAND).expect("install");
        // The user wipes the file; the recorded "hooks was an empty object" is now stale.
        write_settings(&path, &serde_json::json!({ "model": "keep" }));
        install_at(&path, FORNAX_HOOK_COMMAND).expect("reinstall");
        uninstall_at(&path).expect("uninstall");
        assert_eq!(read_json(&path), serde_json::json!({ "model": "keep" }));
        cleanup(&path);
    }

    // FORNX-469: the hook command is the binary beside the installed `fornax`.
    fn exe_dir(name: &str, with_hook: bool, mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("fornax-hookpath-{name}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("fornax"), "#!/bin/sh\n").unwrap();
        if with_hook {
            let hook = dir.join(FORNAX_HOOK_COMMAND);
            std::fs::write(&hook, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        dir
    }

    #[test]
    fn resolve_uses_the_executable_sibling_by_absolute_path() {
        let dir = exe_dir("sibling", true, 0o755);
        let r = resolve_hook_command(&dir.join("fornax"));
        assert_eq!(r.command, dir.join(FORNAX_HOOK_COMMAND).to_str().unwrap());
        assert_eq!(r.warning, None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_falls_back_to_the_bare_name_with_a_warning() {
        let missing = exe_dir("missing", false, 0);
        let not_exec = exe_dir("noexec", true, 0o644);
        let spaced = exe_dir("with space", true, 0o755);
        let meta = exe_dir("meta$(x)", true, 0o755);
        for dir in [&missing, &not_exec, &spaced, &meta] {
            let r = resolve_hook_command(&dir.join("fornax"));
            assert_eq!(r.command, FORNAX_HOOK_COMMAND, "{}", dir.display());
            let w = r.warning.as_ref().expect("warning");
            assert!(w.contains("PATH"), "{w}");
            assert!(r.annotate("m".into()).starts_with("m\nwarning:"));
            std::fs::remove_dir_all(dir).ok();
        }
    }

    const ABS: &str = "/opt/fornax/bin/fornax-hook-claude";

    fn commands_for(path: &std::path::Path, event: &str) -> Vec<String> {
        load_settings(path).unwrap()["hooks"][event]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|g| g["hooks"].as_array().unwrap().clone())
            .map(|h| h["command"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn install_writes_the_given_absolute_command_and_is_idempotent() {
        let path = tmp_settings_path("abs-install");
        assert!(install_at(&path, ABS).unwrap().changed);
        assert!(!install_at(&path, ABS).unwrap().changed);
        for event in CLAUDE_HOOK_EVENTS {
            assert_eq!(commands_for(&path, event), vec![ABS.to_string()]);
        }
        assert_eq!(
            wiring_at(&path),
            Wiring::Full {
                command: ABS.to_string()
            }
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn upgrade_replaces_a_bare_or_stale_entry_leaving_exactly_one() {
        let path = tmp_settings_path("upgrade");
        install_at(&path, FORNAX_HOOK_COMMAND).unwrap();
        assert!(plan_install_at(&path, ABS).unwrap().changed);
        assert!(install_at(&path, ABS).unwrap().changed);
        for event in CLAUDE_HOOK_EVENTS {
            assert_eq!(commands_for(&path, event), vec![ABS.to_string()]);
        }
        let newer = "/new/bin/fornax-hook-claude";
        install_at(&path, newer).unwrap();
        for event in CLAUDE_HOOK_EVENTS {
            assert_eq!(commands_for(&path, event), vec![newer.to_string()]);
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn install_collapses_duplicate_fornax_entries_and_keeps_foreign_ones() {
        let path = tmp_settings_path("dedupe");
        let foreign = serde_json::json!({ "type": "command", "command": "other-tool" });
        let fornax = |c: &str| serde_json::json!({ "type": "command", "command": c });
        write_settings(
            &path,
            &serde_json::json!({
                "hooks": { "Stop": [
                    { "hooks": [fornax(FORNAX_HOOK_COMMAND), foreign.clone()] },
                    { "hooks": [fornax(ABS)] },
                ] },
                "model": "x"
            }),
        );
        install_at(&path, ABS).unwrap();
        assert_eq!(
            commands_for(&path, "Stop"),
            vec![ABS.to_string(), "other-tool".to_string()]
        );
        assert_eq!(load_settings(&path).unwrap()["model"], "x");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_removes_bare_absolute_and_stale_entries_but_not_foreign_wrappers() {
        let path = tmp_settings_path("uninstall-mixed");
        let cmd = |c: &str| serde_json::json!({ "hooks": [{ "type": "command", "command": c }] });
        write_settings(
            &path,
            &serde_json::json!({ "hooks": { "Stop": [
                cmd(FORNAX_HOOK_COMMAND),
                cmd(ABS),
                cmd("/old/place/fornax-hook-claude"),
                cmd("/usr/bin/my-fornax-hook-claude"),
                cmd("fornax-hook-claude --extra"),
            ] } }),
        );
        assert!(uninstall_at(&path).unwrap().changed);
        assert_eq!(
            commands_for(&path, "Stop"),
            vec![
                "/usr/bin/my-fornax-hook-claude".to_string(),
                "fornax-hook-claude --extra".to_string()
            ]
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bare_fallback_keeps_an_existing_working_absolute_entry_and_warns() {
        let dir = exe_dir("keep", true, 0o755);
        let existing = dir.join(FORNAX_HOOK_COMMAND);
        let path = tmp_settings_path("keep-existing");
        install_at(&path, existing.to_str().unwrap()).unwrap();
        let no_sibling = exe_dir("nosib", false, 0);
        let r = resolve_hook_command(&no_sibling.join("fornax")).keeping_working_entry(&path);
        assert_eq!(r.command, existing.to_str().unwrap());
        assert!(r.warning.expect("warning").contains("kept the existing"));
        for d in [&dir, &no_sibling] {
            std::fs::remove_dir_all(d).ok();
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn bare_fallback_replaces_an_existing_absolute_entry_that_is_missing() {
        let no_sibling = exe_dir("nosib2", false, 0);
        let path = tmp_settings_path("missing-existing");
        install_at(&path, ABS).unwrap();
        let r = resolve_hook_command(&no_sibling.join("fornax")).keeping_working_entry(&path);
        assert_eq!(r.command, FORNAX_HOOK_COMMAND);
        assert!(r.warning.expect("warning").contains("PATH"));
        std::fs::remove_dir_all(&no_sibling).ok();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_refuses_a_group_writable_file_or_world_writable_directory() {
        use std::os::unix::fs::PermissionsExt;
        let file = exe_dir("gwfile", true, 0o775);
        let dir = exe_dir("wwdir", true, 0o755);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        for d in [&file, &dir] {
            let r = resolve_hook_command(&d.join("fornax"));
            assert_eq!(r.command, FORNAX_HOOK_COMMAND, "{}", d.display());
            assert!(r.warning.expect("warning").contains("writable"));
        }
        // An existing absolute entry that fails the same check is not kept.
        let path = tmp_settings_path("unsafe-existing");
        install_at(&path, file.join(FORNAX_HOOK_COMMAND).to_str().unwrap()).unwrap();
        let no_sibling = exe_dir("nosib3", false, 0);
        let r = resolve_hook_command(&no_sibling.join("fornax")).keeping_working_entry(&path);
        assert_eq!(r.command, FORNAX_HOOK_COMMAND);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        for d in [&file, &dir, &no_sibling] {
            std::fs::remove_dir_all(d).ok();
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrappers_ending_in_the_hook_name_are_foreign_to_install_and_uninstall() {
        let path = tmp_settings_path("wrappers");
        let wrappers = [
            "/usr/bin/audit ; /x/fornax-hook-claude",
            "/usr/bin/audit && /x/fornax-hook-claude",
            "/opt/my tools/fornax-hook-claude",
        ];
        let group = |c: &str| serde_json::json!({ "hooks": [{ "type": "command", "command": c }] });
        write_settings(
            &path,
            &serde_json::json!({ "hooks": { "Stop": wrappers.iter().map(|w| group(w)).collect::<Vec<_>>() } }),
        );
        install_at(&path, ABS).unwrap();
        let after_install = commands_for(&path, "Stop");
        for w in wrappers {
            assert!(after_install.contains(&w.to_string()), "{w}");
        }
        assert!(after_install.contains(&ABS.to_string()));
        uninstall_at(&path).unwrap();
        assert_eq!(
            commands_for(&path, "Stop"),
            wrappers.iter().map(|w| w.to_string()).collect::<Vec<_>>()
        );
        std::fs::remove_file(&path).ok();
    }
}
