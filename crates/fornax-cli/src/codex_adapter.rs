//! Codex adapter install/uninstall (FORNX-16/FORNX-17), routed through the
//! `adapter_registry` (HORO-1621). Straight extraction of the original
//! `install-codex`/`uninstall-codex` implementation, plus `plan_install_at`
//! so `install_at` and `fornax install plan codex` share one computation.

use crate::adapter_registry::AdapterActionResult;

/// Filename marker identifying a Fornax-owned `notify` entry in
/// `~/.codex/config.toml`. Matched by suffix (rather than requiring a
/// byte-for-byte absolute-path match) so uninstall still recognizes an
/// install made from a different checkout of this repo.
const CODEX_NOTIFY_SCRIPT_MARKER: &str = "fornax-codex-notify.sh";

pub fn default_path() -> std::path::PathBuf {
    crate::dirs_home().join(".codex").join("config.toml")
}

/// Absolute path to `scripts/fornax-codex-notify.sh`, resolved relative to
/// this crate's location in the workspace at compile time — matches the
/// documented from-source workflow (`cargo build --workspace` from the
/// repo root; see `docs/dogfooding-codex-notify.md`).
pub fn default_notify_script() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/fornax-codex-notify.sh")
}

/// Parses `path` as a format-preserving TOML document (comments and table
/// ordering survive edits), or an empty document if `path` does not exist.
/// Unlike the Claude adapter's JSON equivalent, a `~/.codex/config.toml`
/// that fails to parse as TOML is always a hard error — there is no
/// sensible "treat it as empty" fallback for a file this consequential.
fn load_codex_config(path: &std::path::Path) -> anyhow::Result<toml_edit::DocumentMut> {
    if !path.exists() {
        return Ok(toml_edit::DocumentMut::new());
    }
    let contents = std::fs::read_to_string(path)?;
    contents.parse::<toml_edit::DocumentMut>().map_err(|e| {
        anyhow::anyhow!(
            "{} is not valid TOML — refusing to touch it: {e}",
            path.display()
        )
    })
}

/// Atomically overwrites `path` with `doc` (write-to-temp then rename).
/// Additionally preserves the original file's Unix permissions on the
/// replacement — a real `~/.codex/config.toml` on this machine is mode
/// 0600, and this repo's own capability-matrix research (FORNX-33) has
/// found plaintext secrets in other Codex on-disk files, so silently
/// widening this file to the process umask's default mode on rename would
/// be a real regression, not a cosmetic one. A freshly created file gets
/// 0600 rather than an umask-dependent default.
fn save_codex_config(path: &std::path::Path, doc: &toml_edit::DocumentMut) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, doc.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map(|m| m.permissions().mode())
            .unwrap_or(0o600);
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// True if `notify`'s first element is a Fornax-owned notify script.
///
/// Compares the path's basename exactly, not a bare `ends_with` on the
/// whole string — a foreign script at e.g. `/opt/my-fornax-codex-notify.sh`
/// would `ends_with(CODEX_NOTIFY_SCRIPT_MARKER)` even though its basename
/// is a different file, which would make uninstall delete a user's real,
/// unrelated `notify` configuration.
fn notify_is_fornax(item: &toml_edit::Item) -> bool {
    item.as_array()
        .and_then(|a| a.get(0))
        .and_then(|v| v.as_str())
        .map(|s| {
            std::path::Path::new(s).file_name().and_then(|f| f.to_str())
                == Some(CODEX_NOTIFY_SCRIPT_MARKER)
        })
        .unwrap_or(false)
}

enum InstallPlan {
    AlreadyInstalled,
    WouldInstall(toml_edit::DocumentMut),
}

/// Codex's `notify` holds exactly one command — its first element is the
/// program, any remaining elements are that program's own extra arguments,
/// not additional commands (see `docs/dogfooding-codex-notify.md`'s
/// live-captured invocation shape). So unlike Claude's per-event hook
/// arrays, this can never safely *add* Fornax alongside an existing foreign
/// `notify` value — doing so would either replace the user's configured
/// command outright or corrupt it by appending Fornax's path as that
/// command's own argument. If `notify` is already set to something other
/// than this exact script, this refuses to touch the file and returns an
/// error instead — for both `plan` and `install`, since this is a safety
/// refusal, not a computed diff.
fn compute_install_plan(
    config_path: &std::path::Path,
    script_path: &std::path::Path,
) -> anyhow::Result<InstallPlan> {
    let mut doc = load_codex_config(config_path)?;
    let script_str = script_path.to_string_lossy().into_owned();

    if let Some(existing) = doc.get("notify") {
        anyhow::ensure!(
            existing.is_array(),
            "existing \"notify\" value in {} is not an array — refusing to overwrite it",
            config_path.display()
        );
        let existing_first = existing
            .as_array()
            .and_then(|a| a.get(0))
            .and_then(|v| v.as_str());
        if existing_first == Some(script_str.as_str()) {
            return Ok(InstallPlan::AlreadyInstalled);
        }
        anyhow::bail!(
            "existing \"notify\" in {} is already wired to {:?} — refusing to overwrite it \
             (Codex's notify holds exactly one command; wire Fornax in manually alongside \
             it, or remove the existing entry first)",
            config_path.display(),
            existing_first.unwrap_or("<non-string entry>")
        );
    }

    let mut arr = toml_edit::Array::new();
    arr.push(script_str);
    doc["notify"] = toml_edit::Item::Value(toml_edit::Value::Array(arr));
    Ok(InstallPlan::WouldInstall(doc))
}

pub fn plan_install_at(
    config_path: &std::path::Path,
    script_path: &std::path::Path,
) -> anyhow::Result<AdapterActionResult> {
    let (changed, message) = match compute_install_plan(config_path, script_path)? {
        InstallPlan::AlreadyInstalled => (
            false,
            format!(
                "Fornax Codex notify already installed in {}",
                config_path.display()
            ),
        ),
        InstallPlan::WouldInstall(_) => (
            true,
            format!(
                "Would install Fornax Codex notify wiring in {}",
                config_path.display()
            ),
        ),
    };
    Ok(mk(config_path, changed, message))
}

fn mk(path: &std::path::Path, changed: bool, message: String) -> AdapterActionResult {
    AdapterActionResult {
        adapter: "codex".to_string(),
        action: "plan".to_string(),
        changed,
        message,
        path: path.display().to_string(),
    }
}

pub fn install_at(
    config_path: &std::path::Path,
    script_path: &std::path::Path,
) -> anyhow::Result<AdapterActionResult> {
    match compute_install_plan(config_path, script_path)? {
        InstallPlan::AlreadyInstalled => Ok(AdapterActionResult {
            adapter: "codex".to_string(),
            action: "install".to_string(),
            changed: false,
            message: format!(
                "Fornax Codex notify already installed in {}",
                config_path.display()
            ),
            path: config_path.display().to_string(),
        }),
        InstallPlan::WouldInstall(doc) => {
            save_codex_config(config_path, &doc)?;
            Ok(AdapterActionResult {
                adapter: "codex".to_string(),
                action: "install".to_string(),
                changed: true,
                message: format!(
                    "Installed Fornax Codex notify wiring in {}",
                    config_path.display()
                ),
                path: config_path.display().to_string(),
            })
        }
    }
}

/// Removes the Fornax `notify` entry from `config_path` iff it is the one
/// `install` added, leaving every other key/table and comment exactly as
/// it was.
pub fn uninstall_at(config_path: &std::path::Path) -> anyhow::Result<AdapterActionResult> {
    if !config_path.exists() {
        // Nothing was ever installed — leave the machine exactly as it
        // was rather than creating a config.toml the user never had.
        return Ok(AdapterActionResult {
            adapter: "codex".to_string(),
            action: "uninstall".to_string(),
            changed: false,
            message: format!(
                "No Fornax Codex notify wiring to remove ({} does not exist)",
                config_path.display()
            ),
            path: config_path.display().to_string(),
        });
    }
    let mut doc = load_codex_config(config_path)?;
    let Some(existing) = doc.get("notify") else {
        return Ok(AdapterActionResult {
            adapter: "codex".to_string(),
            action: "uninstall".to_string(),
            changed: false,
            message: format!(
                "No Fornax Codex notify wiring found in {}",
                config_path.display()
            ),
            path: config_path.display().to_string(),
        });
    };
    if !notify_is_fornax(existing) {
        return Ok(AdapterActionResult {
            adapter: "codex".to_string(),
            action: "uninstall".to_string(),
            changed: false,
            message: format!(
                "No Fornax Codex notify wiring found in {}",
                config_path.display()
            ),
            path: config_path.display().to_string(),
        });
    }
    doc.remove("notify");
    save_codex_config(config_path, &doc)?;
    Ok(AdapterActionResult {
        adapter: "codex".to_string(),
        action: "uninstall".to_string(),
        changed: true,
        message: format!(
            "Removed Fornax Codex notify wiring from {}",
            config_path.display()
        ),
        path: config_path.display().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_config_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-cli-test-codex-{name}-{}.toml",
            uuid::Uuid::new_v4()
        ))
    }

    fn fake_script() -> std::path::PathBuf {
        std::path::PathBuf::from("/opt/fornax/scripts/fornax-codex-notify.sh")
    }

    #[test]
    fn install_wires_notify_into_fresh_config() {
        let path = tmp_config_path("fresh-install");
        let result = install_at(&path, &fake_script()).expect("install");
        assert!(result.changed);
        let doc = load_codex_config(&path).expect("load");
        assert!(notify_is_fornax(doc.get("notify").unwrap()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn install_is_idempotent() {
        let path = tmp_config_path("idempotent-install");
        install_at(&path, &fake_script()).expect("first install");
        let second = install_at(&path, &fake_script()).expect("second install");
        assert!(!second.changed);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn install_refuses_to_overwrite_foreign_notify() {
        let path = tmp_config_path("foreign-notify");
        std::fs::write(&path, "notify = [\"/usr/bin/my-other-tool\"]\n").unwrap();
        let err = install_at(&path, &fake_script()).expect_err("must refuse");
        assert!(err.to_string().contains("refusing to overwrite it"));
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "notify = [\"/usr/bin/my-other-tool\"]\n");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn plan_matches_install_without_writing() {
        let path = tmp_config_path("plan-no-write");
        let plan = plan_install_at(&path, &fake_script()).expect("plan");
        assert!(plan.changed);
        assert!(!path.exists(), "plan must not create the file");
        install_at(&path, &fake_script()).expect("install");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn uninstall_on_never_installed_file_is_a_safe_noop() {
        let path = tmp_config_path("never-installed");
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed);
        assert!(!path.exists());
    }

    #[test]
    fn uninstall_leaves_foreign_notify_untouched() {
        let path = tmp_config_path("uninstall-foreign");
        std::fs::write(&path, "notify = [\"/usr/bin/my-other-tool\"]\n").unwrap();
        let result = uninstall_at(&path).expect("uninstall");
        assert!(!result.changed);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "notify = [\"/usr/bin/my-other-tool\"]\n");
        std::fs::remove_file(&path).ok();
    }
}
