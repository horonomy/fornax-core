//! Codex adapter install/uninstall (FORNX-16/FORNX-17), routed through the
//! `adapter_registry` (HORO-1621). Straight extraction of the original
//! `install-codex`/`uninstall-codex` implementation, plus `plan_install_at`
//! so `install_at` and `fornax adapter plan codex` share one computation.

use crate::adapter_registry::AdapterActionResult;
use crate::guarded_write::{digest_of_bytes, write_guarded, ContentDigest};

/// Filename marker identifying a Fornax-owned `notify` entry in
/// `~/.codex/config.toml`. Matched by suffix (rather than requiring a
/// byte-for-byte absolute-path match) so uninstall still recognizes an
/// install made from a different checkout of this repo.
const CODEX_NOTIFY_SCRIPT_MARKER: &str = "fornax-codex-notify.sh";

/// The active Codex root (FORNX-474). An explicit non-empty `CODEX_HOME` wins;
/// unset or empty keeps `$HOME/.codex`, the same rule Codex itself and
/// `fornax-adapter-codex` use. Config, hooks, the capture marker's sessions
/// directory and `doctor` all derive from this one root, so they cannot
/// disagree about which tree Fornax is wired into.
pub fn codex_home() -> std::path::PathBuf {
    codex_home_from(std::env::var_os("CODEX_HOME"), &crate::dirs_home())
}

fn codex_home_from(
    explicit: Option<std::ffi::OsString>,
    home: &std::path::Path,
) -> std::path::PathBuf {
    match explicit {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(v),
        _ => home.join(".codex"),
    }
}

/// Refuses a relative `CODEX_HOME` before any write: the capture marker bakes
/// an absolute sessions directory (the daemon ignores a relative one), and a
/// relative root would mean a different tree depending on the working
/// directory. Called by plan, install and uninstall.
pub fn ensure_codex_home_usable() -> anyhow::Result<()> {
    check_codex_home(std::env::var_os("CODEX_HOME").as_deref())
}

fn check_codex_home(explicit: Option<&std::ffi::OsStr>) -> anyhow::Result<()> {
    match explicit {
        Some(v) if !v.is_empty() && !std::path::Path::new(v).is_absolute() => anyhow::bail!(
            "CODEX_HOME={} is not an absolute path; refusing before changing anything. \
             Set it to an absolute directory, or unset it to use ~/.codex",
            std::path::Path::new(v).display()
        ),
        _ => Ok(()),
    }
}

pub fn default_path() -> std::path::PathBuf {
    codex_home().join("config.toml")
}

const NOTIFY_SCRIPT_TEMPLATE: &str = include_str!("../../../scripts/fornax-codex-notify.sh");
const NOTIFY_BIN_PLACEHOLDER: &str = "__FORNAX_BIN__";

/// Where `install` puts the notify script: under the Fornax home, so the path
/// written into `~/.codex/config.toml` does not depend on where this binary
/// was built or checked out (FORNX-469).
pub fn default_notify_script() -> std::path::PathBuf {
    crate::fornax_home()
        .join("bin")
        .join(CODEX_NOTIFY_SCRIPT_MARKER)
}

/// Writes the embedded notify script to `script_path` (0755, atomic) with the
/// absolute path of this `fornax` binary baked in. Refuses a binary path that
/// could break out of the shell string it is placed in.
pub fn write_notify_script(
    script_path: &std::path::Path,
    fornax_bin: &std::path::Path,
) -> anyhow::Result<()> {
    let bin = fornax_bin.to_string_lossy();
    anyhow::ensure!(
        fornax_bin.is_absolute() && !bin.contains(['"', '$', '`', '\\', '\n']),
        "cannot bake {} into the notify script (not absolute, or contains shell metacharacters)",
        fornax_bin.display()
    );
    let body = NOTIFY_SCRIPT_TEMPLATE.replacen(NOTIFY_BIN_PLACEHOLDER, &bin, 1);
    if std::fs::read_to_string(script_path).ok().as_deref() == Some(body.as_str()) {
        return Ok(());
    }
    let dir = script_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("notify script path has no parent"))?;
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{CODEX_NOTIFY_SCRIPT_MARKER}.tmp"));
    std::fs::write(&tmp, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::rename(&tmp, script_path)?;
    Ok(())
}

/// Parses `path` as a format-preserving TOML document (comments and table
/// ordering survive edits), or an empty document if `path` does not exist.
/// Unlike the Claude adapter's JSON equivalent, a `~/.codex/config.toml`
/// that fails to parse as TOML is always a hard error — there is no
/// sensible "treat it as empty" fallback for a file this consequential.
#[cfg(test)]
fn load_codex_config(path: &std::path::Path) -> anyhow::Result<toml_edit::DocumentMut> {
    load_codex_config_with_digest(path).map(|(doc, _)| doc)
}

/// As `load_codex_config`, also returning the digest of the very bytes that
/// were parsed, so `save_codex_config` can refuse if the file changed before
/// it writes.
fn load_codex_config_with_digest(
    path: &std::path::Path,
) -> anyhow::Result<(toml_edit::DocumentMut, ContentDigest)> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((toml_edit::DocumentMut::new(), ContentDigest::absent()));
        }
        Err(e) => return Err(e.into()),
    };
    let digest = digest_of_bytes(&bytes);
    let contents = String::from_utf8(bytes)
        .map_err(|e| anyhow::anyhow!("{} is not valid UTF-8: {e}", path.display()))?;
    let doc = contents.parse::<toml_edit::DocumentMut>().map_err(|e| {
        anyhow::anyhow!(
            "{} is not valid TOML — refusing to touch it: {e}",
            path.display()
        )
    })?;
    Ok((doc, digest))
}

/// Replaces `path` with `doc` through [`write_guarded`]: refuses, changing
/// nothing, if the file differs from what `expected` was taken from; stages
/// in a uniquely named exclusive sibling; keeps the existing file's rwx
/// bits (new files are 0600 -- this repo's capability-matrix research,
/// FORNX-33, found plaintext secrets in other Codex on-disk files); and
/// syncs the file and its directory. Its documented limits (the
/// final-check-to-rename window, a symlinked target being replaced, no
/// ACL/xattr/ownership carry-over) apply here unchanged.
fn save_codex_config(
    path: &std::path::Path,
    doc: &toml_edit::DocumentMut,
    expected: &ContentDigest,
) -> anyhow::Result<()> {
    write_guarded(path, &doc.to_string(), expected)
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

/// What `config.toml` actually wires as Codex's `notify`, read-only. Parsed as
/// TOML, so a mention of the script in a comment or another key is not wiring.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NotifyState {
    /// No `notify` entry (or no config file).
    Absent,
    /// The first element is a Fornax-owned script at this path.
    Fornax(std::path::PathBuf),
    /// `notify` is set to something else; Fornax will not overwrite it.
    Foreign(String),
    /// The config cannot be parsed, or `notify` is not an array.
    Unreadable(String),
}

pub(crate) fn notify_state_at(config_path: &std::path::Path) -> NotifyState {
    let doc = match load_codex_config_with_digest(config_path) {
        Ok((doc, _)) => doc,
        Err(e) => return NotifyState::Unreadable(e.to_string()),
    };
    let Some(item) = doc.get("notify") else {
        return NotifyState::Absent;
    };
    let Some(first) = item
        .as_array()
        .map(|a| a.get(0).and_then(|v| v.as_str()).unwrap_or(""))
    else {
        return NotifyState::Unreadable("\"notify\" is not an array".into());
    };
    if notify_is_fornax(item) {
        NotifyState::Fornax(std::path::PathBuf::from(first))
    } else {
        NotifyState::Foreign(first.to_string())
    }
}

enum InstallPlan {
    AlreadyInstalled,
    WouldInstall(Box<toml_edit::DocumentMut>, ContentDigest),
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
    let (mut doc, digest) = load_codex_config_with_digest(config_path)?;
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
        if notify_is_fornax(existing) {
            // A Fornax-owned entry left by an older install (a checkout that
            // moved or was deleted) is ours to repoint, not a foreign command.
            let mut arr = toml_edit::Array::new();
            arr.push(script_str);
            doc["notify"] = toml_edit::Item::Value(toml_edit::Value::Array(arr));
            return Ok(InstallPlan::WouldInstall(Box::new(doc), digest));
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
    Ok(InstallPlan::WouldInstall(Box::new(doc), digest))
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
        InstallPlan::WouldInstall(..) => (
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
    install_at_with(config_path, script_path, || {})
}

/// `before_write` runs between planning and writing; tests use it to change
/// the file inside the window the digest guard must catch.
fn install_at_with(
    config_path: &std::path::Path,
    script_path: &std::path::Path,
    before_write: impl FnOnce(),
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
        InstallPlan::WouldInstall(doc, digest) => {
            before_write();
            save_codex_config(config_path, &doc, &digest)?;
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
    uninstall_at_with(config_path, || {})
}

fn uninstall_at_with(
    config_path: &std::path::Path,
    before_write: impl FnOnce(),
) -> anyhow::Result<AdapterActionResult> {
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
    let (mut doc, digest) = load_codex_config_with_digest(config_path)?;
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
    before_write();
    save_codex_config(config_path, &doc, &digest)?;
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

/// Composite plan covering both the `notify` wiring (`config.toml`) and the
/// lifecycle-hook wiring (`hooks.json`, HORO-1712 part B). The two are
/// independent capabilities with no shared state, so a refusal on one side
/// (most commonly a foreign `notify` already wired to something else — e.g.
/// Codex's own built-in computer-use client, confirmed live on a real
/// dogfood machine) is folded into the message as a warning rather than
/// failing the whole plan; `hooks.json` installability must still be
/// reported even when `notify` cannot be touched.
pub fn plan_install_all(
    config_path: &std::path::Path,
    script_path: &std::path::Path,
    hooks_path: &std::path::Path,
) -> anyhow::Result<AdapterActionResult> {
    let (hooks_changed, hooks_message) = match crate::codex_hooks::plan_install_at(hooks_path) {
        Ok(plan) => (plan.changed, plan.message),
        Err(e) => (false, format!("hooks: refused — {e}")),
    };
    let (notify_changed, notify_message) = match plan_install_at(config_path, script_path) {
        Ok(plan) => (plan.changed, plan.message),
        Err(e) => (false, format!("notify: refused — {e}")),
    };
    let changed = notify_changed || hooks_changed;
    let message = format!("{notify_message}\n{hooks_message}");
    Ok(mk(config_path, changed, message))
}

/// Installs both the `notify` wiring and the lifecycle-hook wiring.
/// Independent capabilities, installed independently: a refusal or hard
/// error on either side (see [`plan_install_all`]) never blocks the other
/// — each half's own failure is caught and folded into the result message
/// as a warning rather than propagated. Attempts `hooks.json` then
/// `config.toml`; if a later I/O error occurs, rerunning `install_all` is
/// idempotent (both halves detect "already installed" and no-op), so this
/// is safely resumable rather than silently half-applied forever.
pub fn install_all(
    config_path: &std::path::Path,
    script_path: &std::path::Path,
    hooks_path: &std::path::Path,
) -> anyhow::Result<AdapterActionResult> {
    let (hooks_changed, hooks_message) = match crate::codex_hooks::install_at(hooks_path) {
        Ok(result) => (result.changed, result.message),
        Err(e) => (false, format!("hooks: refused — {e}")),
    };
    let (notify_changed, notify_message) = match install_at(config_path, script_path) {
        Ok(result) => (result.changed, result.message),
        Err(e) => (false, format!("notify: refused — {e}")),
    };

    let changed = hooks_changed || notify_changed;
    let message = format!("{notify_message}\n{hooks_message}");
    Ok(mk(config_path, changed, message))
}

/// Uninstalls both the lifecycle-hook wiring and the `notify` wiring. Each
/// half no-ops safely if it was never installed.
pub fn uninstall_all(
    config_path: &std::path::Path,
    hooks_path: &std::path::Path,
) -> anyhow::Result<AdapterActionResult> {
    let hooks_result = crate::codex_hooks::uninstall_at(hooks_path)?;
    let notify_result = uninstall_at(config_path)?;
    let changed = hooks_result.changed || notify_result.changed;
    let message = format!("{}\n{}", notify_result.message, hooks_result.message);
    Ok(mk(config_path, changed, message))
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

    #[test]
    fn written_script_bakes_the_binary_path_and_is_executable() {
        let dir = std::env::temp_dir().join(format!("fnx-notify-{}", std::process::id()));
        let script = dir.join("bin").join(CODEX_NOTIFY_SCRIPT_MARKER);
        write_notify_script(&script, std::path::Path::new("/opt/fornax/bin/fornax")).unwrap();
        let body = std::fs::read_to_string(&script).unwrap();
        assert!(body.contains("${FORNAX_BIN:-/opt/fornax/bin/fornax}"));
        assert!(!body.contains("${FORNAX_BIN:-__FORNAX_BIN__}"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&script).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn script_refuses_a_binary_path_that_could_inject_shell() {
        let dir = std::env::temp_dir().join(format!("fnx-notify-bad-{}", std::process::id()));
        let script = dir.join(CODEX_NOTIFY_SCRIPT_MARKER);
        for bad in ["/tmp/a\"b", "/tmp/$(x)", "/tmp/`x`", "relative/fornax"] {
            assert!(write_notify_script(&script, std::path::Path::new(bad)).is_err());
        }
        assert!(!script.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reinstall_repoints_a_stale_fornax_notify_path() {
        let path = tmp_config_path("stale-notify");
        std::fs::write(
            &path,
            "notify = [\"/gone/checkout/scripts/fornax-codex-notify.sh\"]\n",
        )
        .unwrap();
        let result = install_at(&path, &fake_script()).expect("install");
        assert!(result.changed);
        let doc = load_codex_config(&path).unwrap();
        assert_eq!(
            doc["notify"][0].as_str(),
            Some(fake_script().to_str().unwrap())
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn foreign_notify_is_still_refused() {
        let path = tmp_config_path("foreign-notify");
        std::fs::write(&path, "notify = [\"/usr/bin/other-tool\"]\n").unwrap();
        assert!(install_at(&path, &fake_script()).is_err());
        std::fs::remove_file(&path).ok();
    }

    fn fake_script() -> std::path::PathBuf {
        std::path::PathBuf::from("/opt/fornax/scripts/fornax-codex-notify.sh")
    }

    fn tmp_hooks_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fornax-cli-test-codex-composite-{name}-{}.json",
            uuid::Uuid::new_v4()
        ))
    }

    /// A foreign `notify` (e.g. Codex's own built-in computer-use client —
    /// confirmed live on a real dogfood machine) must not block installing
    /// Fornax's independent hooks.json capability. Regression test for the
    /// original bundled design, which propagated the notify refusal via `?`
    /// and aborted the whole `install_all` before touching hooks.json.
    #[test]
    fn foreign_notify_does_not_block_hooks_install() {
        let config_path = tmp_config_path("foreign-notify-composite");
        let hooks_path = tmp_hooks_path("foreign-notify-composite");
        std::fs::write(&config_path, "notify = [\"/usr/bin/some-other-tool\"]\n").unwrap();

        let result = install_all(&config_path, &fake_script(), &hooks_path).expect("install_all");
        assert!(
            result.changed,
            "hooks.json install alone must still report changed"
        );
        assert!(
            hooks_path.exists(),
            "hooks.json must be written despite notify refusal"
        );
        assert!(
            result.message.contains("refused"),
            "message must surface the notify refusal"
        );

        let config_contents = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(
            config_contents, "notify = [\"/usr/bin/some-other-tool\"]\n",
            "foreign notify must be left untouched"
        );

        std::fs::remove_file(&config_path).ok();
        std::fs::remove_file(&hooks_path).ok();
    }

    /// Symmetric case: a malformed `hooks.json` (hooks is a hard error, not
    /// a safety refusal, but must still be scoped to its own half) must not
    /// block installing the independent `notify` wiring.
    #[test]
    fn malformed_hooks_json_does_not_block_notify_install() {
        let config_path = tmp_config_path("malformed-hooks-composite");
        let hooks_path = tmp_hooks_path("malformed-hooks-composite");
        std::fs::write(&hooks_path, "[]").unwrap();

        let result = install_all(&config_path, &fake_script(), &hooks_path).expect("install_all");
        assert!(
            result.changed,
            "notify install alone must still report changed"
        );
        assert!(
            result.message.contains("refused"),
            "message must surface the hooks refusal"
        );

        let doc = load_codex_config(&config_path).expect("load");
        assert!(notify_is_fornax(doc.get("notify").unwrap()));

        let hooks_contents = std::fs::read_to_string(&hooks_path).unwrap();
        assert_eq!(
            hooks_contents, "[]",
            "malformed hooks.json must be left untouched"
        );

        std::fs::remove_file(&config_path).ok();
        std::fs::remove_file(&hooks_path).ok();
    }

    #[test]
    fn install_refuses_instead_of_clobbering_an_edit_made_after_the_read() {
        let path = tmp_config_path("install-clobber");
        std::fs::write(&path, "model = \"a\"\n").unwrap();
        let edit = "model = \"edited-by-user\"\n";

        let err = install_at_with(&path, &fake_script(), || {
            std::fs::write(&path, edit).unwrap();
        })
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
        let path = tmp_config_path("uninstall-clobber");
        install_at(&path, &fake_script()).expect("install");
        let edit = "model = \"edited-by-user\"\n";

        let err = uninstall_at_with(&path, || {
            std::fs::write(&path, edit).unwrap();
        })
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
        let path = tmp_config_path("owner-only");
        std::fs::write(&path, "model = \"a\"\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        install_at(&path, &fake_script()).expect("install");
        assert_eq!(mode_of(&path), 0o600);
        uninstall_at(&path).expect("uninstall");
        assert_eq!(mode_of(&path), 0o600);
        std::fs::remove_file(&path).ok();
    }

    #[cfg(unix)]
    #[test]
    fn install_never_writes_through_a_symlink_planted_at_the_old_temp_name() {
        let path = tmp_config_path("symlink-tmp");
        let victim = tmp_config_path("symlink-victim");
        std::fs::write(&victim, "untouched").unwrap();
        std::os::unix::fs::symlink(&victim, path.with_extension("toml.tmp")).unwrap();

        install_at(&path, &fake_script()).expect("install");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("fornax-codex-notify.sh"));
        std::fs::remove_file(path.with_extension("toml.tmp")).ok();
        std::fs::remove_file(&victim).ok();
        std::fs::remove_file(&path).ok();
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

    #[test]
    fn explicit_codex_home_wins_and_unset_or_empty_keeps_the_home_default() {
        use std::ffi::OsString;
        let home = std::path::Path::new("/h");
        assert_eq!(
            codex_home_from(Some(OsString::from("/custom")), home),
            std::path::PathBuf::from("/custom")
        );
        for unset in [None, Some(OsString::new())] {
            assert_eq!(
                codex_home_from(unset, home),
                std::path::PathBuf::from("/h/.codex")
            );
        }
    }

    #[test]
    fn only_a_relative_codex_home_is_refused() {
        use std::ffi::OsStr;
        assert!(check_codex_home(None).is_ok());
        assert!(check_codex_home(Some(OsStr::new(""))).is_ok());
        assert!(check_codex_home(Some(OsStr::new("/abs/codex"))).is_ok());
        let err = check_codex_home(Some(OsStr::new("rel/codex"))).unwrap_err();
        assert!(err.to_string().contains("CODEX_HOME"), "{err}");
    }
}
