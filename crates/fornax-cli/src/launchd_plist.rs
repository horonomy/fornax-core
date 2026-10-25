//! Daemon autostart for macOS (FORNX-469). The daemon must be running for any
//! adapter to deliver anything, and a new user had no supported way to start
//! it. `fornax install codex` writes a LaunchAgent plist as a plain file and
//! prints the exact `launchctl` command; it never runs it (the zero-subprocess
//! control forbids spawning from Fornax binaries, and loading a login item is
//! the user's call).

use std::path::{Path, PathBuf};

pub const LABEL: &str = "com.horonomy.fornax-daemon";
/// Written into every plist Fornax creates; install and uninstall only touch a
/// file that carries it, so a hand-written plist under the same label is safe.
const OWNER_MARK: &str = "<!-- managed by fornax: `fornax uninstall codex` removes this file -->";

pub fn plist_path(user_home: &Path) -> PathBuf {
    user_home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn render(daemon_bin: &Path, fornax_home: &Path) -> String {
    let bin = xml_escape(&daemon_bin.to_string_lossy());
    let home = xml_escape(&fornax_home.to_string_lossy());
    let log = xml_escape(
        &fornax_home
            .join("logs")
            .join("daemon.log")
            .to_string_lossy(),
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
{OWNER_MARK}
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{bin}</string></array>
  <key>EnvironmentVariables</key><dict><key>FORNAX_HOME</key><string>{home}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#
    )
}

/// Writes the plist (0644, atomic). Refuses a daemon binary that is not an
/// existing absolute path rather than writing a login item that cannot start.
pub fn install(user_home: &Path, fornax_home: &Path, daemon_bin: &Path) -> anyhow::Result<PathBuf> {
    anyhow::ensure!(
        daemon_bin.is_absolute() && daemon_bin.is_file(),
        "fornax-daemon not found at {}",
        daemon_bin.display()
    );
    for p in [user_home, fornax_home, daemon_bin] {
        let ok = p.is_absolute() && p.to_str().is_some_and(|t| !t.chars().any(char::is_control));
        anyhow::ensure!(
            ok,
            "{} is not an absolute, plain-text path; not writing a login item",
            p.display()
        );
    }
    let path = plist_path(user_home);
    ensure_ours(&path)?;
    let dir = path.parent().expect("plist path has a parent");
    std::fs::create_dir_all(dir)?;
    std::fs::create_dir_all(fornax_home.join("logs"))?;
    let tmp = dir.join(format!(".{LABEL}.plist.tmp"));
    std::fs::write(&tmp, render(daemon_bin, fornax_home))?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Refuses to touch an existing file that Fornax did not write.
fn ensure_ours(path: &Path) -> anyhow::Result<()> {
    match std::fs::read_to_string(path) {
        Ok(body) if !body.contains(OWNER_MARK) => anyhow::bail!(
            "{} exists and was not written by Fornax; leaving it alone",
            path.display()
        ),
        _ => Ok(()),
    }
}

/// Removes the plist; true if one was there.
pub fn uninstall(user_home: &Path) -> anyhow::Result<bool> {
    ensure_ours(&plist_path(user_home))?;
    match std::fs::remove_file(plist_path(user_home)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub fn bootstrap_hint(plist: &Path) -> String {
    format!(
        "start it now and at every login with: launchctl bootstrap gui/$(id -u) {}",
        plist.display()
    )
}

pub fn bootout_hint() -> String {
    format!("stop it with: launchctl bootout gui/$(id -u)/{LABEL}")
}

/// Plist action for `fornax install codex`, as a message line. Never fatal:
/// autostart is a convenience and must not block wiring the adapter.
pub fn install_message(user_home: &Path, fornax_home: &Path) -> String {
    if !cfg!(target_os = "macos") {
        return "daemon autostart: only automated on macOS; start fornax-daemon yourself".into();
    }
    let daemon = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .and_then(|p| p.parent().map(|d| d.join("fornax-daemon")));
    let Some(daemon) = daemon else {
        return "daemon autostart skipped: cannot locate the fornax binary".into();
    };
    match install(user_home, fornax_home, &daemon) {
        Ok(plist) => format!(
            "daemon autostart: wrote {}; {}",
            plist.display(),
            bootstrap_hint(&plist)
        ),
        Err(e) => format!("daemon autostart skipped: {e}"),
    }
}

pub fn uninstall_message(user_home: &Path) -> String {
    match uninstall(user_home) {
        Ok(true) => format!(
            "daemon autostart: removed the login item file; {}",
            bootout_hint()
        ),
        Ok(false) => "daemon autostart: nothing to remove".into(),
        Err(e) => format!("daemon autostart: could not remove the login item file: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fnx-launchd-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn install_writes_plist_with_sibling_daemon_abs_path() {
        let d = scratch("ok");
        let daemon = d.join("fornax-daemon");
        std::fs::write(&daemon, "").unwrap();
        let fh = d.join("fh & co");
        let path = install(&d, &fh, &daemon).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains(&format!("<string>{}</string>", daemon.display())));
        assert!(body.contains("fh &amp; co"), "values are XML-escaped");
        assert!(body.contains("<key>SuccessfulExit</key><false/>"));
        assert!(fh.join("logs").is_dir());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn missing_daemon_refuses_plist() {
        let d = scratch("missing");
        let err = install(&d, &d.join("fh"), &d.join("fornax-daemon")).unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert!(!plist_path(&d).exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_foreign_plist_with_the_same_label_is_never_overwritten_or_removed() {
        let d = scratch("foreign");
        let daemon = d.join("fornax-daemon");
        std::fs::write(&daemon, "").unwrap();
        let path = plist_path(&d);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "<plist>hand written</plist>").unwrap();
        assert!(install(&d, &d.join("fh"), &daemon).is_err());
        assert!(uninstall(&d).is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "<plist>hand written</plist>"
        );
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn control_characters_in_a_path_are_refused() {
        let d = scratch("ctrl");
        let daemon = d.join("fornax-daemon");
        std::fs::write(&daemon, "").unwrap();
        assert!(install(&d, &d.join("fh\nx"), &daemon).is_err());
        assert!(!plist_path(&d).exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn uninstall_removes_plist_and_is_idempotent() {
        let d = scratch("rm");
        let daemon = d.join("fornax-daemon");
        std::fs::write(&daemon, "").unwrap();
        install(&d, &d.join("fh"), &daemon).unwrap();
        assert!(uninstall(&d).unwrap());
        assert!(!uninstall(&d).unwrap());
        std::fs::remove_dir_all(&d).ok();
    }
}
