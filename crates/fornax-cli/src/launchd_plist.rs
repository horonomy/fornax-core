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
    let existed = ensure_ours(&path)?;
    let dir = path.parent().expect("plist path has a parent");
    std::fs::create_dir_all(dir)?;
    std::fs::create_dir_all(fornax_home.join("logs"))?;
    let tmp = staging_path(dir);
    stage(&tmp, &render(daemon_bin, fornax_home))?;
    // A verified-ours plist is replaced atomically. One that was absent at the
    // check is published with a hard link, which fails rather than clobbers if
    // anything appears there since. (Replacing a verified-ours file can still
    // race a same-user writer: POSIX has no atomic compare-and-replace.)
    let published = if existed {
        std::fs::rename(&tmp, &path)
    } else {
        std::fs::hard_link(&tmp, &path).and_then(|()| std::fs::remove_file(&tmp))
    };
    if let Err(e) = published {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(path)
}

/// Per-process, so concurrent installs never share or delete each other's file.
fn staging_path(dir: &Path) -> PathBuf {
    dir.join(format!(".{LABEL}.plist.{}.tmp", std::process::id()))
}

/// Writes the staging file with `create_new`, so a pre-planted symlink or file
/// is never followed or truncated. A leftover regular file from an interrupted
/// install is replaced; anything else at the staging path is left alone.
fn stage(tmp: &Path, body: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let open = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(tmp)
    };
    let mut file = match open() {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let stale = std::fs::symlink_metadata(tmp)?;
            anyhow::ensure!(
                stale.is_file(),
                "{} exists and is not a regular file; leaving it alone",
                tmp.display()
            );
            std::fs::remove_file(tmp)?;
            open()?
        }
        other => other?,
    };
    // Flushed before publish so a crash cannot leave a truncated plist at the
    // real path, which the strict ownership check would then refuse to heal.
    if let Err(e) = file
        .write_all(body.as_bytes())
        .and_then(|()| file.sync_all())
    {
        let _ = std::fs::remove_file(tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Returns whether a verified-ours file is present (false: genuinely absent).
/// Only a path that is genuinely absent, or a regular file we can read and that
/// carries our ownership mark, may be written or removed. Anything else
/// (foreign, binary, invalid UTF-8, unreadable, a directory or symlink) is
/// unverified and is left alone.
fn ensure_ours(path: &Path) -> anyhow::Result<bool> {
    let leave = |why: &str| anyhow::anyhow!("{} {why}; leaving it alone", path.display());
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(leave(&format!("cannot be inspected ({e})"))),
        Ok(m) if !m.is_file() => return Err(leave("is not a regular file")),
        Ok(_) => {}
    }
    let bytes = std::fs::read(path).map_err(|e| leave(&format!("cannot be read ({e})")))?;
    let body = std::str::from_utf8(&bytes).map_err(|_| leave("is not valid UTF-8 text"))?;
    // The mark sits on the third line of every plist we render; a mark quoted
    // elsewhere in a foreign file does not make it ours.
    anyhow::ensure!(
        body.lines().nth(2) == Some(OWNER_MARK),
        "{} exists and was not written by Fornax; leaving it alone",
        path.display()
    );
    Ok(true)
}

/// Removes the plist; true if one was there.
pub fn uninstall(user_home: &Path) -> anyhow::Result<bool> {
    ensure_ours(&plist_path(user_home))?;
    match std::fs::remove_file(plist_path(user_home)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow::anyhow!(
            "{} cannot be removed ({e}); leaving it alone",
            plist_path(user_home).display()
        )),
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

/// Whether the file at the plist path is verifiably one Fornax wrote.
pub fn is_ours(user_home: &Path) -> bool {
    matches!(ensure_ours(&plist_path(user_home)), Ok(true))
}

/// The login item is shared by everything that needs the daemon, so
/// uninstalling one user of it leaves the file (and says why, with no stop
/// advice) while another still depends on it.
pub fn kept_message(why: &str) -> String {
    format!(
        "daemon autostart: left in place -- {why}; run `fornax uninstall codex` again once \
         nothing else needs the daemon"
    )
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

    /// What sits at the plist path before install/uninstall, so a refusal can
    /// be checked to have left it byte-for-byte alone.
    enum Existing {
        File(Vec<u8>),
        /// Cannot be read back; only its size is compared.
        Opaque(u64),
        Dir,
        Symlink(PathBuf),
    }

    fn assert_unverified_is_preserved(name: &str, make: impl FnOnce(&Path) -> Existing) {
        let d = scratch(name);
        let daemon = d.join("fornax-daemon");
        std::fs::write(&daemon, "").unwrap();
        let path = plist_path(&d);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let existing = make(&path);

        let install_err = install(&d, &d.join("fh"), &daemon).expect_err("install must refuse");
        let uninstall_err = uninstall(&d).expect_err("uninstall must refuse");
        assert!(
            install_err.to_string().contains("leaving it alone"),
            "{install_err}"
        );
        assert!(
            uninstall_err.to_string().contains("leaving it alone"),
            "{uninstall_err}"
        );

        let meta = std::fs::symlink_metadata(&path).expect("still present");
        match existing {
            Existing::File(bytes) => {
                assert!(meta.is_file());
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
            }
            Existing::Opaque(len) => {
                assert!(meta.is_file());
                assert_eq!(meta.len(), len);
            }
            Existing::Dir => assert!(meta.is_dir()),
            Existing::Symlink(target) => {
                assert!(meta.file_type().is_symlink());
                assert_eq!(std::fs::read_link(&path).unwrap(), target);
            }
        }
        // No staged temp file (dot-prefixed) left behind either.
        let stray: Vec<_> = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with('.'))
            .collect();
        assert!(stray.is_empty(), "unexpected files: {stray:?}");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_foreign_binary_plist_is_never_overwritten_or_removed() {
        assert_unverified_is_preserved("bplist", |p| {
            let bytes = b"bplist00\xd1\x01\x02\x5fcom.example.other\xff\xfe\x08".to_vec();
            std::fs::write(p, &bytes).unwrap();
            Existing::File(bytes)
        });
    }

    #[test]
    fn a_plist_with_invalid_utf8_is_never_overwritten_or_removed() {
        // Carries the ownership text but is not valid UTF-8: not verifiably ours.
        assert_unverified_is_preserved("badutf8", |p| {
            let mut bytes = OWNER_MARK.as_bytes().to_vec();
            bytes.extend_from_slice(b"\xff\xfe\xc3\x28");
            std::fs::write(p, &bytes).unwrap();
            Existing::File(bytes)
        });
    }

    #[test]
    fn an_unreadable_plist_is_never_overwritten_or_removed() {
        use std::os::unix::fs::PermissionsExt;
        let probe = scratch("unreadable-probe");
        let f = probe.join("f");
        std::fs::write(&f, "x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        let can_still_read = std::fs::read(&f).is_ok(); // running as root
        std::fs::remove_dir_all(&probe).ok();
        if can_still_read {
            return;
        }
        assert_unverified_is_preserved("unreadable", |p| {
            let body = format!("{OWNER_MARK} unreadable");
            std::fs::write(p, &body).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o000)).unwrap();
            Existing::Opaque(body.len() as u64)
        });
    }

    #[test]
    fn a_directory_at_the_plist_path_is_never_replaced_or_removed() {
        assert_unverified_is_preserved("dir", |p| {
            std::fs::create_dir(p).unwrap();
            Existing::Dir
        });
    }

    #[test]
    fn a_symlink_at_the_plist_path_is_never_replaced_or_removed() {
        // Dangling, and pointing at a foreign file: neither is verifiably ours.
        assert_unverified_is_preserved("dangling", |p| {
            let t = PathBuf::from("/nonexistent/fornax-test-target.plist");
            std::os::unix::fs::symlink(&t, p).unwrap();
            Existing::Symlink(t)
        });
        assert_unverified_is_preserved("symlink-foreign", |p| {
            let target = p.parent().unwrap().join("elsewhere.txt");
            std::fs::write(&target, "<plist>foreign</plist>").unwrap();
            std::os::unix::fs::symlink(&target, p).unwrap();
            Existing::Symlink(target)
        });
    }

    #[test]
    fn only_a_genuinely_absent_plist_is_created_and_our_own_is_replaced() {
        let d = scratch("absent-then-ours");
        let daemon = d.join("fornax-daemon");
        std::fs::write(&daemon, "").unwrap();
        assert!(!uninstall(&d).unwrap(), "absent: nothing to remove");
        let path = install(&d, &d.join("fh"), &daemon).unwrap();
        assert!(std::fs::read_to_string(&path).unwrap().contains(OWNER_MARK));
        install(&d, &d.join("fh2"), &daemon).expect("our own plist may be rewritten");
        assert!(uninstall(&d).unwrap());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_foreign_plist_that_merely_quotes_the_mark_is_not_ours() {
        assert_unverified_is_preserved("quoted-mark", |p| {
            let body = format!("<plist><!-- see {OWNER_MARK} --></plist>\n").into_bytes();
            std::fs::write(p, &body).unwrap();
            Existing::File(body)
        });
    }

    #[test]
    fn a_symlink_to_a_file_carrying_the_mark_is_not_ours() {
        assert_unverified_is_preserved("symlink-marked", |p| {
            let target = p.parent().unwrap().join("elsewhere.txt");
            std::fs::write(&target, render(Path::new("/x"), Path::new("/y"))).unwrap();
            std::os::unix::fs::symlink(&target, p).unwrap();
            Existing::Symlink(target)
        });
    }

    #[test]
    fn a_planted_staging_symlink_is_never_followed_or_truncated() {
        let d = scratch("tmp-symlink");
        let daemon = d.join("fornax-daemon");
        std::fs::write(&daemon, "").unwrap();
        let path = plist_path(&d);
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let victim = d.join("victim.txt");
        std::fs::write(&victim, "precious").unwrap();
        std::os::unix::fs::symlink(&victim, staging_path(dir)).unwrap();

        let err =
            install(&d, &d.join("fh"), &daemon).expect_err("must refuse a symlinked staging path");
        assert!(err.to_string().contains("leaving it alone"), "{err}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "precious");
        assert!(!path.exists(), "no plist published");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_stale_regular_staging_file_is_replaced_and_no_staging_file_is_left() {
        let d = scratch("tmp-stale");
        let daemon = d.join("fornax-daemon");
        std::fs::write(&daemon, "").unwrap();
        let path = plist_path(&d);
        let dir = path.parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let tmp = staging_path(dir);
        std::fs::write(&tmp, "half-written").unwrap();

        install(&d, &d.join("fh"), &daemon).expect("stale staging file is ours to replace");
        assert!(!tmp.exists());
        assert!(std::fs::read_to_string(&path).unwrap().contains(LABEL));
        std::fs::remove_dir_all(&d).ok();
    }
}
