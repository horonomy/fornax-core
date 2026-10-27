//! Opt-in marker for the daemon's Codex rollout capture (FORNX-468).
//!
//! `fornax install codex` writes `$FORNAX_HOME/codex-watch.json`; the daemon
//! reads Codex rollouts only while that file exists (see the daemon's
//! `codex_watch` module). The sessions directory is baked into the marker
//! because a daemon started by a service manager does not inherit the
//! installing shell's environment. It is derived from the same Codex config
//! path `install` edits, so one `CODEX_HOME`/`HOME` decides both.

use std::path::{Path, PathBuf};

pub use fornax_adapter_codex::watch_marker::MARKER_FILE;

/// What capture reads, stated at the moment the user opts in.
pub const DISCLOSURE: &str = "the fornax daemon will now read every Codex session on this machine \
     (tool commands and their output, and the final assistant message) so claims such as \
     \"tests passed\" can be checked; it stores them locally with secret-pattern redaction \
     only (no PII redaction). `fornax uninstall codex` turns this off";

pub fn marker_path(fornax_home: &Path) -> PathBuf {
    fornax_home.join(MARKER_FILE)
}

fn sessions_dir(codex_config: &Path) -> PathBuf {
    codex_config
        .parent()
        .map(|p| p.join("sessions"))
        .unwrap_or_else(|| PathBuf::from("sessions"))
}

/// Writes (or refreshes) the marker. Returns whether the file changed.
pub fn install(fornax_home: &Path, codex_config: &Path) -> anyhow::Result<bool> {
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "sessions_dir": sessions_dir(codex_config),
    }))?;
    let path = marker_path(fornax_home);
    if std::fs::read(&path).ok().as_deref() == Some(body.as_slice()) {
        return Ok(false);
    }
    std::fs::create_dir_all(fornax_home)?;
    let tmp = fornax_home.join(format!("{MARKER_FILE}.tmp"));
    write_private(&tmp, &body)?;
    std::fs::rename(&tmp, &path)?;
    Ok(true)
}

/// Removes the marker. Returns whether one existed.
pub fn uninstall(fornax_home: &Path) -> anyhow::Result<bool> {
    match std::fs::remove_file(marker_path(fornax_home)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub fn is_installed(fornax_home: &Path) -> bool {
    marker_path(fornax_home).exists()
}

/// Whether capture is actually on, by the daemon's own rule, and whether it
/// reads the sessions directory the current Codex config writes to.
#[derive(Debug, PartialEq, Eq)]
pub enum Capture {
    Off,
    /// A marker the daemon will ignore.
    Unusable(String),
    On {
        dir_matches_config: bool,
        dir: PathBuf,
    },
}

pub fn capture_state(fornax_home: &Path, codex_config: &Path) -> Capture {
    use fornax_adapter_codex::watch_marker::{read, MarkerError};
    match read(fornax_home) {
        Err(MarkerError::Missing) => Capture::Off,
        Err(MarkerError::RelativeSessionsDir) => {
            Capture::Unusable("sessions_dir is not an absolute path".into())
        }
        Err(MarkerError::Invalid(e)) => Capture::Unusable(format!("not valid marker JSON ({e})")),
        Err(MarkerError::Unreadable(e)) => Capture::Unusable(format!("cannot be read ({e})")),
        Ok(m) => Capture::On {
            dir_matches_config: m.sessions_dir == sessions_dir(codex_config),
            dir: m.sessions_dir,
        },
    }
}

#[cfg(unix)]
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(body)
}

#[cfg(not(unix))]
fn write_private(path: &Path, body: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("fornax-cw-marker-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn install_codex_writes_watch_marker_with_resolved_codex_home() {
        let home = tmp("home");
        let config = tmp("codex").join("config.toml");
        assert!(install(&home, &config).unwrap());
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(marker_path(&home)).unwrap()).unwrap();
        assert_eq!(
            v["sessions_dir"],
            config.parent().unwrap().join("sessions").to_str().unwrap()
        );
        assert!(!install(&home, &config).unwrap(), "idempotent");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(marker_path(&home))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn uninstall_codex_removes_watch_marker() {
        let home = tmp("uninst");
        let config = tmp("codex2").join("config.toml");
        install(&home, &config).unwrap();
        assert!(uninstall(&home).unwrap());
        assert!(!is_installed(&home));
        assert!(!uninstall(&home).unwrap(), "nothing left to remove");
    }
}
