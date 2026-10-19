//! Guarded replacement of a user-owned config file (FORNX-420).
//!
//! The target (e.g. `~/.claude/settings.json`) also holds state Fornax does
//! not own, so a writer must refuse rather than clobber: it checks the file
//! is unchanged since it was read, stages in a uniquely named exclusive
//! sibling (so a planted file or symlink at a predictable temp name is never
//! a write target), keeps the rwx permission bits, and orders the syscalls
//! for durability (fsync file, rename, fsync directory).
//!
//! Durability is code-reviewed ordering, not tested against power loss: the
//! crash test kills the process, which keeps the page cache, so it proves
//! atomicity (old or new bytes, never partial) only. A crash can leave one
//! `.fornax-tmp-*` sibling holding the full new content with the file's mode;
//! nothing removes it later.

use sha2::{Digest, Sha256};

/// What a file's bytes were when they were read; `None` means it did not
/// exist. Compared again immediately before a write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDigest(Option<[u8; 32]>);

impl ContentDigest {
    /// The digest of a file that does not exist.
    pub fn absent() -> Self {
        Self(None)
    }
}

/// Digest of `path`'s current bytes, or the "absent" digest if it does not
/// exist. Any other read error is returned, never treated as "absent".
pub fn digest_of(path: &std::path::Path) -> std::io::Result<ContentDigest> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(digest_of_bytes(&bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ContentDigest(None)),
        Err(e) => Err(e),
    }
}

/// Digest of bytes the caller already read, so the digest and whatever the
/// caller parsed from them come from the same read.
pub fn digest_of_bytes(bytes: &[u8]) -> ContentDigest {
    ContentDigest(Some(Sha256::digest(bytes).into()))
}

/// The replacement keeps the existing file's rwx permission bits (not
/// setuid/setgid/sticky, which mean nothing on a config file), and is
/// owner-only when the file is new -- the file may hold credentials.
#[cfg(unix)]
fn target_mode(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o600)
}

/// Replaces `path` with `contents` only if `path` still has the content
/// `expected` was taken from. A mismatch means someone else changed the file
/// since it was read; this refuses with no mutation at all instead of
/// overwriting their edit. The check runs before anything is created and
/// again after the staged file is synced, just before the rename. A change
/// landing between that last check and the rename is not detectable without
/// a lock, and Claude Code takes none on settings.json.
///
/// Known limit: if `path` is itself a symlink, the rename replaces the link
/// with a regular file (the previous writer behaved the same way); it does not
/// write through to the link target. The replacement is also a new inode, so
/// file ownership, ACLs and extended attributes of the old file are not
/// carried over (only the rwx bits are). One consequence: under `sudo` with
/// the user's HOME, the replacement is owned by root with mode 0600 and the
/// user's own CLI can no longer read it.
///
/// Platform: Unix only. Staging is a sibling of `path`, so the rename never
/// crosses a filesystem; read-only directories, file-level bind mounts and
/// filesystems without a working fsync fail before the rename with "was not
/// changed", while a directory fsync that some network or FUSE filesystems
/// reject fails after it and is reported as "was replaced".
///
/// The replacement is staged in a uniquely named sibling opened with
/// `create_new`, so a planted file or symlink at any predictable name is
/// never a write target.
pub fn write_guarded(
    path: &std::path::Path,
    contents: &str,
    expected: &ContentDigest,
) -> anyhow::Result<()> {
    write_guarded_inner(path, contents, expected, &mut |_| Ok(()))
}

/// Points in `write_guarded_inner` where a test can inject a fault or a
/// concurrent edit. The shipped writer passes a no-op, so nothing here is
/// reachable from the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Created,
    Written,
    Synced,
    Renamed,
    DirSynced,
}

fn write_guarded_inner(
    path: &std::path::Path,
    contents: &str,
    expected: &ContentDigest,
    checkpoint: &mut dyn FnMut(Step) -> std::io::Result<()>,
) -> anyhow::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    anyhow::ensure!(
        digest_of(path)? == *expected,
        "{} changed since it was read -- refusing to overwrite it; re-run to retry",
        path.display()
    );
    std::fs::create_dir_all(parent).map_err(|e| {
        anyhow::anyhow!(
            "{} was not changed: could not create {}: {e}",
            path.display(),
            parent.display()
        )
    })?;

    let tmp_path = parent.join(format!(".fornax-tmp-{}", uuid::Uuid::new_v4()));
    let staged = (|| -> anyhow::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(target_mode(path));
        }
        let mut file = options.open(&tmp_path)?;
        checkpoint(Step::Created)?;
        // Re-assert on the open handle: `mode` above is masked by the umask,
        // and this must hold before any content is written.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(target_mode(path)))?;
        }
        file.write_all(contents.as_bytes())?;
        checkpoint(Step::Written)?;
        // Data must be durable before the rename makes it the live file.
        file.sync_all()?;
        checkpoint(Step::Synced)?;
        // Staging (and the fsync above) can take a while, so look again
        // right before the rename to narrow the window for a concurrent edit.
        anyhow::ensure!(
            digest_of(path)? == *expected,
            "{} changed since it was read -- refusing to overwrite it; re-run to retry",
            path.display()
        );
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();
    if let Err(e) = staged {
        std::fs::remove_file(&tmp_path).ok();
        // An io error here is a staging or rename failure, so the target was
        // not touched; a bare "Permission denied" would not say either.
        return Err(match e.downcast::<std::io::Error>() {
            Ok(io) => anyhow::anyhow!(
                "{} was not changed: could not stage the replacement in {}: {io}",
                path.display(),
                parent.display()
            ),
            Err(refusal) => refusal,
        });
    }
    confirm_replaced(path, parent, contents, checkpoint)
}

/// Steps after the rename. The live file is already replaced here, so a
/// failure must say so rather than read like a failed install.
fn confirm_replaced(
    path: &std::path::Path,
    parent: &std::path::Path,
    intended: &str,
    checkpoint: &mut dyn FnMut(Step) -> std::io::Result<()>,
) -> anyhow::Result<()> {
    let synced = (|| -> anyhow::Result<()> {
        checkpoint(Step::Renamed)?;
        // The rename itself must survive a crash.
        std::fs::File::open(parent)?.sync_all()?;
        checkpoint(Step::DirSynced)?;
        Ok(())
    })();
    // Read back even when the directory sync failed, so the message can say
    // whether the content on disk is right.
    let read_back = verify_written(path, intended);
    let shown = path.display();
    match (synced, read_back) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(sync), Ok(())) => Err(anyhow::anyhow!(
            "{shown} was replaced and reads back correctly, but making the rename durable failed: {sync}"
        )),
        (Ok(()), Err(read)) => Err(anyhow::anyhow!(
            "{shown} was replaced, but the result could not be confirmed: {read}"
        )),
        (Err(sync), Err(read)) => Err(anyhow::anyhow!(
            "{shown} was replaced, but the result could not be confirmed: {read}; making the rename durable also failed: {sync}"
        )),
    }
}

/// Read-back: the file on disk must be exactly what was meant to be written.
fn verify_written(path: &std::path::Path, intended: &str) -> anyhow::Result<()> {
    let on_disk = std::fs::read_to_string(path)?;
    anyhow::ensure!(
        on_disk == intended,
        "{} does not contain the intended content after the write",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("fornax-guarded-{name}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn digest_distinguishes_absent_unchanged_and_changed_content() {
        let path = tmp_path("digest");
        let absent = digest_of(&path).expect("absent");
        std::fs::write(&path, "a").unwrap();
        let first = digest_of(&path).expect("first");
        assert_ne!(absent, first);
        assert_eq!(first, digest_of(&path).expect("again"));
        std::fs::write(&path, "b").unwrap();
        assert_ne!(first, digest_of(&path).expect("changed"));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_refuses_and_leaves_the_file_untouched_when_it_changed_since_read() {
        let path = tmp_path("stale");
        std::fs::write(&path, "original").unwrap();
        let read_earlier = digest_of(&path).unwrap();
        std::fs::write(&path, "edited by the user meanwhile").unwrap();
        let err = write_guarded(&path, "ours", &read_earlier).expect_err("must refuse");
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "edited by the user meanwhile"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn write_replaces_an_unchanged_file_and_leaves_no_staging_file() {
        let dir = tmp_path("dir");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "original").unwrap();
        let read = digest_of(&path).unwrap();
        write_guarded(&path, "ours", &read).expect("write");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ours");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("settings.json")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn write_preserves_an_owner_only_mode_and_creates_new_files_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode_of =
            |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let existing = tmp_path("mode-existing");
        std::fs::write(&existing, "x").unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o600)).unwrap();
        write_guarded(&existing, "y", &digest_of(&existing).unwrap()).unwrap();
        assert_eq!(mode_of(&existing), 0o600);

        let fresh = tmp_path("mode-new");
        write_guarded(&fresh, "y", &digest_of(&fresh).unwrap()).unwrap();
        assert_eq!(mode_of(&fresh), 0o600);

        std::fs::remove_file(&existing).ok();
        std::fs::remove_file(&fresh).ok();
    }

    #[test]
    fn concurrent_edit_during_staging_is_refused_and_leaves_no_temp_file() {
        let dir = tmp_path("staging-edit");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "original").unwrap();
        let read = digest_of(&path).unwrap();
        let err = write_guarded_inner(&path, "ours", &read, &mut |step| {
            if step == Step::Synced {
                std::fs::write(&path, "edited while we staged").unwrap();
            }
            Ok(())
        })
        .expect_err("must refuse");
        assert!(
            err.to_string().contains("changed since it was read"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "edited while we staged"
        );
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("settings.json")]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn read_only_parent_error_names_the_file_and_says_it_was_not_changed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_path("read-only-parent");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "original").unwrap();
        let read = digest_of(&path).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        // root ignores directory permissions, so the failure can't be provoked.
        let probe = dir.join("probe");
        let is_enforced = std::fs::write(&probe, "").is_err();
        if is_enforced {
            let err = write_guarded(&path, "ours", &read).expect_err("must fail");
            let msg = err.to_string();
            assert!(msg.contains("settings.json was not changed"), "{msg}");
            assert!(msg.contains("could not stage the replacement"), "{msg}");
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "original");
        } else {
            std::fs::remove_file(&probe).ok();
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Child half of the crash test: aborts the process at the step named by
    /// `FORNAX_GW_CRASH_AT`. Ignored so it only runs when the parent test
    /// re-executes this binary with `--ignored`.
    #[test]
    #[ignore = "re-executed by crash_at_each_step_leaves_old_or_new_never_partial"]
    fn crash_child_aborts_at_the_requested_step() {
        let (Ok(at), Ok(dir)) = (
            std::env::var("FORNAX_GW_CRASH_AT"),
            std::env::var("FORNAX_GW_CRASH_DIR"),
        ) else {
            return;
        };
        let path = std::path::Path::new(&dir).join("settings.json");
        let read = digest_of(&path).unwrap();
        let _ = write_guarded_inner(&path, "NEW-CONTENT", &read, &mut |step| {
            if format!("{step:?}") == at {
                std::process::abort();
            }
            Ok(())
        });
    }

    /// A killed process keeps the page cache, so this proves atomicity only
    /// (the target is the old or the new bytes, never empty or partial). It
    /// does not prove fsync durability across power loss.
    #[test]
    fn crash_at_each_step_leaves_old_or_new_never_partial() {
        let exe = std::env::current_exe().unwrap();
        for step in ["Created", "Written", "Synced", "Renamed", "DirSynced"] {
            let dir = tmp_path(&format!("crash-{step}"));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("settings.json");
            std::fs::write(&path, "OLD-CONTENT").unwrap();
            let status = std::process::Command::new(&exe)
                .args([
                    "--exact",
                    "guarded_write::tests::crash_child_aborts_at_the_requested_step",
                    "--ignored",
                    "--nocapture",
                ])
                .env("FORNAX_GW_CRASH_AT", step)
                .env("FORNAX_GW_CRASH_DIR", &dir)
                .status()
                .unwrap();
            assert!(!status.success(), "{step}: child should have aborted");
            let on_disk = std::fs::read_to_string(&path).unwrap();
            assert!(
                on_disk == "OLD-CONTENT" || on_disk == "NEW-CONTENT",
                "{step}: target is neither old nor new: {on_disk:?}"
            );
            let staged = std::fs::read_dir(&dir)
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".fornax-tmp-")
                })
                .count();
            assert!(staged <= 1, "{step}: {staged} leftover staging files");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn a_failed_directory_sync_reports_that_the_content_reads_back_correctly() {
        let dir = tmp_path("dir-sync-fails");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, "original").unwrap();
        let read = digest_of(&path).unwrap();
        let err = write_guarded_inner(&path, "ours", &read, &mut |step| {
            if step == Step::DirSynced {
                return Err(std::io::Error::other("injected directory sync failure"));
            }
            Ok(())
        })
        .expect_err("must report the failed sync");
        let msg = err.to_string();
        assert!(
            msg.contains("was replaced and reads back correctly"),
            "{msg}"
        );
        assert!(msg.contains("injected directory sync failure"), "{msg}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "ours");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn verify_written_rejects_content_that_differs_from_the_intended_text() {
        let path = tmp_path("verify");
        std::fs::write(&path, "on disk").unwrap();
        assert!(verify_written(&path, "on disk").is_ok());
        assert!(verify_written(&path, "something else").is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_failure_after_the_rename_says_the_file_was_already_replaced() {
        let path = tmp_path("post-rename");
        std::fs::write(&path, "on disk").unwrap();
        let dir = path.parent().unwrap();
        let err = confirm_replaced(&path, dir, "different", &mut |_| Ok(()))
            .expect_err("verify must fail");
        assert!(err.to_string().contains("was replaced, but"), "{err}");
        std::fs::remove_file(&path).ok();
    }
}
