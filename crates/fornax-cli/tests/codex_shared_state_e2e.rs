//! FORNX-474 follow-up (independent QA F474-CROSS-01 / F474-PLAN-01). The
//! capture marker and the daemon's LaunchAgent plist are shared by every Codex
//! home (one per Fornax home), so uninstalling or planning for one home must
//! not act as if they were private to it. Everything runs under a private temp
//! tree with a copied `fornax` and a placeholder sibling `fornax-daemon`; no
//! real home, no `launchctl`, no model.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct World {
    root: PathBuf,
    home: PathBuf,
    fornax_home: PathBuf,
    bin: PathBuf,
}

#[allow(dead_code)] // the plist helpers are only used by the macOS-gated tests
impl World {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("fornax-ss-e2e-{}", uuid::Uuid::new_v4()));
        let (home, bin) = (root.join("home"), root.join("bin"));
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin).unwrap();
        // The plist is only written when a daemon binary sits next to `fornax`.
        fs::copy(env!("CARGO_BIN_EXE_fornax"), bin.join("fornax")).unwrap();
        fs::write(bin.join("fornax-daemon"), b"").unwrap();
        fs::set_permissions(bin.join("fornax-daemon"), fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            fornax_home: root.join("fh"),
            root,
            home,
            bin,
        }
    }

    fn codex_dir(&self, name: &str) -> PathBuf {
        let d = self.root.join(name);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn run(&self, args: &[&str], codex_home: Option<&Path>) -> Output {
        let mut c = Command::new(self.bin.join("fornax"));
        c.args(args)
            .current_dir(&self.root)
            .env("HOME", &self.home)
            .env("FORNAX_HOME", &self.fornax_home)
            .env("PATH", "/usr/bin:/bin");
        match codex_home {
            Some(d) => c.env("CODEX_HOME", d),
            None => c.env_remove("CODEX_HOME"),
        };
        c.output().unwrap()
    }

    fn plist(&self) -> PathBuf {
        self.home
            .join("Library/LaunchAgents/com.horonomy.fornax-daemon.plist")
    }

    fn marker_dir(&self) -> Option<String> {
        let raw = fs::read(self.fornax_home.join("codex-watch.json")).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        v["sessions_dir"].as_str().map(str::to_owned)
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn wired(config: &Path) -> bool {
    fs::read_to_string(config)
        .map(|t| t.contains("fornax-codex-notify.sh"))
        .unwrap_or(false)
}

fn sessions(dir: &Path) -> String {
    dir.join("sessions").to_str().unwrap().to_owned()
}

#[cfg(target_os = "macos")]
#[test]
fn uninstalling_one_home_keeps_the_autostart_another_home_still_needs() {
    let w = World::new();
    let (a, b) = (w.codex_dir("codex-a"), w.codex_dir("codex-b"));
    assert!(w.run(&["install", "codex"], Some(&a)).status.success());
    assert!(w.run(&["install", "codex"], Some(&b)).status.success());
    assert_eq!(w.marker_dir(), Some(sessions(&b)), "capture now follows B");
    let plist = fs::read(w.plist()).expect("install wrote the shared autostart plist");

    let un_a = w.run(&["uninstall", "codex"], Some(&a));
    assert!(un_a.status.success(), "{}", out(&un_a));
    assert!(!wired(&a.join("config.toml")));
    assert!(wired(&b.join("config.toml")), "B's config must stay wired");
    assert_eq!(
        w.marker_dir(),
        Some(sessions(&b)),
        "B's capture must stay on"
    );
    assert_eq!(
        fs::read(w.plist()).ok().as_deref(),
        Some(plist.as_slice()),
        "the shared autostart plist B still needs must be kept byte-for-byte: {}",
        out(&un_a)
    );
    assert!(
        !out(&un_a).contains("launchctl bootout"),
        "must not tell the user to stop a service B still needs: {}",
        out(&un_a)
    );
    assert!(out(&un_a).contains("left in place"), "{}", out(&un_a));

    // The last user of the daemon removes it, with the stop advice.
    let un_b = w.run(&["uninstall", "codex"], Some(&b));
    assert!(un_b.status.success(), "{}", out(&un_b));
    assert!(!w.plist().exists());
    assert!(w.marker_dir().is_none());
    assert!(out(&un_b).contains("launchctl bootout"), "{}", out(&un_b));

    // Idempotent: nothing left to remove, and no stale stop advice.
    let again = w.run(&["uninstall", "codex"], Some(&b));
    assert!(again.status.success(), "{}", out(&again));
    assert!(out(&again).contains("nothing to remove"), "{}", out(&again));
    assert!(
        !out(&again).contains("launchctl bootout"),
        "{}",
        out(&again)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn uninstall_order_does_not_matter_for_the_last_user_removing_the_autostart() {
    let w = World::new();
    let (a, b) = (w.codex_dir("codex-a"), w.codex_dir("codex-b"));
    assert!(w.run(&["install", "codex"], Some(&a)).status.success());
    assert!(w.run(&["install", "codex"], Some(&b)).status.success());

    // B holds the capture; uninstalling it is the last use of the daemon.
    let un_b = w.run(&["uninstall", "codex"], Some(&b));
    assert!(un_b.status.success(), "{}", out(&un_b));
    assert!(!w.plist().exists(), "{}", out(&un_b));
    assert!(w.marker_dir().is_none());

    // A (capture long since moved to B) can still be unwired cleanly.
    assert!(wired(&a.join("config.toml")));
    let un_a = w.run(&["uninstall", "codex"], Some(&a));
    assert!(un_a.status.success(), "{}", out(&un_a));
    assert!(!wired(&a.join("config.toml")));
    assert!(!w.plist().exists());
}

#[cfg(target_os = "macos")]
#[test]
fn a_single_home_still_removes_its_autostart_with_the_stop_advice() {
    // Negative control: nothing else needs the daemon, so nothing is kept.
    let w = World::new();
    let a = w.codex_dir("codex-a");
    assert!(w.run(&["install", "codex"], Some(&a)).status.success());
    assert!(w.plist().exists());
    let un = w.run(&["uninstall", "codex"], Some(&a));
    assert!(un.status.success(), "{}", out(&un));
    assert!(!w.plist().exists(), "{}", out(&un));
    assert!(out(&un).contains("launchctl bootout"), "{}", out(&un));
    assert!(!out(&un).contains("left in place"), "{}", out(&un));
}

#[cfg(target_os = "macos")]
#[test]
fn claude_code_hooks_also_keep_the_shared_autostart() {
    let w = World::new();
    let a = w.codex_dir("codex-a");
    assert!(w
        .run(&["install", "claude-code"], Some(&a))
        .status
        .success());
    assert!(w.run(&["install", "codex"], Some(&a)).status.success());
    let plist = fs::read(w.plist()).unwrap();

    let un = w.run(&["uninstall", "codex"], Some(&a));
    assert!(un.status.success(), "{}", out(&un));
    assert_eq!(
        fs::read(w.plist()).ok().as_deref(),
        Some(plist.as_slice()),
        "{}",
        out(&un)
    );
    assert!(out(&un).contains("Claude Code"), "{}", out(&un));
    assert!(!out(&un).contains("launchctl bootout"), "{}", out(&un));

    // Once nothing else needs the daemon, uninstalling again removes it.
    assert!(w
        .run(&["uninstall", "claude-code"], Some(&a))
        .status
        .success());
    let last = w.run(&["uninstall", "codex"], Some(&a));
    assert!(last.status.success(), "{}", out(&last));
    assert!(!w.plist().exists(), "{}", out(&last));
    assert!(out(&last).contains("launchctl bootout"), "{}", out(&last));
}

#[test]
fn plan_reports_the_capture_move_that_install_will_make() {
    let w = World::new();
    let (a, b) = (w.codex_dir("codex-a"), w.codex_dir("codex-b"));

    // Positive control: nothing installed yet.
    let fresh = out(&w.run(&["adapter", "plan", "codex"], Some(&a)));
    assert!(
        fresh.contains("would enable daemon Codex capture"),
        "{fresh}"
    );

    assert!(w.run(&["install", "codex"], Some(&a)).status.success());
    assert!(w.run(&["install", "codex"], Some(&b)).status.success());
    assert_eq!(w.marker_dir(), Some(sessions(&b)));

    // Capture is on, but for B: installing A would move it, and the plan says so.
    let plan_a = out(&w.run(&["adapter", "plan", "codex"], Some(&a)));
    assert!(!plan_a.contains("already enabled"), "{plan_a}");
    assert!(
        plan_a.contains("would move daemon Codex capture"),
        "{plan_a}"
    );
    assert!(
        plan_a.contains(&sessions(&b)) && plan_a.contains(&sessions(&a)),
        "{plan_a}"
    );
    assert!(plan_a.contains("only one Codex home"), "{plan_a}");

    // Planning is read-only.
    assert_eq!(w.marker_dir(), Some(sessions(&b)));

    // The plan matches the actual effect, and install says what it did.
    let install_a = w.run(&["install", "codex"], Some(&a));
    assert!(install_a.status.success(), "{}", out(&install_a));
    assert_eq!(w.marker_dir(), Some(sessions(&a)));
    assert!(
        out(&install_a).contains("moved daemon Codex capture"),
        "{}",
        out(&install_a)
    );
    assert!(
        out(&install_a).contains(&sessions(&b)),
        "{}",
        out(&install_a)
    );

    // Same home again: genuinely already enabled, and no move is claimed.
    let again = out(&w.run(&["adapter", "plan", "codex"], Some(&a)));
    assert!(again.contains("already enabled"), "{again}");
    assert!(!again.contains("would move"), "{again}");
    let reinstall = out(&w.run(&["install", "codex"], Some(&a)));
    assert!(
        !reinstall.contains("moved daemon Codex capture"),
        "{reinstall}"
    );
}

#[test]
fn plan_against_the_default_home_also_reports_the_move() {
    let w = World::new();
    let b = w.codex_dir("codex-b");
    assert!(w.run(&["install", "codex"], Some(&b)).status.success());
    let default_sessions = sessions(&w.home.join(".codex"));

    let plan = out(&w.run(&["adapter", "plan", "codex"], None));
    assert!(plan.contains("would move daemon Codex capture"), "{plan}");
    assert!(
        plan.contains(&default_sessions) && plan.contains(&sessions(&b)),
        "{plan}"
    );

    assert!(w.run(&["install", "codex"], None).status.success());
    assert_eq!(w.marker_dir(), Some(default_sessions));
}
