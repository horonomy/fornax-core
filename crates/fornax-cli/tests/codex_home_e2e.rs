//! FORNX-474: one active Codex root decides where `install`, `plan`,
//! `uninstall`, the optional hooks, the capture marker and `doctor` look. An
//! explicit non-empty `CODEX_HOME` wins; an unset or empty one keeps
//! `$HOME/.codex`. A relative `CODEX_HOME` is refused before anything is
//! written, because the daemon only accepts an absolute sessions directory.
//! Everything runs under a private temp tree; no real home is touched.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct World {
    root: PathBuf,
    home: PathBuf,
    custom: PathBuf,
    fornax_home: PathBuf,
}

impl World {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fornax-ch-e2e-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        let custom = root.join("custom-codex");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&custom).unwrap();
        Self {
            fornax_home: root.join("fh"),
            root,
            home,
            custom,
        }
    }

    fn run(&self, args: &[&str], codex_home: Option<&str>) -> Output {
        let mut c = Command::new(env!("CARGO_BIN_EXE_fornax"));
        c.args(args)
            .current_dir(&self.root)
            .env("HOME", &self.home)
            .env("FORNAX_HOME", &self.fornax_home)
            .env("PATH", "/usr/bin:/bin");
        match codex_home {
            Some(v) => c.env("CODEX_HOME", v),
            None => c.env_remove("CODEX_HOME"),
        };
        c.output().unwrap()
    }

    /// A second, distinct Codex home.
    fn other(&self) -> PathBuf {
        let d = self.root.join("other-codex");
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn custom_str(&self) -> String {
        self.custom.to_str().unwrap().to_owned()
    }

    fn default_tree(&self) -> PathBuf {
        self.home.join(".codex")
    }

    fn marker_dir(&self) -> Option<String> {
        let raw = fs::read(self.fornax_home.join("codex-watch.json")).ok()?;
        let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        v["sessions_dir"].as_str().map(str::to_owned)
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

#[test]
fn redirected_codex_home_is_where_install_wires_and_capture_watches() {
    let w = World::new();
    let custom = w.custom_str();
    let install = w.run(&["install", "codex"], Some(&custom));
    assert!(install.status.success(), "{}", out(&install));

    assert!(wired(&w.custom.join("config.toml")), "{}", out(&install));
    assert!(w.custom.join("hooks.json").exists());
    assert_eq!(
        w.marker_dir().as_deref(),
        Some(w.custom.join("sessions").to_str().unwrap()),
        "the daemon must watch the selected home's sessions"
    );
    assert!(
        !w.default_tree().exists(),
        "the default tree must not be created or edited"
    );

    let doctor = out(&w.run(&["doctor"], Some(&custom)));
    assert!(doctor.contains("[ok] codex wiring"), "{doctor}");
    assert!(doctor.contains("custom-codex/config.toml"), "{doctor}");
    assert!(doctor.contains("[ok] codex capture"), "{doctor}");
}

#[test]
fn an_unset_or_empty_codex_home_keeps_the_home_default() {
    for value in [None, Some("")] {
        let w = World::new();
        let install = w.run(&["install", "codex"], value);
        assert!(install.status.success(), "{}", out(&install));
        assert!(wired(&w.default_tree().join("config.toml")));
        assert_eq!(
            w.marker_dir().as_deref(),
            Some(w.default_tree().join("sessions").to_str().unwrap())
        );
        let doctor = out(&w.run(&["doctor"], value));
        assert!(doctor.contains("[ok] codex wiring"), "{doctor}");
        assert!(doctor.contains("[ok] codex capture"), "{doctor}");
    }
}

#[test]
fn doctor_never_calls_the_default_tree_healthy_for_a_redirected_home() {
    // The reported defect: wired under HOME/.codex, then the user selects
    // another home. The selected home is not wired and the daemon is not
    // watching its sessions, so neither row may be ok.
    let w = World::new();
    assert!(w.run(&["install", "codex"], None).status.success());
    assert!(wired(&w.default_tree().join("config.toml")));

    let doctor = out(&w.run(&["doctor"], Some(&w.custom_str())));
    assert!(doctor.contains("[!!] codex wiring"), "{doctor}");
    assert!(doctor.contains("[!!] codex capture"), "{doctor}");
    assert!(!doctor.contains("[ok] codex wiring"), "{doctor}");
    assert!(!doctor.contains("[ok] codex capture"), "{doctor}");
}

#[test]
fn foreign_or_malformed_config_in_the_redirected_home_is_preserved() {
    for (name, body) in [
        (
            "foreign",
            "model = \"x\"\nnotify = [\"/usr/local/bin/foreign-notify\"]\n",
        ),
        ("malformed", "notify = [unterminated\nmodel = \"x\"\n"),
    ] {
        let w = World::new();
        let config = w.custom.join("config.toml");
        fs::write(&config, body).unwrap();
        let custom = w.custom_str();

        let _ = w.run(&["install", "codex"], Some(&custom));
        assert_eq!(
            fs::read_to_string(&config).unwrap(),
            body,
            "{name}: the selected home's config must be left byte-for-byte alone"
        );
        assert!(
            !w.default_tree().join("config.toml").exists(),
            "{name}: the default tree must not be touched"
        );
        let doctor = out(&w.run(&["doctor"], Some(&custom)));
        assert!(doctor.contains("[!!] codex wiring"), "{name}: {doctor}");
        assert!(!doctor.contains("[ok] codex wiring"), "{name}: {doctor}");
    }
}

#[test]
fn uninstall_follows_the_selected_home_and_leaves_the_other_tree_alone() {
    let w = World::new();
    let custom = w.custom_str();
    assert!(w.run(&["install", "codex"], None).status.success());
    assert!(w.run(&["install", "codex"], Some(&custom)).status.success());
    assert!(wired(&w.default_tree().join("config.toml")));
    assert!(wired(&w.custom.join("config.toml")));

    let un = w.run(&["uninstall", "codex"], Some(&custom));
    assert!(un.status.success(), "{}", out(&un));
    assert!(!wired(&w.custom.join("config.toml")), "{}", out(&un));
    assert!(
        wired(&w.default_tree().join("config.toml")),
        "the default tree was not selected and must stay as it was"
    );
}

#[test]
fn a_relative_codex_home_is_refused_before_anything_is_written() {
    let w = World::new();
    for args in [&["install", "codex"][..], &["adapter", "plan", "codex"][..]] {
        let o = w.run(args, Some("relative/codex"));
        assert!(!o.status.success(), "{args:?}: {}", out(&o));
        assert!(out(&o).contains("CODEX_HOME"), "{args:?}: {}", out(&o));
    }
    assert!(!w.default_tree().exists());
    assert!(!w.root.join("relative").exists());
    assert!(w.marker_dir().is_none());
    assert!(!w.fornax_home.join("bin").exists());
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn uninstall_leaves_capture_on_when_it_watches_a_different_home() {
    // The marker is global. Wire home A, then home B (the marker now names
    // B). Uninstalling A must not switch off capture B still depends on.
    let w = World::new();
    let a = w.custom_str();
    let b_path = w.other();
    let b = b_path.to_str().unwrap().to_owned();
    assert!(w.run(&["install", "codex"], Some(&a)).status.success());
    assert!(w.run(&["install", "codex"], Some(&b)).status.success());
    assert_eq!(
        w.marker_dir().as_deref(),
        Some(b_path.join("sessions").to_str().unwrap())
    );

    let un = w.run(&["uninstall", "codex"], Some(&a));
    assert!(un.status.success(), "{}", out(&un));
    assert!(!wired(&w.custom.join("config.toml")));
    assert!(wired(&b_path.join("config.toml")));
    assert_eq!(
        w.marker_dir().as_deref(),
        Some(b_path.join("sessions").to_str().unwrap()),
        "capture for home B must stay on: {}",
        out(&un)
    );
    assert!(out(&un).contains("left on"), "{}", out(&un));

    let un_b = w.run(&["uninstall", "codex"], Some(&b));
    assert!(un_b.status.success(), "{}", out(&un_b));
    assert!(w.marker_dir().is_none(), "{}", out(&un_b));
}

#[test]
fn doctor_flags_a_relative_codex_home_and_ignores_a_stray_config_in_the_cwd() {
    let w = World::new();
    let stray = w.root.join("relative").join("codex");
    fs::create_dir_all(&stray).unwrap();
    fs::write(
        stray.join("config.toml"),
        "notify = [\"/x/fornax-codex-notify.sh\"]\n",
    )
    .unwrap();
    let doctor = out(&w.run(&["doctor"], Some("relative/codex")));
    assert!(doctor.contains("[!!] codex wiring"), "{doctor}");
    assert!(doctor.contains("CODEX_HOME"), "{doctor}");
    assert!(!doctor.contains("[ok] codex wiring"), "{doctor}");
}

#[cfg(unix)]
#[test]
fn a_non_utf8_codex_home_is_refused_before_anything_is_written() {
    use std::os::unix::ffi::OsStrExt;
    let w = World::new();
    let bad = std::ffi::OsStr::from_bytes(b"/tmp/fornax-\xff-codex");
    let o = Command::new(env!("CARGO_BIN_EXE_fornax"))
        .args(["install", "codex"])
        .current_dir(&w.root)
        .env("HOME", &w.home)
        .env("FORNAX_HOME", &w.fornax_home)
        .env("PATH", "/usr/bin:/bin")
        .env("CODEX_HOME", bad)
        .output()
        .unwrap();
    assert!(!o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("CODEX_HOME"), "{}", out(&o));
    assert!(!w.default_tree().exists());
    assert!(w.marker_dir().is_none());
}
