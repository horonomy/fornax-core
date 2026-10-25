//! FORNX-468: `fornax install codex` is the user's opt-in to daemon-managed
//! Codex capture. It must say what is read, write the marker the daemon
//! checks, and `uninstall codex` must turn it off.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Scratch {
    home: PathBuf,
    fornax_home: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("fornax-cw-e2e-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        Self {
            home,
            fornax_home: root.join("fornax"),
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fornax"))
            .args(args)
            .env("HOME", &self.home)
            .env("FORNAX_HOME", &self.fornax_home)
            .env_remove("CODEX_HOME")
            .output()
            .unwrap()
    }

    fn marker(&self) -> PathBuf {
        self.fornax_home.join("codex-watch.json")
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn plan_reports_capture_before_install_and_install_discloses_what_is_read() {
    let s = Scratch::new();
    let plan = s.run(&["adapter", "plan", "codex"]);
    assert!(plan.status.success());
    let plan_text = stdout(&plan);
    assert!(
        plan_text.contains("would enable daemon Codex capture"),
        "{plan_text}"
    );
    assert!(!s.marker().exists(), "plan must not write anything");

    let out = s.run(&["install", "codex"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    assert!(
        text.contains("every Codex session on this machine"),
        "{text}"
    );
    assert!(text.contains("secret-pattern redaction only"), "{text}");

    let marker: serde_json::Value = serde_json::from_slice(&fs::read(s.marker()).unwrap()).unwrap();
    assert_eq!(
        marker["sessions_dir"],
        s.home.join(".codex").join("sessions").to_str().unwrap()
    );

    let again = stdout(&s.run(&["adapter", "plan", "codex"]));
    assert!(
        again.contains("daemon Codex capture already enabled"),
        "{again}"
    );
}

#[test]
fn uninstall_turns_capture_off() {
    let s = Scratch::new();
    assert!(s.run(&["install", "codex"]).status.success());
    assert!(s.marker().exists());
    let out = s.run(&["uninstall", "codex"]);
    assert!(out.status.success());
    assert!(!s.marker().exists(), "marker must be removed");
    assert!(stdout(&out).contains("daemon Codex capture turned off"));
}
