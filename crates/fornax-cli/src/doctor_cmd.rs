//! `fornax doctor` checklist (FORNX-469, FORNX-471). The command used to print
//! only the execution-identity paragraph, which tells a user nothing when no
//! finding appears. This answers the first-run questions in order -- is the
//! daemon up, is the agent wired, is capture on, has anything been seen -- each
//! with the next step.
//!
//! Configuration is not execution: a hook entry in `settings.json` shows what
//! Claude Code was told to run, never that it ran. Only recorded events show
//! that. No subprocess and no config writes. The database is opened only if it
//! already exists, read-only (no create, no migration, file unchanged), and only
//! to count rows; SQLite may create empty `-wal`/`-shm` sidecars to read a WAL
//! database.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// Something to fix before findings can appear.
    Gap,
    /// Provider not in use on this machine; nothing to fix.
    Idle,
}

pub struct Check {
    pub status: Status,
    pub name: &'static str,
    pub detail: String,
}

impl Check {
    fn new(ok: bool, name: &'static str, detail: String) -> Self {
        Check {
            status: if ok { Status::Ok } else { Status::Gap },
            name,
            detail,
        }
    }
}

/// Claude Code rows in the local database. `None` in [`Inputs`] means there is
/// no database yet (or it could not be read), which is different from zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaudeActivity {
    pub events: i64,
    pub claims: i64,
    pub findings: i64,
}

pub struct Inputs<'a> {
    pub fornax_home: &'a Path,
    pub codex_config: &'a Path,
    pub claude_settings: &'a Path,
    pub path_dirs: &'a [PathBuf],
    pub daemon_reachable: bool,
    pub autostart_file: bool,
    pub claude_activity: Option<ClaudeActivity>,
}

fn script_is_runnable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

fn find_on_path(name: &str, dirs: &[PathBuf]) -> Option<PathBuf> {
    dirs.iter()
        .map(|d| d.join(name))
        .find(|p| script_is_runnable(p))
}

pub fn checks(i: &Inputs) -> Vec<Check> {
    use crate::claude_adapter::{hook_command, wiring_at, Wiring};
    let mut out = Vec::new();

    out.push(if i.daemon_reachable {
        Check::new(true, "daemon", "running and accepting connections".into())
    } else {
        let how = if i.autostart_file {
            "load the login item: launchctl bootstrap gui/$(id -u) \
             ~/Library/LaunchAgents/com.horonomy.fornax-daemon.plist"
        } else {
            "start `fornax-daemon`, or run `fornax install codex` to get a login item for it"
        };
        Check::new(
            false,
            "daemon",
            format!(
                "not reachable at {}; nothing is recorded until it runs -- {how}",
                i.fornax_home.join("fornax.sock").display()
            ),
        )
    });

    use crate::codex_adapter::{notify_state_at, NotifyState};
    use crate::codex_watch_marker::{capture_state, Capture};
    let notify = notify_state_at(i.codex_config);
    let capture = capture_state(i.fornax_home, i.codex_config);
    let wiring = wiring_at(i.claude_settings);
    let claude_in_use = matches!(wiring, Wiring::Full | Wiring::Partial { .. });
    let codex_in_use = matches!(notify, NotifyState::Fornax(_) | NotifyState::Unreadable(_))
        || capture != Capture::Off;

    // Codex.
    if claude_in_use && !codex_in_use {
        out.push(Check {
            status: Status::Idle,
            name: "codex",
            detail: "not installed (optional); not needed while you use Claude Code only".into(),
        });
    } else {
        out.push(match &notify {
            NotifyState::Fornax(script) if script_is_runnable(script) => Check::new(
                true,
                "codex wiring",
                format!(
                    "notify runs {} (from {})",
                    script.display(),
                    i.codex_config.display()
                ),
            ),
            NotifyState::Fornax(script) => Check::new(
                false,
                "codex wiring",
                format!(
                    "notify points at {} which is missing or not executable -- run \
                     `fornax install codex` to rewrite it",
                    script.display()
                ),
            ),
            NotifyState::Foreign(cmd) => Check::new(
                false,
                "codex wiring",
                format!(
                    "notify in {} runs another command ({cmd}); Fornax will not replace it. \
                     Capture below does not need notify",
                    i.codex_config.display()
                ),
            ),
            NotifyState::Unreadable(why) => Check::new(
                false,
                "codex wiring",
                format!("{} cannot be used ({why})", i.codex_config.display()),
            ),
            NotifyState::Absent => Check::new(
                false,
                "codex wiring",
                "Fornax is not wired into Codex -- run `fornax install codex`".into(),
            ),
        });
        out.push(match &capture {
            Capture::Off => Check::new(
                false,
                "codex capture",
                "off: Codex claims are not checked -- `fornax install codex` turns it on".into(),
            ),
            Capture::Unusable(why) => Check::new(
                false,
                "codex capture",
                format!(
                    "codex-watch.json exists but the daemon will ignore it: {why} -- run \
                     `fornax install codex` to rewrite it"
                ),
            ),
            Capture::On {
                dir_matches_config: false,
                dir,
            } => Check::new(
                false,
                "codex capture",
                format!(
                    "on, but the daemon watches {} while this Codex config writes sessions \
                     elsewhere -- run `fornax install codex` to refresh it",
                    dir.display()
                ),
            ),
            Capture::On { .. } => Check::new(
                true,
                "codex capture",
                "on: the daemon reads Codex sessions and checks \"tests passed\" claims \
                 (`fornax uninstall codex` turns it off)"
                    .into(),
            ),
        });
    }

    // Claude Code.
    match &wiring {
        Wiring::Absent if codex_in_use => out.push(Check {
            status: Status::Idle,
            name: "claude code",
            detail: "not installed (optional); `fornax install claude-code` adds it".into(),
        }),
        Wiring::Absent => out.push(Check::new(
            false,
            "claude code wiring",
            format!(
                "Fornax hooks are not in {} -- run `fornax install claude-code`",
                i.claude_settings.display()
            ),
        )),
        Wiring::Unreadable(why) => out.push(Check::new(
            false,
            "claude code wiring",
            format!(
                "cannot read {} as a JSON object ({why}); Fornax will not touch it until it parses",
                i.claude_settings.display()
            ),
        )),
        Wiring::Partial { missing } => out.push(Check::new(
            false,
            "claude code wiring",
            format!(
                "hooks missing for {} in {} -- run `fornax install claude-code` to add them",
                missing.join(", "),
                i.claude_settings.display()
            ),
        )),
        Wiring::Full => {
            let name = hook_command();
            out.push(match find_on_path(name, i.path_dirs) {
                Some(p) => Check::new(
                    true,
                    "claude code wiring",
                    format!(
                        "all hook events configured; `{name}` is executable at {} on this shell's \
                         PATH (configuration only: Claude Code's own PATH is not checked)",
                        p.display()
                    ),
                ),
                None => Check::new(
                    false,
                    "claude code wiring",
                    format!(
                        "hooks are configured but `{name}` is not an executable on this shell's \
                         PATH, so Claude Code may fail to run it -- put its directory on PATH"
                    ),
                ),
            });
            out.push(match i.claude_activity {
                None => Check::new(
                    false,
                    "claude code events",
                    "no events recorded yet (no readable database) -- start the daemon, then \
                     start a new Claude Code session; an already-open one may not have loaded \
                     the hooks"
                        .into(),
                ),
                Some(a) if a.events == 0 => Check::new(
                    false,
                    "claude code events",
                    "no Claude Code events recorded yet -- start a new Claude Code session with \
                     the daemon running; an already-open one may not have loaded the hooks"
                        .into(),
                ),
                Some(a) if a.claims == 0 => Check::new(
                    true,
                    "claude code events",
                    format!(
                        "{} Claude Code events recorded; no \"tests passed\" claim seen yet",
                        a.events
                    ),
                ),
                Some(a) if a.findings == 0 => Check::new(
                    true,
                    "claude code events",
                    format!(
                        "{} events and {} claims recorded; none checked yet (a finding needs the \
                         run's own test output as evidence)",
                        a.events, a.claims
                    ),
                ),
                Some(a) => Check::new(
                    true,
                    "claude code events",
                    format!(
                        "{} events, {} claims, {} findings recorded",
                        a.events, a.claims, a.findings
                    ),
                ),
            });
            out.push(Check::new(
                true,
                "claude code limit",
                "Claude Code gives no exit code, so a test result shows as Review, never \
                 Verified (accepted v0.0.9 limit, ADR-0025)"
                    .into(),
            ));
        }
    }

    out
}

pub fn render(checks: &[Check]) -> String {
    let mut s = String::from("Fornax checklist\n");
    for c in checks {
        let tag = match c.status {
            Status::Ok => "ok",
            Status::Gap => "!!",
            Status::Idle => "--",
        };
        s.push_str(&format!("  [{tag}] {}: {}\n", c.name, c.detail));
    }
    if checks.iter().all(|c| c.status != Status::Gap) {
        s.push_str(
            "A finding appears after an agent says it ran tests and the run's own output \
             (exit code) is seen; see them with `fornax status` and `fornax detail`.\n",
        );
    }
    s
}

/// Counts Claude Code rows if a database already exists. Read-only: never
/// creates the file, runs migrations, or changes journal mode.
async fn claude_activity(fornax_home: &Path) -> Option<ClaudeActivity> {
    let db = fornax_home.join("fornax.db");
    if !db.exists() {
        return None;
    }
    let provider = serde_json::to_value(fornax_types::Provider::ClaudeCode).ok()?;
    let provider = provider.as_str()?.to_owned();
    let read = async {
        let store = fornax_store::Store::open_read_only(&db).await.ok()?;
        let rows = store.sessions_overview().await.ok()?;
        Some(rows.iter().filter(|r| r.provider == provider).fold(
            ClaudeActivity {
                events: 0,
                claims: 0,
                findings: 0,
            },
            |a, r| ClaudeActivity {
                events: a.events + r.event_count,
                claims: a.claims + r.claim_count,
                findings: a.findings + r.finding_count,
            },
        ))
    };
    tokio::time::timeout(std::time::Duration::from_secs(3), read)
        .await
        .ok()
        .flatten()
}

pub async fn report(fornax_home: &Path) -> String {
    let sock = fornax_home.join("fornax.sock");
    let reachable = std::os::unix::net::UnixStream::connect(&sock).is_ok();
    let codex_config = crate::codex_adapter::default_path();
    let claude_settings = crate::claude_adapter::default_path();
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let inputs = Inputs {
        fornax_home,
        codex_config: &codex_config,
        claude_settings: &claude_settings,
        path_dirs: &path_dirs,
        daemon_reachable: reachable,
        autostart_file: crate::launchd_plist::plist_path(&crate::dirs_home()).exists(),
        claude_activity: claude_activity(fornax_home).await,
    };
    render(&checks(&inputs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fnx-doctor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    struct World {
        d: PathBuf,
        path_dirs: Vec<PathBuf>,
        reachable: bool,
        autostart: bool,
        activity: Option<ClaudeActivity>,
    }

    impl World {
        fn new(name: &str) -> Self {
            let d = scratch(name);
            World {
                path_dirs: vec![d.join("bin")],
                d,
                reachable: false,
                autostart: false,
                activity: None,
            }
        }
        fn codex_cfg(&self) -> PathBuf {
            self.d.join("config.toml")
        }
        fn claude_cfg(&self) -> PathBuf {
            self.d.join("settings.json")
        }
        fn install_claude(&self) {
            crate::claude_adapter::install_at(&self.claude_cfg()).unwrap();
        }
        fn script(&self) -> PathBuf {
            self.d.join("bin").join("fornax-codex-notify.sh")
        }
        /// A Codex setup the installer and daemon would both accept.
        fn wire_codex(&self) {
            std::fs::create_dir_all(self.d.join("bin")).unwrap();
            std::fs::write(self.script(), "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(self.script(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            std::fs::write(
                self.codex_cfg(),
                format!("notify = [\"{}\"]\n", self.script().display()),
            )
            .unwrap();
            self.write_marker(&format!(
                r#"{{"sessions_dir":"{}"}}"#,
                self.d.join("sessions").display()
            ));
        }
        fn write_marker(&self, body: &str) {
            std::fs::write(self.d.join(crate::codex_watch_marker::MARKER_FILE), body).unwrap();
        }
        fn put_hook_on_path(&self, mode: u32) {
            std::fs::create_dir_all(self.d.join("bin")).unwrap();
            let p = self
                .d
                .join("bin")
                .join(crate::claude_adapter::hook_command());
            std::fs::write(&p, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        fn run(&self) -> Vec<Check> {
            checks(&Inputs {
                fornax_home: &self.d,
                codex_config: &self.codex_cfg(),
                claude_settings: &self.claude_cfg(),
                path_dirs: &self.path_dirs,
                daemon_reachable: self.reachable,
                autostart_file: self.autostart,
                claude_activity: self.activity,
            })
        }
        fn text(&self) -> String {
            render(&self.run())
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.d).ok();
        }
    }

    fn act(events: i64, claims: i64, findings: i64) -> Option<ClaudeActivity> {
        Some(ClaudeActivity {
            events,
            claims,
            findings,
        })
    }

    #[test]
    fn fresh_machine_reports_each_gap_with_its_next_step() {
        let w = World::new("fresh");
        let cs = w.run();
        assert!(cs.iter().all(|c| c.status == Status::Gap));
        let text = render(&cs);
        assert!(text.contains("[!!] daemon"));
        assert!(text.contains("fornax install codex"));
        assert!(text.contains("fornax install claude-code"));
        assert!(!text.contains("A finding appears"));
    }

    #[test]
    fn a_wired_running_codex_machine_is_all_ok() {
        let mut w = World::new("ready");
        w.wire_codex();
        w.reachable = true;
        w.autostart = true;
        let t = w.text();
        assert!(w.run().iter().all(|c| c.status != Status::Gap), "{t}");
        assert!(t.contains("[--] claude code: not installed (optional)"));
        assert!(t.contains("A finding appears"));
    }

    // QA F2: a mention of the script is not wiring.
    #[test]
    fn a_comment_beside_a_foreign_notify_is_not_codex_wiring() {
        let w = World::new("comment");
        std::fs::write(
            w.codex_cfg(),
            "# notify = [\"/x/fornax-codex-notify.sh\"]\nnotify = [\"/usr/bin/other\"]\n",
        )
        .unwrap();
        let t = w.text();
        assert!(t.contains("[!!] codex wiring: notify in"), "{t}");
        assert!(t.contains("runs another command (/usr/bin/other)"), "{t}");
    }

    #[test]
    fn the_script_name_in_another_key_or_a_comment_alone_is_not_wiring() {
        let w = World::new("othercomment");
        std::fs::write(
            w.codex_cfg(),
            "# fornax-codex-notify.sh\nmodel = \"fornax-codex-notify.sh\"\n",
        )
        .unwrap();
        assert!(w
            .text()
            .contains("[!!] codex wiring: Fornax is not wired into Codex"));
    }

    #[test]
    fn a_fornax_notify_whose_script_is_gone_or_not_executable_is_a_gap() {
        let w = World::new("stale-script");
        w.wire_codex();
        std::fs::set_permissions(w.script(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(w.text().contains("[!!] codex wiring: notify points at"));
        std::fs::remove_file(w.script()).unwrap();
        assert!(w.text().contains("missing or not executable"));
    }

    #[test]
    fn invalid_toml_is_reported_not_treated_as_wired() {
        let w = World::new("badtoml");
        std::fs::write(w.codex_cfg(), "notify = [\"/x/fornax-codex-notify.sh\"\n").unwrap();
        assert!(w.text().contains("[!!] codex wiring:"), "{}", w.text());
        assert!(!w.text().contains("[ok] codex wiring"));
    }

    // QA F2: marker existence is not marker validity (daemon's own rule).
    #[test]
    fn an_empty_invalid_or_relative_marker_is_not_capture_on() {
        let w = World::new("marker");
        w.wire_codex();
        for body in ["{}", "", "not json", r#"{"sessions_dir":"sessions"}"#] {
            w.write_marker(body);
            let t = w.text();
            assert!(
                t.contains(
                    "[!!] codex capture: codex-watch.json exists but the daemon will ignore it"
                ),
                "{body:?} -> {t}"
            );
            assert!(!t.contains("[ok] codex capture"), "{body:?}");
        }
    }

    #[test]
    fn a_marker_for_another_sessions_dir_is_not_capture_on() {
        let w = World::new("marker-dir");
        w.wire_codex();
        w.write_marker(r#"{"sessions_dir":"/somewhere/else/sessions"}"#);
        let t = w.text();
        assert!(
            t.contains("[!!] codex capture: on, but the daemon watches /somewhere/else/sessions"),
            "{t}"
        );
    }

    #[test]
    fn an_installed_login_item_changes_the_daemon_advice() {
        let mut w = World::new("plist");
        w.autostart = true;
        assert!(w.run()[0].detail.contains("launchctl bootstrap"));
    }

    #[test]
    fn claude_only_user_is_not_told_codex_is_broken() {
        let w = World::new("claude-only");
        w.install_claude();
        let t = w.text();
        assert!(t.contains("[--] codex: not installed (optional)"), "{t}");
        assert!(!t.contains("[!!] codex"), "{t}");
    }

    #[test]
    fn partial_claude_wiring_names_the_missing_events() {
        let w = World::new("partial");
        std::fs::write(
            w.claude_cfg(),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"fornax-hook-claude"}]}]}}"#,
        )
        .unwrap();
        let t = w.text();
        assert!(
            t.contains("[!!] claude code wiring: hooks missing for SessionStart"),
            "{t}"
        );
        assert!(
            !t.contains("PreToolUse, PostToolUse, Stop"),
            "Stop is wired: {t}"
        );
    }

    #[test]
    fn a_foreign_hook_alone_is_not_installed() {
        let w = World::new("foreign");
        std::fs::write(
            w.claude_cfg(),
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/usr/bin/true"}]}]}}"#,
        )
        .unwrap();
        assert!(w.text().contains("Fornax hooks are not in"));
    }

    #[test]
    fn unparseable_settings_are_reported_not_overwritten() {
        let w = World::new("broken");
        std::fs::write(w.claude_cfg(), "{ not json").unwrap();
        let t = w.text();
        assert!(
            t.contains("cannot read") && t.contains("will not touch it"),
            "{t}"
        );
        assert_eq!(
            std::fs::read_to_string(w.claude_cfg()).unwrap(),
            "{ not json"
        );
    }

    #[test]
    fn configured_hook_missing_from_path_is_a_gap_not_a_pass() {
        let w = World::new("nopath");
        w.install_claude();
        let t = w.text();
        assert!(
            t.contains("[!!] claude code wiring: hooks are configured but"),
            "{t}"
        );
    }

    #[test]
    fn a_non_executable_hook_file_does_not_count() {
        let w = World::new("noexec");
        w.install_claude();
        w.put_hook_on_path(0o644);
        assert!(w
            .text()
            .contains("[!!] claude code wiring: hooks are configured but"));
    }

    #[test]
    fn configuration_alone_never_claims_the_hook_ran() {
        let w = World::new("cfg-only");
        w.install_claude();
        w.put_hook_on_path(0o755);
        let t = w.text();
        assert!(t.contains("[ok] claude code wiring"), "{t}");
        assert!(t.contains("configuration only"), "{t}");
        assert!(
            t.contains("[!!] claude code events: no events recorded yet"),
            "{t}"
        );
        assert!(!t.contains("events recorded;"), "{t}");
    }

    #[test]
    fn recorded_events_are_the_only_proof_and_each_stage_is_distinct() {
        let mut w = World::new("events");
        w.install_claude();
        w.put_hook_on_path(0o755);

        w.activity = act(0, 0, 0);
        assert!(w
            .text()
            .contains("[!!] claude code events: no Claude Code events recorded yet"));

        w.activity = act(7, 0, 0);
        let t = w.text();
        assert!(
            t.contains("[ok] claude code events: 7 Claude Code events recorded; no"),
            "{t}"
        );

        w.activity = act(7, 2, 0);
        assert!(w.text().contains("2 claims recorded; none checked yet"));

        w.activity = act(7, 2, 1);
        assert!(w.text().contains("7 events, 2 claims, 1 findings recorded"));
    }

    #[test]
    fn provider_limit_is_stated_only_when_claude_is_wired() {
        let w = World::new("limit");
        assert!(!w.text().contains("ADR-0025"));
        w.install_claude();
        assert!(w.text().contains("never Verified"));
    }

    #[test]
    fn doctor_never_writes_the_claude_settings() {
        let w = World::new("readonly");
        w.install_claude();
        let before = std::fs::read(w.claude_cfg()).unwrap();
        let _ = w.text();
        assert_eq!(std::fs::read(w.claude_cfg()).unwrap(), before);
    }

    #[test]
    fn a_broken_codex_config_is_not_hidden_when_claude_is_wired() {
        let w = World::new("broken-codex");
        w.install_claude();
        w.put_hook_on_path(0o755);
        std::fs::write(w.codex_cfg(), "notify = [unterminated\n").unwrap();
        let t = w.text();
        assert!(t.contains("[!!] codex wiring"), "{t}");
        assert!(!t.contains("[--] codex: not installed"), "{t}");
    }

    fn dir_state(d: &Path) -> Vec<(String, u64, std::time::SystemTime)> {
        let mut v: Vec<_> = std::fs::read_dir(d)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                let m = e.metadata().unwrap();
                (
                    e.file_name().to_string_lossy().into_owned(),
                    m.len(),
                    m.modified().unwrap(),
                )
            })
            .collect();
        v.sort();
        v
    }

    fn run_async<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn reading_activity_never_creates_or_changes_the_database() {
        let w = World::new("db-readonly");
        // No database: nothing is read and nothing is created.
        assert!(run_async(claude_activity(&w.d)).is_none());
        assert!(!w.d.join("fornax.db").exists());
        assert!(std::fs::read_dir(&w.d).unwrap().next().is_none());

        // An existing database: counted without touching a single file.
        run_async(async {
            let s = fornax_store::Store::open(w.d.join("fornax.db"))
                .await
                .unwrap();
            s.close().await;
        });
        let db = w.d.join("fornax.db");
        // Store::open would tighten this to 0600; a diagnostic must leave the
        // user's file mode alone (and this is what makes the test discriminating).
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        let snapshot = || {
            (
                std::fs::read(&db).unwrap(),
                db.metadata().unwrap().modified().unwrap(),
            )
        };
        let before = snapshot();
        let a = run_async(claude_activity(&w.d)).expect("existing db is readable");
        assert_eq!((a.events, a.claims, a.findings), (0, 0, 0));
        assert_eq!(
            snapshot(),
            before,
            "doctor must not change the database file"
        );
        assert_eq!(
            db.metadata().unwrap().permissions().mode() & 0o777,
            0o644,
            "doctor must not change the database file mode"
        );
        // SQLite itself may create the empty WAL sidecars when it opens a WAL
        // database to read; nothing else may appear and they hold no data.
        for (name, len, _) in dir_state(&w.d) {
            match name.as_str() {
                "fornax.db" | "fornax.db-shm" => {}
                "fornax.db-wal" => assert_eq!(len, 0, "wal sidecar must be empty"),
                other => panic!("unexpected file created: {other}"),
            }
        }
    }
}
