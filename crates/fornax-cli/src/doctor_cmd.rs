//! `fornax doctor` checklist (FORNX-469). The command used to print only the
//! execution-identity paragraph, which tells a user nothing when no finding
//! appears. This answers the first-run questions in order -- is the daemon
//! up, is the agent wired, is capture on -- each with the next step.
//! Read-only: no subprocess, no writes, no database access.

use std::path::Path;

pub struct Check {
    pub ok: bool,
    pub name: &'static str,
    pub detail: String,
}

pub struct Inputs<'a> {
    pub fornax_home: &'a Path,
    pub codex_config: &'a Path,
    pub daemon_reachable: bool,
    pub autostart_file: bool,
}

pub fn checks(i: &Inputs) -> Vec<Check> {
    let mut out = Vec::new();

    out.push(if i.daemon_reachable {
        Check {
            ok: true,
            name: "daemon",
            detail: "running and accepting connections".into(),
        }
    } else {
        let how = if i.autostart_file {
            "load the login item: launchctl bootstrap gui/$(id -u) \
             ~/Library/LaunchAgents/com.horonomy.fornax-daemon.plist"
        } else {
            "start `fornax-daemon`, or run `fornax install codex` to get a login item for it"
        };
        Check {
            ok: false,
            name: "daemon",
            detail: format!(
                "not reachable at {}; nothing is recorded until it runs -- {how}",
                i.fornax_home.join("fornax.sock").display()
            ),
        }
    });

    let notify = std::fs::read_to_string(i.codex_config)
        .map(|t| t.contains("fornax-codex-notify.sh"))
        .unwrap_or(false);
    out.push(Check {
        ok: notify,
        name: "codex wiring",
        detail: if notify {
            format!("notify entry present in {}", i.codex_config.display())
        } else {
            "Fornax is not wired into Codex -- run `fornax install codex`".into()
        },
    });

    let capture = crate::codex_watch_marker::is_installed(i.fornax_home);
    out.push(Check {
        ok: capture,
        name: "codex capture",
        detail: if capture {
            "on: the daemon reads Codex sessions and checks \"tests passed\" claims \
             (`fornax uninstall codex` turns it off)"
                .into()
        } else {
            "off: Codex claims are not checked -- `fornax install codex` turns it on".into()
        },
    });

    out
}

pub fn render(checks: &[Check]) -> String {
    let mut s = String::from("Fornax checklist\n");
    for c in checks {
        s.push_str(&format!(
            "  [{}] {}: {}\n",
            if c.ok { "ok" } else { "!!" },
            c.name,
            c.detail
        ));
    }
    if checks.iter().all(|c| c.ok) {
        s.push_str(
            "A finding appears after an agent says it ran tests and the run's own output \
             (exit code) is seen; see them with `fornax status` and `fornax detail`.\n",
        );
    }
    s
}

pub fn report(fornax_home: &Path) -> String {
    let sock = fornax_home.join("fornax.sock");
    let reachable = std::os::unix::net::UnixStream::connect(&sock).is_ok();
    let codex_config = crate::codex_adapter::default_path();
    let inputs = Inputs {
        fornax_home,
        codex_config: &codex_config,
        daemon_reachable: reachable,
        autostart_file: crate::launchd_plist::plist_path(&crate::dirs_home()).exists(),
    };
    render(&checks(&inputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fnx-doctor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn fresh_machine_reports_each_gap_with_its_next_step() {
        let d = scratch("fresh");
        let cs = checks(&Inputs {
            fornax_home: &d,
            codex_config: &d.join("config.toml"),
            daemon_reachable: false,
            autostart_file: false,
        });
        assert!(cs.iter().all(|c| !c.ok));
        let text = render(&cs);
        assert!(text.contains("[!!] daemon"));
        assert!(text.contains("fornax install codex"));
        assert!(!text.contains("A finding appears"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn a_wired_running_machine_is_all_ok() {
        let d = scratch("ready");
        let cfg = d.join("config.toml");
        std::fs::write(&cfg, "notify = [\"/x/bin/fornax-codex-notify.sh\"]\n").unwrap();
        std::fs::write(d.join(crate::codex_watch_marker::MARKER_FILE), "{}").unwrap();
        let cs = checks(&Inputs {
            fornax_home: &d,
            codex_config: &cfg,
            daemon_reachable: true,
            autostart_file: true,
        });
        assert!(cs.iter().all(|c| c.ok), "{}", render(&cs));
        assert!(render(&cs).contains("A finding appears"));
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_installed_login_item_changes_the_daemon_advice() {
        let d = scratch("plist");
        let cs = checks(&Inputs {
            fornax_home: &d,
            codex_config: &d.join("none.toml"),
            daemon_reachable: false,
            autostart_file: true,
        });
        assert!(cs[0].detail.contains("launchctl bootstrap"));
        std::fs::remove_dir_all(&d).ok();
    }
}
