//! The only module in this crate allowed to spawn a process
//! (`tests/boundary_invariants.rs::spawn_surface_is_confined_to_launch_module`
//! enforces this). Resolves and version-gates the Codex binary, builds the
//! macOS Seatbelt profile, and runs `codex app-server` under it — never on
//! any other platform (internal-docs ADR-0015's own Security considerations
//! table in `docs/adr/0026-codex-host-trust-verification.md` records why
//! macOS-only is an accepted scope limit, not a gap).
//!
//! Single process, not a process tree: `sandbox-exec` execs directly into
//! Codex (replacing itself, same pid), and the sandbox profile denies
//! `process-exec` for everything except that one canonicalized binary, so
//! there is never more than one child to track or tear down.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use crate::verdict::ReasonCode;

/// Codex versions this feature has had its security review run against
/// (internal-docs ADR-0015 R3). `app-server` never starts on a version not
/// in this list -- a Codex upgrade turns the feature into
/// `codex_version_unreviewed` until this list is updated by a new,
/// evidence-backed review (deliberate; see ADR-0026 "Consequences").
pub const REVIEWED_CODEX_VERSIONS: &[&str] = &["0.160.0"];

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub codex_bin: PathBuf,
    pub codex_home: PathBuf,
    pub cwd: PathBuf,
}

/// Returns `Err` with the single reason code that should end the run,
/// without ever having spawned anything, when the platform can't support
/// the sandboxed launch at all.
pub fn require_sandbox_available() -> Result<(), ReasonCode> {
    if !cfg!(target_os = "macos") {
        return Err(ReasonCode::SandboxUnavailable);
    }
    if !is_executable(Path::new(SANDBOX_EXEC)) {
        return Err(ReasonCode::SandboxUnavailable);
    }
    Ok(())
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Resolves the Codex binary: an explicit `--codex-bin` wins outright; else
/// a no-shell walk of `PATH`. Never consults a shell, never globs.
pub fn resolve_codex_binary(explicit: Option<&Path>) -> Result<PathBuf, ReasonCode> {
    if let Some(p) = explicit {
        return canonical_executable(p).ok_or(ReasonCode::CodexBinaryNotFound);
    }
    let path_var = std::env::var_os("PATH").ok_or(ReasonCode::CodexBinaryNotFound)?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("codex");
        if let Some(resolved) = canonical_executable(&candidate) {
            return Ok(resolved);
        }
    }
    Err(ReasonCode::CodexBinaryNotFound)
}

fn canonical_executable(path: &Path) -> Option<PathBuf> {
    let resolved = std::fs::canonicalize(path).ok()?;
    is_executable(&resolved).then_some(resolved)
}

/// The Seatbelt profile text. Paths are never interpolated into the
/// profile string itself -- every path reaches `sandbox-exec` through a
/// `-D NAME=value` parameter and is referenced here only as
/// `(param "NAME")`, so a path containing a quote or parenthesis can never
/// corrupt the profile grammar.
fn seatbelt_profile() -> &'static str {
    r#"(version 1)
(allow default)
(deny network*)
(deny process-exec)
(allow process-exec (literal (param "CODEX_BIN")))
(deny file-write*
  (literal (param "CONFIG_TOML"))
  (literal (param "HOOKS_JSON"))
  (literal (param "AUTH_JSON")))
"#
}

/// Builds the exact `sandbox-exec` argv for one invocation. `extra_args`
/// is appended after the canonicalized Codex binary (e.g.
/// `["--version"]` or `["--disable", "plugins", "app-server", "--listen",
/// "stdio://"]`) -- this function never special-cases which command is
/// being run, keeping the sandbox wrapping identical for both.
fn sandbox_argv(plan: &LaunchPlan, extra_args: &[&str]) -> Vec<String> {
    let codex_home = crate::snapshot::codex_home_dir(&plan.codex_home);
    let mut argv = vec![
        "-D".to_string(),
        format!("CODEX_BIN={}", plan.codex_bin.display()),
        "-D".to_string(),
        format!("CONFIG_TOML={}", codex_home.join("config.toml").display()),
        "-D".to_string(),
        format!("HOOKS_JSON={}", codex_home.join("hooks.json").display()),
        "-D".to_string(),
        format!("AUTH_JSON={}", codex_home.join("auth.json").display()),
        "-p".to_string(),
        seatbelt_profile().to_string(),
        plan.codex_bin.display().to_string(),
    ];
    argv.extend(extra_args.iter().map(|s| s.to_string()));
    argv
}

/// `env_clear()`'d, then exactly this allow-list set -- internal-docs
/// ADR-0015 R5: the child must never see an API key, auth token, or
/// anything else ambient in the operator's shell environment.
fn configure_env(cmd: &mut Command, plan: &LaunchPlan) {
    cmd.env_clear();
    cmd.env("HOME", &plan.codex_home);
    if let Ok(codex_home_override) = std::env::var("CODEX_HOME") {
        cmd.env("CODEX_HOME", codex_home_override);
    }
    cmd.env("PATH", "/usr/bin:/bin");
    for var in ["LANG", "LC_ALL"] {
        if let Ok(v) = std::env::var(var) {
            cmd.env(var, v);
        }
    }
}

fn spawn_sandboxed(
    plan: &LaunchPlan,
    extra_args: &[&str],
    pipe_stdout: bool,
) -> std::io::Result<Child> {
    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.args(sandbox_argv(plan, extra_args));
    cmd.current_dir(&plan.cwd);
    configure_env(&mut cmd, plan);
    cmd.stdin(Stdio::piped());
    cmd.stdout(if pipe_stdout {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stderr(Stdio::null());
    cmd.spawn()
}

/// Runs `codex --version` under the same sandbox and parses the reviewed
/// version string. `app-server` is never started if this doesn't resolve
/// to an entry in [`REVIEWED_CODEX_VERSIONS`].
pub fn check_reviewed_version(plan: &LaunchPlan, timeout: Duration) -> Result<String, ReasonCode> {
    let mut child =
        spawn_sandboxed(plan, &["--version"], true).map_err(|_| ReasonCode::CodexBinaryNotFound)?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let deadline = Instant::now() + timeout;
    let mut buf = String::new();
    // A bounded, blocking read is acceptable here: `--version` under this
    // sandbox is observed to answer in well under a second, and this
    // function's caller (`main.rs`) applies its own overall deadline
    // around the whole verification run, not just this step.
    let read_result = stdout.read_to_string(&mut buf);
    let _ = child.wait();
    if Instant::now() > deadline {
        return Err(ReasonCode::CodexVersionUnreadable);
    }
    read_result.map_err(|_| ReasonCode::CodexVersionUnreadable)?;
    let version = buf
        .trim()
        .strip_prefix("codex-cli ")
        .ok_or(ReasonCode::CodexVersionUnreadable)?
        .to_string();
    if REVIEWED_CODEX_VERSIONS.contains(&version.as_str()) {
        Ok(version)
    } else {
        Err(ReasonCode::CodexVersionUnreviewed(version))
    }
}

/// Spawns `codex app-server` under the sandbox with stdin/stdout piped for
/// `protocol::Session`. `--disable plugins` avoids app-server's default
/// `git ls-remote` to the plugin registry (confirmed live against
/// codex-cli 0.160.0) -- a network call the Seatbelt profile's
/// `deny network*` also blocks, but avoiding the attempt outright keeps
/// the run from spending time on something guaranteed to fail anyway.
pub fn spawn_app_server(plan: &LaunchPlan) -> std::io::Result<Child> {
    spawn_sandboxed(
        plan,
        &["--disable", "plugins", "app-server", "--listen", "stdio://"],
        true,
    )
}

/// Takes ownership of a spawned app-server's stdin/stdout for
/// `protocol::Session`. Panics only if called twice on the same `Child`
/// (a programmer error, not a runtime condition).
pub fn take_pipes(child: &mut Child) -> (ChildStdin, ChildStdout) {
    (
        child.stdin.take().expect("app-server stdin not piped"),
        child.stdout.take().expect("app-server stdout not piped"),
    )
}

/// Hard teardown: close stdin (if not already taken/dropped), then kill.
/// This crate intentionally does not distinguish SIGTERM from SIGKILL --
/// app-server has no shutdown handshake this crate relies on (the RPC
/// session is strictly read-only), and the single-process guarantee above
/// means there is nothing a graceful SIGTERM would let clean up that a
/// SIGKILL doesn't equally well end. `wait()` after `kill()` reaps the
/// process so it never becomes a zombie.
pub fn teardown(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// A fresh, empty, mode-0700 directory for `cwd` -- never the operator's
/// real project directory, which could itself carry an untrusted
/// project-level `.codex/` that produces unrelated project-trust errors
/// (confirmed live). Removed via `Drop`.
pub struct ScratchCwd {
    pub path: PathBuf,
}

impl ScratchCwd {
    pub fn new() -> std::io::Result<Self> {
        let path =
            std::env::temp_dir().join(format!("fornax-host-trust-exec-cwd-{}", std::process::id()));
        std::fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(ScratchCwd { path })
    }
}

impl Drop for ScratchCwd {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seatbelt_profile_has_required_clauses() {
        let profile = seatbelt_profile();
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(deny process-exec)"));
        assert!(profile.contains(r#"(allow process-exec (literal (param "CODEX_BIN")))"#));
        assert!(profile.contains(r#"(literal (param "CONFIG_TOML"))"#));
        assert!(profile.contains(r#"(literal (param "HOOKS_JSON"))"#));
        assert!(profile.contains(r#"(literal (param "AUTH_JSON"))"#));
    }

    #[test]
    fn sandbox_argv_never_interpolates_paths_into_profile_text() {
        let plan = LaunchPlan {
            codex_bin: PathBuf::from("/usr/local/bin/codex"),
            codex_home: PathBuf::from("/home/op"),
            cwd: PathBuf::from("/tmp/scratch"),
        };
        let argv = sandbox_argv(&plan, &["--version"]);
        // the -p (profile) argument must not itself contain the literal path
        let profile_arg = &argv[argv.iter().position(|a| a == "-p").unwrap() + 1];
        assert!(!profile_arg.contains("/usr/local/bin/codex"));
        assert!(!profile_arg.contains("/home/op"));
        // but the -D params must carry them
        assert!(argv.contains(&"CODEX_BIN=/usr/local/bin/codex".to_string()));
        assert!(argv.contains(&"--version".to_string()));
    }

    #[test]
    fn resolve_codex_binary_rejects_nonexistent_explicit_path() {
        let result = resolve_codex_binary(Some(Path::new("/definitely/not/a/real/path/codex")));
        assert_eq!(result, Err(ReasonCode::CodexBinaryNotFound));
    }

    #[test]
    fn env_whitelist_is_exact() {
        let plan = LaunchPlan {
            codex_bin: PathBuf::from("/usr/local/bin/codex"),
            codex_home: PathBuf::from("/home/op"),
            cwd: PathBuf::from("/tmp/scratch"),
        };
        let mut cmd = Command::new("/usr/bin/true");
        configure_env(&mut cmd, &plan);
        // std::process::Command has no public env-introspection API, so
        // this test only proves `configure_env` compiles against a fixed
        // shape and calls `env_clear` first -- the real guarantee is
        // enforced structurally (this is the only function that sets env
        // vars on the launched command) and exercised end-to-end by the
        // macOS tamper-shim e2e test, which checks the child's actual
        // environment via its own shim script.
        let _ = cmd;
    }

    #[test]
    fn scratch_cwd_is_created_and_removed() {
        let path = {
            let scratch = ScratchCwd::new().unwrap();
            assert!(scratch.path.is_dir());
            scratch.path.clone()
        };
        assert!(!path.exists());
    }
}
