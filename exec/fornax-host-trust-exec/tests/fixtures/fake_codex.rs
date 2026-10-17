//! Test-only stand-in for the real `codex` binary, used by
//! `tests/verify_codex_e2e.rs` as `--codex-bin`.
//!
//! Must be a real compiled binary, not a shell script: macOS's Seatbelt
//! `(allow process-exec (literal ...))` rule in `src/launch.rs` was
//! empirically found NOT to match a `#!/bin/sh` shebang script executed
//! through `sandbox-exec` -- even when the literal path matches exactly
//! -- while it matches a real (even relocated/copied) Mach-O binary at
//! its real path without issue. `tests/fixtures/fake-codex.sh` still
//! exists for `tests/session_streams.rs`, which never goes through the
//! sandbox at all; this binary is the sandbox-compatible equivalent for
//! the layer that does.
//!
//! Mode selection mirrors the shell shim: a `mode` file and an optional
//! `version` file sitting next to this binary's own path (found via
//! `std::env::current_exe()`), because `launch.rs`'s env-clearing means
//! no env var can carry a mode through the sandboxed child.

use std::io::{BufRead, Write};

fn sibling_file(name: &str) -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.join(name);
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--version") {
        let version = sibling_file("version").unwrap_or_else(|| "0.160.0".to_string());
        println!("codex-cli {version}");
        return;
    }

    let mode = sibling_file("mode").unwrap_or_else(|| "positive".to_string());

    if mode == "tamper" {
        let home = std::env::var("HOME").unwrap_or_default();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("tamper.log");
        let mut log = log.ok();
        let mut note = |msg: &str| {
            if let Some(f) = log.as_mut() {
                let _ = writeln!(f, "{msg}");
            }
        };
        match std::fs::OpenOptions::new()
            .append(true)
            .open(format!("{home}/.codex/config.toml"))
            .and_then(|mut f| f.write_all(b"x"))
        {
            Ok(_) => note("wrote config.toml"),
            Err(_) => note("denied config.toml write"),
        }
        match std::fs::OpenOptions::new()
            .append(true)
            .open(format!("{home}/.codex/hooks.json"))
            .and_then(|mut f| f.write_all(b"x"))
        {
            Ok(_) => note("wrote hooks.json"),
            Err(_) => note("denied hooks.json write"),
        }
        match std::process::Command::new("/usr/bin/true").status() {
            Ok(s) if s.success() => note("ran /usr/bin/true"),
            _ => note("denied /usr/bin/true exec"),
        }
    }

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let home = std::env::var("HOME").unwrap_or_default();
    let version = sibling_file("version").unwrap_or_else(|| "0.160.0".to_string());

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        match mode.as_str() {
            "malformed" => {
                println!("not json at all");
                return;
            }
            "truncated" => {
                print!("{{\"jsonrpc\":\"2.0\",\"id\":0,\"resu");
                let _ = stdout.lock().flush();
                return;
            }
            "oversized" => {
                print!("{{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{{\"pad\":\"");
                print!("{}", "a".repeat(2_000_000));
                println!("\"}}}}");
                return;
            }
            "rpc_error" => {
                println!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{{\"code\":-32601,\"message\":\"no such method\"}}}}"
                );
                return;
            }
            "interleaved" => {
                println!(r#"{{"method":"remoteControl/status/changed"}}"#);
                println!(
                    r#"{{"jsonrpc":"2.0","id":0,"result":{{"codexHome":"/isolated","userAgent":"codex-cli/{version} (test-shim)"}}}}"#
                );
            }
            _ => {
                if line.contains("\"method\":\"initialize\"") {
                    println!(
                        r#"{{"jsonrpc":"2.0","id":0,"result":{{"codexHome":"{home}/.codex","userAgent":"codex-cli/{version} (test-shim)"}}}}"#
                    );
                } else if line.contains("\"method\":\"hooks/list\"") {
                    // Always reports zero hooks -- against a real
                    // installed hooks.json this is the orphaned-entry
                    // case for every expected hook. Not a real Codex
                    // trust-state emulation, only the RPC shape.
                    println!(
                        r#"{{"jsonrpc":"2.0","id":1,"result":{{"data":[{{"cwd":"/isolated","hooks":[],"errors":[],"warnings":[]}}]}}}}"#
                    );
                }
            }
        }
        let _ = stdout.lock().flush();
    }
}
