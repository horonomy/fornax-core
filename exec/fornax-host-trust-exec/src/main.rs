//! CLI entry point. The `verify-codex` subcommand lands in a later
//! FORNX-450 commit, once `identity`/`verdict`/`launch` exist; until then
//! this binary exists only so the crate links and its protocol-layer tests
//! run in CI.

fn main() {
    eprintln!("fornax-host-trust-exec: verify-codex not yet wired (FORNX-450 in progress)");
    std::process::exit(2);
}
