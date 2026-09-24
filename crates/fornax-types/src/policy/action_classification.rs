//! Real tool-call data -> [`ActionClass`] (FORNX-121, epic FORNX-69).
//!
//! FORNX-116 defined the `ActionClass` vocabulary an [`super::EnforcementRule`]
//! is keyed on, but nothing in the workspace ever produced one from a real
//! adapter event. This module is that mapping, and it is the *only* place
//! this knowledge lives — a caller (today: nothing wired yet; eventually
//! `fornax-daemon`, once it gates on `Verdict`, see FORNX-121's PR notes for
//! why that wiring is out of this ticket's scope) must classify through
//! [`classify_action_class`], never re-derive its own tool-name mapping.
//!
//! Pure and total: every `(provider, tool_name, tool_input)` triple produces
//! exactly one `ActionClass`. An unmapped tool name produces
//! [`ActionClass::Unrecognized`] rather than a guess — an unrecognized
//! `action_class` has no enforcement rule to match
//! ([`super::ResolvedValues::enforcement_outcome_for`]), so it falls back to
//! `ObserveOnly` via the same "no rule published for this class" path as any
//! other unmatched class, never a silently invented risk assumption.
//!
//! Grounded in the real tool-name shapes captured in
//! `docs/research/adapter-capability-matrix.md` and produced by
//! `fornax-adapter-claude`/`fornax-adapter-codex`/`fornax-adapter-opencode`
//! (see those crates' `AgentAdapter::normalize` implementations): Claude
//! Code hook events carry `tool_name` values like `"Bash"`/`"Edit"`/
//! `"Write"`; Codex's rollout tailer normalizes every shell invocation to
//! the canonical `tool_name` `"exec_command"` regardless of the
//! provider-native `custom_tool_call`/`exec_command_end` shape it came from;
//! OpenCode's `tool.execute.before`/`tool.execute.after` hooks currently
//! only ever normalize a shell invocation as `"bash"` — every other
//! OpenCode tool name is genuinely unmapped today (no other tool_name value
//! has been observed live), not silently guessed at.

use super::content::ActionClass;
use crate::Provider;

/// Classify one already-normalized tool call into the policy's action
/// vocabulary.
///
/// `tool_input` is consulted only for shell-shaped tools (Claude's `Bash`,
/// Codex's `exec_command`) — see [`classify_shell_command`] for the command-
/// text heuristics. Every other tool name is classified from `tool_name`
/// alone.
pub fn classify_action_class(
    provider: Provider,
    tool_name: &str,
    tool_input: Option<&serde_json::Value>,
) -> ActionClass {
    match (provider, tool_name) {
        (_, "Bash") | (Provider::Codex, "exec_command") | (Provider::OpenCode, "bash") => {
            classify_shell_command(command_text(tool_input).as_deref())
        }
        (Provider::ClaudeCode, "Edit" | "Write" | "MultiEdit" | "NotebookEdit") => {
            ActionClass::CodeEdit
        }
        (Provider::ClaudeCode, "WebFetch" | "WebSearch") => ActionClass::NetworkFetch,
        // fornax-adapter-opencode currently only ever normalizes "bash" as
        // a tool_name (see docs/research/adapter-capability-matrix.md and
        // that crate's `tool.execute.before`/`after` handling) -- every
        // other OpenCode tool name is genuinely unmapped pending its own
        // ticket, not silently guessed at here.
        _ => ActionClass::Unrecognized(tool_name.to_string()),
    }
}

/// Both adapters place a shell command's text under `tool_input.command`
/// (Claude's native `Bash` shape and Codex's normalized `exec_command`
/// `AgentEvent.tool_input` alike — see `fornax-adapter-codex`'s
/// `custom_tool_call`/`exec_command_end` handling, which both construct
/// `tool_input: Some(json!({"command": ...}))`).
fn command_text(tool_input: Option<&serde_json::Value>) -> Option<String> {
    tool_input?
        .get("command")
        .and_then(|v| v.as_str())
        .map(str::to_string)
}

/// Best-effort command-text classification for a shell invocation. This is
/// deliberately a small, documented set of substring heuristics, not an
/// attempt at a full shell-command parser — a command this function doesn't
/// recognize falls back to the plain `ShellCommand` class rather than a
/// wrong guess, and every heuristic here only ever *tightens* the
/// classification away from that floor, never loosens it.
///
/// Order matters: the highest-risk classes are checked first so a command
/// matching more than one heuristic (e.g. `curl ... | bash` piping a
/// download into a shell) classifies at its most sensitive applicable tier.
fn classify_shell_command(command: Option<&str>) -> ActionClass {
    let Some(command) = command else {
        return ActionClass::ShellCommand;
    };
    let normalized = command.to_ascii_lowercase();

    // Every check below is a whole-string `contains`, deliberately —
    // `tool_input.command` is a full shell line that may carry a `cd repo
    // &&`/`sudo`/pipeline prefix before the command this heuristic actually
    // cares about (e.g. `cd /repo && git push origin main`). A first-token
    // check would miss exactly that shape and silently *loosen* the
    // classification, which this function's doc comment promises never
    // happens.
    if contains_any(&normalized, CREDENTIAL_PATH_MARKERS) {
        return ActionClass::CredentialAccess;
    }
    if contains_any(&normalized, INFRA_MUTATION_PHRASES) {
        return ActionClass::InfrastructureMutation;
    }
    if contains_any(&normalized, VCS_WRITE_PHRASES) {
        return ActionClass::VersionControlWrite;
    }
    if contains_any(&normalized, PACKAGE_INSTALL_PHRASES) {
        return ActionClass::PackageInstall;
    }
    if contains_any(&normalized, NETWORK_FETCH_PHRASES) {
        return ActionClass::NetworkFetch;
    }
    ActionClass::ShellCommand
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Well-known paths/filenames a shell command reading them is almost always
/// deliberate credential access, independent of which command does the
/// reading (`cat`, `cp`, `scp`, ...).
const CREDENTIAL_PATH_MARKERS: &[&str] = &[
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".aws/credentials",
    ".netrc",
    "credentials.json",
    "/etc/shadow",
];

/// Tool+verb phrases that mutate live infrastructure state. Not exhaustive
/// (this is a heuristic floor-tightener, not a parser for every provider's
/// CLI) — a mutating invocation this list misses still classifies as
/// `ShellCommand`, never silently as something safer than that.
const INFRA_MUTATION_PHRASES: &[&str] = &[
    "terraform apply",
    "terraform destroy",
    "kubectl apply",
    "kubectl delete",
    "kubectl create",
    "kubectl scale",
    "helm install",
    "helm upgrade",
    "helm uninstall",
    "docker rm",
    "docker rmi",
    "docker system prune",
];

/// `git` subcommand phrases that mutate committed history or push to a
/// remote, as opposed to read-only inspection (`git status`, `git log`,
/// `git diff`). Anchored on `"git "` + the subcommand (not a bare verb like
/// `"tag"`) so `git log --tags` doesn't false-positive as a write.
const VCS_WRITE_PHRASES: &[&str] = &[
    "git push",
    "git commit",
    "git tag",
    "git merge",
    "git rebase",
    "git cherry-pick",
    "git reset --hard",
    "git clean -f",
    "git branch -d",
];

/// Package-manager install/add invocations across the ecosystems this
/// codebase's own tooling touches (npm/yarn/pnpm, pip/pip3, cargo, apt,
/// brew, gem, go).
const PACKAGE_INSTALL_PHRASES: &[&str] = &[
    "npm install",
    "npm i ",
    "yarn add",
    "pnpm add",
    "pip install",
    "pip3 install",
    "cargo install",
    "cargo add",
    "apt install",
    "apt-get install",
    "brew install",
    "gem install",
    "go install",
];

/// Network-fetch commands. `"curl "`/`"wget "` (trailing space, not a bare
/// first-token check) so a `cd repo && curl ...` prefix or pipeline still
/// matches.
const NETWORK_FETCH_PHRASES: &[&str] = &["curl ", "wget "];

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn bash_input(command: &str) -> serde_json::Value {
        json!({ "command": command })
    }

    // --- Claude Code tool_name mapping ------------------------------------

    #[test]
    fn claude_edit_write_multiedit_notebookedit_are_code_edit() {
        for tool in ["Edit", "Write", "MultiEdit", "NotebookEdit"] {
            assert_eq!(
                classify_action_class(Provider::ClaudeCode, tool, None),
                ActionClass::CodeEdit,
                "tool={tool}"
            );
        }
    }

    #[test]
    fn claude_webfetch_and_websearch_are_network_fetch() {
        for tool in ["WebFetch", "WebSearch"] {
            assert_eq!(
                classify_action_class(Provider::ClaudeCode, tool, None),
                ActionClass::NetworkFetch,
                "tool={tool}"
            );
        }
    }

    #[test]
    fn claude_read_only_tools_are_unrecognized_not_guessed() {
        for tool in ["Read", "Glob", "Grep", "Task", "TodoWrite"] {
            assert_eq!(
                classify_action_class(Provider::ClaudeCode, tool, None),
                ActionClass::Unrecognized(tool.to_string()),
                "tool={tool}"
            );
        }
    }

    // --- Shell command classification, both providers ---------------------

    #[test]
    fn plain_shell_command_with_no_heuristic_match_is_shell_command() {
        let input = bash_input("cargo test --workspace");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::ShellCommand
        );
        assert_eq!(
            classify_action_class(Provider::Codex, "exec_command", Some(&input)),
            ActionClass::ShellCommand
        );
    }

    #[test]
    fn bash_with_no_tool_input_defaults_to_shell_command_not_unrecognized() {
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", None),
            ActionClass::ShellCommand
        );
    }

    #[test]
    fn git_push_is_version_control_write() {
        let input = bash_input("git push origin main");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::VersionControlWrite
        );
    }

    #[test]
    fn git_status_is_plain_shell_command_not_version_control_write() {
        let input = bash_input("git status --porcelain");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::ShellCommand
        );
    }

    #[test]
    fn git_log_with_tags_flag_is_not_version_control_write() {
        // Regression: a bare "tag" substring check would false-positive on
        // this read-only inspection command.
        let input = bash_input("git log --tags");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::ShellCommand
        );
    }

    #[test]
    fn cd_prefixed_git_push_is_still_version_control_write() {
        // Regression: real agent-issued commands are routinely prefixed
        // with `cd <repo> &&` -- a first-token check on "git" would miss
        // this shape entirely.
        let input = bash_input("cd /repo && git push origin main");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::VersionControlWrite
        );
    }

    #[test]
    fn npm_install_is_package_install() {
        let input = bash_input("npm install left-pad --save");
        assert_eq!(
            classify_action_class(Provider::Codex, "exec_command", Some(&input)),
            ActionClass::PackageInstall
        );
    }

    #[test]
    fn curl_is_network_fetch() {
        let input = bash_input("curl -sSL https://example.com/install.sh");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::NetworkFetch
        );
    }

    #[test]
    fn reading_ssh_private_key_is_credential_access() {
        let input = bash_input("cat ~/.ssh/id_rsa");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::CredentialAccess
        );
    }

    #[test]
    fn terraform_apply_is_infrastructure_mutation() {
        let input = bash_input("terraform apply -auto-approve");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::InfrastructureMutation
        );
    }

    #[test]
    fn kubectl_get_is_plain_shell_command_not_infrastructure_mutation() {
        let input = bash_input("kubectl get pods");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::ShellCommand
        );
    }

    #[test]
    fn credential_access_outranks_infra_mutation_when_both_could_match() {
        // A command that would otherwise match an infra-mutation phrase but
        // also touches a credential path classifies at the higher tier
        // (CredentialAccess is checked first) -- documents the precedence,
        // not a claim this exact command is realistic.
        let input = bash_input("cat ~/.aws/credentials && kubectl apply -f x.yaml");
        assert_eq!(
            classify_action_class(Provider::ClaudeCode, "Bash", Some(&input)),
            ActionClass::CredentialAccess
        );
    }

    #[test]
    fn codex_exec_command_uses_the_same_command_heuristics_as_claude_bash() {
        let input = bash_input("git commit -am 'wip'");
        assert_eq!(
            classify_action_class(Provider::Codex, "exec_command", Some(&input)),
            ActionClass::VersionControlWrite
        );
    }

    #[test]
    fn opencode_bash_uses_the_same_command_heuristics_as_claude_bash() {
        let input = bash_input("npm install left-pad");
        assert_eq!(
            classify_action_class(Provider::OpenCode, "bash", Some(&input)),
            ActionClass::PackageInstall
        );
    }

    #[test]
    fn opencode_unmapped_tool_is_unrecognized_pending_its_own_ticket() {
        assert_eq!(
            classify_action_class(Provider::OpenCode, "edit", None),
            ActionClass::Unrecognized("edit".to_string())
        );
    }

    #[test]
    fn unknown_provider_tool_pair_is_unrecognized_carrying_the_tool_name() {
        assert_eq!(
            classify_action_class(Provider::OpenCode, "some_future_tool", None),
            ActionClass::Unrecognized("some_future_tool".to_string())
        );
    }
}
