#!/bin/sh
# Misbehaving-peer shim, used two ways:
#
# 1. tests/session_streams.rs spawns this directly with argv[1] as the
#    mode ("positive", "hang", "malformed", ...) -- a raw pipes test, no
#    sandbox, no launch.rs involved.
#
# 2. tests/verify_codex_e2e.rs points `--codex-bin` at a per-test COPY of
#    this script and runs it through the real launch.rs/sandbox-exec path.
#    In that shape argv is whatever launch.rs itself passes (`--version`,
#    or `--disable plugins app-server --listen stdio://`), so there is no
#    room for a mode argument -- the mode instead comes from a `mode` file
#    sitting next to this script (same directory, via `${0%/*}`), because
#    launch.rs's env-clearing means no env var can carry it through. A
#    `version` file next to the script overrides the reported
#    `codex-cli <version>` string (used for the unreviewed-version case).
#
# POSIX sh, builtins only (read/printf/case) -- must run under exec-deny.
set -u
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mode_file="$script_dir/mode"
version_file="$script_dir/version"
log_file="./tamper.log"

mode="positive"
[ -f "$mode_file" ] && mode="$(cat "$mode_file")"
version="0.160.0"
[ -f "$version_file" ] && version="$(cat "$version_file")"

case "${1:-}" in
    --version)
        printf 'codex-cli %s\n' "$version"
        exit 0
        ;;
esac

# Only reached for a bare argv[1] mode (session_streams.rs) or an
# app-server-shaped invocation (anything else, including no args).
case "${1:-}" in
    exit_immediately) exit 0 ;;
    hang) while true; do sleep 3600; done ;;
    positive|malformed|truncated|oversized|rpc_error|interleaved)
        mode="$1"
        ;;
esac

if [ "$mode" = "tamper" ]; then
    printf 'x' >>"$HOME/.codex/config.toml" 2>>"$log_file" && echo "wrote config.toml" >>"$log_file" || echo "denied config.toml write" >>"$log_file"
    printf 'x' >>"$HOME/.codex/hooks.json" 2>>"$log_file" && echo "wrote hooks.json" >>"$log_file" || echo "denied hooks.json write" >>"$log_file"
    /usr/bin/true >>"$log_file" 2>>"$log_file" && echo "ran /usr/bin/true" >>"$log_file" || echo "denied /usr/bin/true exec" >>"$log_file"
fi

while IFS= read -r line; do
    case "$mode" in
        malformed)
            printf 'not json at all\n'
            exit 0
            ;;
        truncated)
            printf '{"jsonrpc":"2.0","id":0,"resu'
            exit 0
            ;;
        oversized)
            printf '{"jsonrpc":"2.0","id":0,"result":{"pad":"'
            yes a | tr -d '\n' | head -c 2000000
            printf '"}}\n'
            exit 0
            ;;
        rpc_error)
            printf '{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"no such method"}}\n'
            exit 0
            ;;
        interleaved)
            printf '{"method":"remoteControl/status/changed"}\n'
            printf '{"jsonrpc":"2.0","id":0,"result":{"codexHome":"/isolated","userAgent":"codex-cli/0.160.0 (test-shim)"}}\n'
            ;;
        *)
            case "$line" in
                *'"method":"initialize"'*)
                    printf '{"jsonrpc":"2.0","id":0,"result":{"codexHome":"%s/.codex","userAgent":"codex-cli/%s (test-shim)"}}\n' "$HOME" "$version"
                    ;;
                *'"method":"hooks/list"'*)
                    # Always reports zero hooks -- against a real
                    # hooks.json with Fornax entries installed, this is
                    # exactly the orphaned-entry case (every expected hook
                    # absent from the listing). No real Codex app-server
                    # behavior is being emulated here, only the RPC shape.
                    printf '{"jsonrpc":"2.0","id":1,"result":{"data":[{"cwd":"/isolated","hooks":[],"errors":[],"warnings":[]}]}}\n'
                    ;;
            esac
            ;;
    esac
done
