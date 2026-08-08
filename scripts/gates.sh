#!/usr/bin/env sh
# Quality and supply-chain gates. Run inside the Rust container.
#
#   docker run --rm -v <backend>:/work -v <repo>:/repo -w /work rust:1-bookworm sh /repo/scripts/gates.sh
#
# Every gate reports its own exit status and the script continues, so one run
# produces the full picture instead of stopping at the first failure. The final
# exit status is non-zero if any gate failed.
set -u

# `rust:1-bookworm` ships the toolchain without rustfmt or clippy. Adding them
# here rather than assuming they exist is what stops the lint gate from silently
# reporting a failure that is really a missing tool.
printf '=== ensuring rustfmt and clippy are present ===\n'
rustup component add rustfmt clippy >/dev/null 2>&1 || true

overall=0
gate() {
    name="$1"; shift
    printf '\n=== %s ===\n' "$name"
    if "$@"; then
        printf '[PASS] %s\n' "$name"
    else
        printf '[FAIL] %s (exit %d)\n' "$name" "$?"
        overall=1
    fi
}

gate "cargo fmt --check" cargo fmt --all -- --check
gate "cargo clippy -D warnings" cargo clippy --all-targets --all-features -- -D warnings

printf '\n=== installing supply-chain tools (first run only) ===\n'
command -v cargo-audit >/dev/null 2>&1 || cargo install cargo-audit --locked --quiet
command -v cargo-deny  >/dev/null 2>&1 || cargo install cargo-deny  --locked --quiet

gate "cargo audit" cargo audit
gate "cargo deny check" cargo deny --manifest-path /work/Cargo.toml --config /repo/deny.toml check

printf '\n=== overall: %s ===\n' "$([ $overall -eq 0 ] && echo PASS || echo FAIL)"
exit $overall
