#!/usr/bin/env bash
# Core purity gate (spec section 1, F-05).
# Fails on: bingsu-core without #![forbid(clippy::disallowed_*)] (so no
# allow/expect can switch the rules off), a forbidden call in bingsu-core
# (clippy), a crate in bingsu-core's dependency graph that is not on the
# allowlist (cargo-deny), or a dead, untested, duplicated or silently removed
# rule (canary checker with a pinned path count).
# The CLI's environment rules (crates/bingsu/clippy.toml) are checked the same
# way with their own canary.
set -euo pipefail
cd "$(dirname "$0")/.."
for lint in disallowed_methods disallowed_types disallowed_macros; do
  grep -qE "^#!\[forbid\(clippy::${lint}\)\]$" crates/bingsu-core/src/lib.rs || {
    echo "purity gate FAILED: bingsu-core lacks #![forbid(clippy::${lint})]" >&2
    exit 1
  }
done
# Change these counts together with the clippy.toml lists.
python3 scripts/check_core_purity.py crates/bingsu-core/purity-canary crates/bingsu-core/clippy.toml 112
python3 scripts/check_core_purity.py crates/bingsu/purity-canary crates/bingsu/clippy.toml 7
cargo clippy --quiet -p bingsu-core --all-targets --all-features -- -D warnings \
  -F clippy::disallowed_methods -F clippy::disallowed_types -F clippy::disallowed_macros
cargo deny --manifest-path crates/bingsu-core/Cargo.toml --config crates/bingsu-core/deny.toml check bans
echo "core purity gate: ok"
