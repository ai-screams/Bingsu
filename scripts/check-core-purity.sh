#!/usr/bin/env bash
# Core purity gate (spec section 1, F-05).
# Fails on: a forbidden call in bingsu-core (clippy), an I/O crate in
# bingsu-core's dependency graph (cargo-deny), or a dead or untested rule
# (canary checker).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/check_core_purity.py crates/bingsu-core/purity-canary crates/bingsu-core/clippy.toml
cargo clippy --quiet -p bingsu-core --all-targets -- -D warnings
cargo deny --manifest-path crates/bingsu-core/Cargo.toml --config crates/bingsu-core/deny.toml check bans
echo "core purity gate: ok"
