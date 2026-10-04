#!/usr/bin/env bash
# Core purity gate (spec section 1, F-05).
# Fails on: a bingsu-core Cargo.toml that does not forbid clippy::disallowed_*
# (so no allow/expect can switch the rules off), conditional compilation in
# bingsu-core (check_core_cfg.py), a forbidden call in bingsu-core (clippy), a
# crate in bingsu-core's dependency graph that is not on the allowlist
# (cargo-deny), or a dead, untested, duplicated or silently removed rule
# (canary checker with a pinned path count).
# The CLI's environment rules (crates/bingsu/clippy.toml) are checked the same
# way with their own canary.
# bingsu-core uses no conditional compilation other than #[cfg(test)], so no
# code can drop out of the lint run through cfg.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 - <<'EOF'
import sys, tomllib
lints = tomllib.load(open("crates/bingsu-core/Cargo.toml", "rb")).get("lints", {}).get("clippy", {})
bad = [l for l in ("disallowed_methods", "disallowed_types", "disallowed_macros") if lints.get(l) != "forbid"]
if bad:
    print(f"purity gate FAILED: bingsu-core Cargo.toml must set [lints.clippy] {', '.join(bad)} = \"forbid\"", file=sys.stderr)
    sys.exit(1)
EOF
python3 scripts/check_core_cfg.py
# Change these counts together with the clippy.toml lists.
python3 scripts/check_core_purity.py crates/bingsu-core/purity-canary crates/bingsu-core/clippy.toml 123
python3 scripts/check_core_purity.py crates/bingsu/purity-canary crates/bingsu/clippy.toml 7
cargo clippy --quiet -p bingsu-core --all-targets --all-features -- -D warnings \
  -F clippy::disallowed_methods -F clippy::disallowed_types -F clippy::disallowed_macros
cargo deny --manifest-path crates/bingsu-core/Cargo.toml --config crates/bingsu-core/deny.toml check bans
echo "core purity gate: ok"
