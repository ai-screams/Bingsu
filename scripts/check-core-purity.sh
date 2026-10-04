#!/usr/bin/env bash
# Core purity gate (spec section 1, F-05).
# Fails on: a bingsu-core Cargo.toml that does not forbid clippy::disallowed_*
# (so no allow/expect can switch the rules off) or whose lint copy drifts from
# [workspace.lints], conditional compilation, #[path], include, macro_rules, a
# shebang, a `.rs` extension in another case, a symlink or an explicit target
# table in bingsu-core, a .cargo directory or a
# stray clippy config in the repository (check_core_cfg.py with the token
# checker in tools/core-cfg-check), a forbidden call in bingsu-core (clippy
# diagnostics counted, not its exit code), a crate in bingsu-core's dependency
# graph that is not on the allowlist
# (cargo-deny), or a dead, untested, duplicated or silently removed rule
# (canary checker with a pinned path count).
# The CLI's environment rules (crates/bingsu/clippy.toml) are checked the same
# way with their own canary.
# bingsu-core uses no conditional compilation other than #[cfg(test)], so no
# code can drop out of the lint run through cfg.
set -euo pipefail
cd "$(dirname "$0")/.."
# Flags from the environment could add --cap-lints and turn the forbid lints
# into warnings, so every cargo and clippy run below (including the canary
# runs in check_core_purity.py) starts without them. CLIPPY_CONF_DIR could
# point clippy at an empty config; the clippy runs below set it explicitly,
# and unsetting it here keeps any other run from inheriting it. A target
# directory from the environment could hold a stale checker binary.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CLIPPY_CONF_DIR \
  CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR
# Policy first: no cargo call may run before .cargo directories and stray
# clippy configs are ruled out.
python3 scripts/check_core_cfg.py --phase policy
python3 - <<'EOF'
import sys, tomllib
core = tomllib.load(open("crates/bingsu-core/Cargo.toml", "rb")).get("lints", {})
lints = core.get("clippy", {})
bad = [l for l in ("disallowed_methods", "disallowed_types", "disallowed_macros") if lints.get(l) != "forbid"]
if bad:
    print(f"purity gate FAILED: bingsu-core Cargo.toml must set [lints.clippy] {', '.join(bad)} = \"forbid\"", file=sys.stderr)
    sys.exit(1)
# bingsu-core cannot inherit [workspace.lints] (it sets the purity lints to
# forbid in its own table), so it carries a copy; the copy must not drift.
workspace = tomllib.load(open("Cargo.toml", "rb")).get("workspace", {}).get("lints", {})
drift = [f"{tool}.{name}" for tool in ("rust", "clippy")
         for name, value in workspace.get(tool, {}).items()
         if core.get(tool, {}).get(name) != value]
if drift:
    print(f"purity gate FAILED: core lints drift from workspace: {', '.join(drift)}", file=sys.stderr)
    sys.exit(1)
EOF
# Take the checker's path from cargo's own report instead of assuming a
# target directory.
checker=$(cargo build --quiet -p core-cfg-check --message-format=json | python3 -c '
import json, sys
paths = [d["executable"] for d in map(json.loads, sys.stdin)
         if d.get("reason") == "compiler-artifact" and d["target"]["name"] == "core-cfg-check" and d.get("executable")]
if len(paths) != 1:
    sys.exit(f"purity gate FAILED: expected one core-cfg-check executable, got {paths}")
print(paths[0])
')
python3 scripts/check_core_cfg.py --phase tokens --checker "$checker"
# Change these counts together with the clippy.toml lists.
python3 scripts/check_core_purity.py crates/bingsu-core/purity-canary crates/bingsu-core/clippy.toml 123
python3 scripts/check_core_purity.py crates/bingsu/purity-canary crates/bingsu/clippy.toml 7
# Count diagnostics instead of trusting the exit code: under --cap-lints warn
# clippy exits 0 but still reports them.
CLIPPY_CONF_DIR="$PWD/crates/bingsu-core" cargo clippy --quiet --message-format=json -p bingsu-core --all-targets --all-features -- -D warnings \
  -F clippy::disallowed_methods -F clippy::disallowed_types -F clippy::disallowed_macros \
  | python3 scripts/check_core_clippy_clean.py
cargo deny --manifest-path crates/bingsu-core/Cargo.toml --config crates/bingsu-core/deny.toml check bans
echo "core purity gate: ok"
