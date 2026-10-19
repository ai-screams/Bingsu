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
# way with their own canary; the prompt adapter must forbid them, and
# check_cli_prompt_forbid.py holds it to its syscall table and pinned
# files. bingsu-core is no_std (core-cfg-check reads the crate attributes,
# and core builds for wasm32v1-none, which has no std)
# and its graph is pinned (check_core_no_std.py, with its rules tested on
# synthetic metadata). The toolchain must be a stable release.
# bingsu-core uses no conditional compilation other than #[cfg(test)], so no
# code can drop out of the lint run through cfg.
set -euo pipefail
cd "$(dirname "$0")/.."
# Flags from the environment could add --cap-lints and turn the forbid lints
# into warnings, so every cargo and clippy run below (including the canary
# runs in check_core_purity.py) starts without them. CLIPPY_CONF_DIR could
# point clippy at an empty config; the clippy runs below set it explicitly,
# and unsetting it here keeps any other run from inheriting it. A target
# directory from the environment could hold a stale checker binary. A rustc
# wrapper or a replaced rustc could add --cap-lints allow for bingsu-core
# alone, which the canaries (separate crates) would not notice. This unset
# covers the environment; the repository's own ways to add flags (.cargo,
# a toolchain file, cargo-features and profile rustflags in a manifest) are
# refused by the policy phase below. A wrapper or [env] in
# $CARGO_HOME/config.toml belongs to the machine running the gate and is out
# of scope. The checker
# binary is built in the shared target/ and could come from a cache poisoned
# by an earlier run; whoever controlled that run's environment could edit this
# script as well, so that is an accepted residual risk.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CLIPPY_CONF_DIR \
  CARGO_TARGET_DIR CARGO_BUILD_TARGET_DIR \
  RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTC CARGO_BUILD_RUSTC \
  CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER \
  RUSTC_BOOTSTRAP RUSTDOCFLAGS CARGO_ENCODED_RUSTDOCFLAGS CARGO_BUILD_RUSTDOCFLAGS
# Per-target flags (CARGO_TARGET_<TRIPLE>_RUSTFLAGS, …_RUSTDOCFLAGS) reach
# rustc as well: --sysroot or --extern std=<rlib> there would undo the
# wasm32v1-none build below, so every such variable goes too.
while read -r name; do
  unset "$name"
done < <(compgen -e | grep -E '^CARGO_TARGET_[A-Z0-9_]+_RUST(DOC)?FLAGS$' || true)
# Policy first: no cargo call may run before .cargo directories, toolchain
# files, manifest rustflags and stray clippy configs are ruled out.
python3 scripts/check_core_cfg.py --phase policy
# A stable rustc: nightly and beta take cargo-features and -Z flags.
release=$(rustc -vV | sed -n 's/^release: //p')
if ! [[ "$release" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "purity gate FAILED: rustc release '$release' is not a stable release" >&2
  exit 1
fi
# The compiler's own proof that core needs no std: wasm32v1-none ships only
# core and alloc, so any std path (or --extern std) fails to compile there.
# This holds for the flags the repository and CI control (the unset above,
# the policy phase); a rustc or sysroot replaced on the machine is out of
# scope, as above. wasm32-unknown-unknown is not enough: it has a std whose
# I/O returns errors at run time.
cargo build --quiet -p bingsu-core --target wasm32v1-none
# Exercise rustdoc under the same sanitized environment as rustc. The child
# environment regression test observes this invocation, not just unset text.
cargo doc --quiet -p bingsu-core --no-deps
python3 - <<'EOF'
import sys, tomllib
core = tomllib.load(open("crates/bingsu-core/Cargo.toml", "rb")).get("lints", {})
lints = core.get("clippy", {})
bad = [l for l in ("disallowed_methods", "disallowed_types", "disallowed_macros", "fn_to_numeric_cast_any") if lints.get(l) != "forbid"]
if bad:
    print(f"purity gate FAILED: bingsu-core Cargo.toml must set [lints.clippy] {', '.join(bad)} = \"forbid\"", file=sys.stderr)
    sys.exit(1)
if core.get("rust", {}).get("unsafe_code") != "forbid":
    print("purity gate FAILED: bingsu-core Cargo.toml must set [lints.rust] unsafe_code = \"forbid\"", file=sys.stderr)
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
python3 scripts/check_core_purity.py crates/bingsu-core/purity-canary crates/bingsu-core/clippy.toml 190
python3 scripts/check_core_purity.py crates/bingsu/purity-canary crates/bingsu/clippy.toml 7
# The graph rules on synthetic metadata (the real graph is clean), then the graph.
python3 -B scripts/test_check_core_no_std.py
python3 scripts/check_core_no_std.py
# The prompt adapter: forbid attribute, adapter paths and syscall table, one
# fn main that only dispatches, no code outside main.
python3 scripts/check_cli_prompt_forbid.py --checker "$checker"
python3 -B scripts/test_prompt_bootstrap.py
python3 -B scripts/test_check_core_cfg.py
python3 -B scripts/test_check_core_purity_env.py
# clippy on core, in a fresh temporary target directory with its config
# pinned; diagnostics are counted, not only the exit code.
python3 scripts/check_core_clippy_clean.py
cargo deny --manifest-path crates/bingsu-core/Cargo.toml --config crates/bingsu-core/deny.toml check bans sources
echo "core purity gate: ok"
