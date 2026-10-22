# CLAUDE.md

This file guides Claude Code (claude.ai/code) when working in this repository.

## Project overview

**bingsu** is a cross-shell terminal theme and prompt engine for bash, zsh and fish.
One set of OKLCH color tokens drives the prompt, the terminal color scheme and CLI tool configs.
The engine is the "ice"; themes, segments and plugins are "toppings" layered on top.

- **Language**: Rust workspace: product crates `bingsu-core` and `bingsu`; the rest are test, bench and tool crates. Windows is checked in CI; macOS and Linux are first-class.
- **License**: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
- **Stage**: M3a (config, snapshot, refresh helper) and M3b (collector process protocol, supervision, publication) are done;
  M3c (git, path facts, safe reads) is next. `bingsu prompt` renders the built-in default theme or the user's TOML config
  through a snapshot the refresh helper publishes; the helper can run the pinned `bingsu-collect` worker under its sandbox,
  but no product segment collects data yet, so there is no git segment; command segments are checked but not run (M6);
  there is no release. `README.md` lists features as planned until they ship and records working behavior in its Status table.
- **Repository**: `ai-screams/Bingsu`, public.

## Layout

| Path | What |
| -- | -- |
| `crates/bingsu-core` | I/O-free core (no files, processes, clocks, environment, network or threads; the purity gate enforces it): `front` makes prompt decisions, `envelope` parses shell input, `shell_values` fills segments; `config` (merge, check, compile, edit, schema), `template`, `layout`/`render`/`bands`, `snapshot`/`snapshot_codec` (helper to prompt hand-off), `diag*`; status grammar, B1 record encoder, shell words, sanitize, width, icons, color, built-in default theme |
| `crates/bingsu` | CLI: `src/prompt.rs` renders a record from the envelope and the published snapshot (`prompt_read.rs` reads it, `prompt_spawn.rs` starts the refresh helper before the filter, `prompt_io.rs` writes under the deadline; these and `sandbox.rs` are hash-pinned); `src/commands/` holds `init` (pins the binary path and four roots), `config`/`reload`/`refresh`/`helper` (load, trust, publish), `collector_process`/`collector_supervisor` (spawn, pidfd supervision, deadlines), `collection_store`/`collection_gc` (per-folder responses, reclaim), messages and libc wrappers; `src/sandbox.rs` installs the Linux seccomp filter, with allowed calls in `prompt-syscalls.tsv`; shell scripts are embedded from `src/shell/{zsh,bash,fish}` |
| `crates/bingsu-core-tests` | Property and byte-golden tests of core, kept out of core's dependency graph |
| `crates/bingsu-core-bench` | Callgrind instruction-count benches (gungraun) for CI job `icount` |
| `crates/bingsu-golden` | Prints render output for fixed inputs; native (its test) and wasm32-wasip1 (CI) must equal `tests/golden/render/render.tsv` byte for byte; regenerate with `cargo run -q -p bingsu-golden --release > tests/golden/render/render.tsv` and review the diff |
| `crates/bingsu-collect` | Collector worker binary pinned by `init`: startup limits, then on Linux Landlock and seccomp (`collector-syscalls.tsv`), then one request/response exchange with the helper; the product and bench dependency graphs are pinned in `dependencies.allowlist.tsv` (`scripts/check_collector_dependencies.py`) |
| `crates/bingsu-bench` | M1 measurement code |
| `tests/golden/record` | Reader golden vectors run in each shell (`run.py`, `run-all.sh`) |
| `tests/shell` | PTY tests (`pty_session.py`), minimum-shell containers, X-01 probes; `test_collector_security.py` maps the collector security rows (`tests/collector-acceptance.tsv`) to tests |
| `tests/hostile` | Hostile-value matrix shared by core, golden and PTY tests |
| `scripts/`, `tools/core-cfg-check` | Purity, prompt-forbid and diagnostic-code gates; `scripts/pin_tcb.py` re-pins TCB hashes |
| `tools/fsbudget`, `tools/gen-ucd-tables` | strace filesystem budget check; generator for `src/ucd.rs` |

## Collaboration rules (MUST FOLLOW)

- **Every change goes through a pull request.** Never commit to `main` directly.
  A ruleset on `main` requires a pull request, squash merges and the CI checks, and blocks force-pushes and deletion.
  A local `pre-push` hook also refuses pushes to `main`.
- **Ask before anything outward-facing.** Pushing a branch, creating a pull request and merging each need an explicit go-ahead
  for that specific item. "Fix this" or "finish it" does not authorize a push, a PR or a merge.
- **Squash merge only.** The PR title becomes the commit on `main`, so it must follow Conventional Commits.
- Assign PRs and issues to the user (`gh pr create --assignee @me`). Do not add reviewers unless asked.
- Titles of PRs, issues and commits are in English: `type(scope): summary`, imperative, no trailing period.
- No session links, attribution trailers or internal tool names in commits, PR bodies or committed docs.
  Write what changed and why, not who or what pointed it out.

## Branches and commits

- Branch: `<type>/<issue>-<summary>` or `<type>/<summary>`, kebab-case. `type` matches the main commit type.
- Types: `feat` `fix` `perf` `refactor` `docs` `test` `build` `ci` `chore` `revert`; `chore(deps)` for dependency updates.
- One topic per PR. Do not mix setup, docs and features.

## Commands

```bash
cargo build
cargo test --workspace --all-features            # schema test: BINGSU_SCHEMA_PY=<venv python with scripts/schema-requirements.txt>
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
scripts/check-core-purity.sh                       # core purity + CLI prompt-path forbid gate
cargo check -p bingsu --target x86_64-unknown-linux-musl   # CI builds musl; libc APIs differ (getentropy is not there)
tests/golden/record/run-all.sh                     # record golden vectors; SHELLS="bash zsh fish", BINGSU_PY=<python>
BINGSU_TEST_SHELLS="zsh fish bash" python -m pytest tests/shell tests/golden/record/test_overrides.py tests/golden/record/test_mixed_versions.py -q -rf -p no:cacheprovider
```

Shell tests (`tests/shell`):
- The minimum-shell images have no cargo or cc: a pytest under `tests/shell` must not build. Generate fixtures on the host before docker (see `BINGSU_SHAPE_ONLY_FIXTURE` in `shell.yml`); tests needing a glibc test binary run in the `filter-calls` gnu debug job.
- `tests/hostile/classes.tsv` is the one source for core, golden and PTY hostile-value tests; add a row, not a per-shell case.
- NUL outcomes per shell, version and locale live in `tests/golden/record/nul_expected.tsv` (first match wins; `*` rows generalise beyond what was observed).
- Minimum shells (bash 5.1, zsh 5.8, fish 3.6) run in `tests/shell/containers/*.Dockerfile`; in a container run tests as root with a root-owned copy of the binary and `--basetemp` outside `/tmp`, because init warns about a folder above the binary that another user can change.
- `BINGSU_RECORD_OBSERVATIONS=1` prints `OBSERVE` lines only for unpinned cells; pinned cells still assert.
- The strace test (Linux) allows only loader/library paths, `/proc/self/maps`, the binary and the four pinned roots; a new distro path needs a reason before it joins the list.

Changelog (git-cliff, config in `cliff.toml`):

```bash
git cliff --unreleased --prepend CHANGELOG.md
git cliff --tag vX.Y.Z -o CHANGELOG.md
```

## CI

| Workflow | Jobs | Notes |
| -- | -- | -- |
| `ci.yml` | Detect project, Lint workflows (actionlint), Lint (rustfmt, clippy, musl check), Test on ubuntu, macos, windows, Core purity gate, Core wasm32 build (also runs the render golden under wasmtime as wasm32-wasip1), Unicode tables (`ucd`), Core instruction counts (`icount`, PRs only), Filesystem budget (strace) | Rust jobs run only when `Cargo.toml` exists (detect job) |
| `shell.yml` | Golden vectors and PTY tests in the min-u22, min-d12 and cur-d13 containers and on macOS Homebrew; Prompt filter calls (Linux x86_64, GNU and musl, debug and release) | `workflow_dispatch` input `record_observations` prints unpinned cells |
| `security.yml` | Secret scan (gitleaks), Dependency advisories (cargo-audit) | gitleaks scans full history; weekly cron; cargo-audit needs `Cargo.lock` |
| `dependabot.yml` | github-actions and cargo, weekly | |

- Pin every action to a full commit SHA with a version comment. Dependabot updates both.
- Downloaded tool binaries (actionlint, gitleaks, wasmtime) are pinned by version and verified with `sha256sum --check`.
  Dependabot does not track them; bump the version variables by hand.
- gitleaks runs as the CLI, not `gitleaks-action`, because the action needs a license key for organization repositories.
- Keep `permissions: contents: read` and `persist-credentials: false` unless a job truly needs more.
- `icount` measures the base tip (`HEAD^1` of the PR merge commit) and the merge result in one job and fails when
  instructions grow past `crates/bingsu-core-bench/limits.txt` (`ir=1%`); raise it in the same PR with the reason.
  Callgrind runs only on Linux; locally check `cargo build -p bingsu-core-bench --benches`.
- Each bench group is its own bench target (`benches/<group>.rs`, `harness = false`), because benches in one binary
  changed each other's inlining and counts. CI runs every bench target of the package; a target new since the base tip records only.
  Put the measured work in an `#[inline(never)]` helper: inlined into the bench wrapper, Callgrind on aarch64 undercounts it.
- gungraun: keep `main!` at top level (inside `fn main` it measures nothing and exits 0), and keep `[profile.bench]`
  `strip = false` (a stripped bench counts 0 instructions). The runner version must equal the locked library version.

## Design rules

Anything visible must line up. Before changing a segment, a generator or a style:

1. Colors come from role tokens; never hard-code a color.
2. Contrast: text at least 4.5:1, non-text marks at least 3:1. Color is never the only signal.
3. Width is counted in terminal cells. Separators are exactly one cell; right-aligned content ends on the last cell.
   Watch East Asian ambiguous-width characters and Nerd Font glyph widths.
4. Every Nerd Font icon has Unicode and ASCII fallbacks.
5. The prompt never blocks: slow work (git status, plugins) gets a time budget and runs in the background.

## Verifying changes

- For each new test or condition, make it fail once with a deliberate mutation before trusting it.
- For claims like "none", "all" or "always" in PR bodies or docs, have the search command that proves it.
- Run actionlint on workflow changes and gitleaks on the working tree before pushing.
- Tests that read repository sources and edit them as text normalize `\r\n` to `\n` first; Windows checkouts are CRLF.
- Changing a hash-pinned prompt file (TCB): review it as a security change, then `scripts/pin_tcb.py --write`.
- Gate bypass shapes live in `tools/core-cfg-check/tests/fixtures/bypass/` and run through the real gates via `scripts/test_gate_bypass.py`; add a fixture per new rule.
- Python test dependencies are hash-pinned (`pip install --require-hashes --only-binary=:all: -r …`); regenerate with `uv pip compile --universal --generate-hashes`.

## Internal notes

`.docs/` holds internal design notes, decision records and research. It is gitignored. **Never commit it**
and never link to it from committed files.
