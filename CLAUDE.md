# CLAUDE.md

This file guides Claude Code (claude.ai/code) when working in this repository.

## Project overview

**bingsu** is a cross-shell terminal theme and prompt engine for bash, zsh and fish.
One set of OKLCH color tokens drives the prompt, the terminal color scheme and CLI tool configs.
The engine is the "ice"; themes, segments and plugins are "toppings" layered on top.

- **Language**: Rust (no crate yet). Windows is checked in CI; macOS and Linux are first-class.
- **License**: MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
- **Stage**: design. There is no code, no release and nothing to install.
  `README.md` lists features as planned. Keep it that way until they ship.
- **Repository**: `ai-screams/Bingsu`, currently private.

## Collaboration rules (MUST FOLLOW)

- **Every change goes through a pull request.** Never commit to `main` directly.
  A local `pre-push` hook blocks pushes to `main` because branch protection is not available while the repository is private.
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
cargo test --workspace --all-features
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
scripts/check-core-purity.sh                       # core purity + CLI prompt-path forbid gate
cargo check -p bingsu --target x86_64-unknown-linux-musl   # CI builds musl; libc APIs differ (getentropy is not there)
tests/golden/record/run-all.sh                     # record golden vectors; SHELLS="bash zsh fish", BINGSU_PY=<python>
BINGSU_TEST_SHELLS="zsh fish bash" python -m pytest tests/shell tests/golden/record/test_overrides.py -q -rf -p no:cacheprovider
```

Shell tests (`tests/shell`):
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
| `ci.yml` | Detect project, Lint workflows (actionlint), Lint (rustfmt, clippy), Test on ubuntu, macos, windows | Rust jobs run only when `Cargo.toml` exists (detect job) |
| `security.yml` | Secret scan (gitleaks), Dependency advisories (cargo-audit) | gitleaks scans full history; weekly cron; cargo-audit needs `Cargo.lock` |
| `dependabot.yml` | github-actions and cargo, weekly | The cargo job fails with "Cargo.toml not found" until the first crate lands; expected |

- Pin every action to a full commit SHA with a version comment. Dependabot updates both.
- Downloaded tool binaries (actionlint, gitleaks) are pinned by version and verified with `sha256sum --check`.
  Dependabot does not track them; bump the version variables by hand.
- gitleaks runs as the CLI, not `gitleaks-action`, because the action needs a license key for organization repositories.
- Keep `permissions: contents: read` and `persist-credentials: false` unless a job truly needs more.

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

## Internal notes

`.docs/` holds internal design notes, decision records and research. It is gitignored. **Never commit it**
and never link to it from committed files.
