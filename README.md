<div align="center">

# 🍧 bingsu

**One theme, every shell.**
A cross-shell terminal theme and prompt engine for bash, zsh and fish.

[![CI](https://github.com/ai-screams/Bingsu/actions/workflows/ci.yml/badge.svg)](https://github.com/ai-screams/Bingsu/actions/workflows/ci.yml)
[![Security](https://github.com/ai-screams/Bingsu/actions/workflows/security.yml/badge.svg)](https://github.com/ai-screams/Bingsu/actions/workflows/security.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

</div>

> [!WARNING]
> **bingsu is in early development (M3a, M3b, M3c, M3d, M4 and M6 done; bash and fish integration (M5) comes after M7).** `bingsu prompt` draws the built-in default prompt
> in bash, zsh and fish, or your own look from a TOML config file, with git status collected in the background. Your
> own text, command and environment variable segments are drawn; commands run in the background, on Linux and macOS.
> There is no release yet. Published performance numbers do not exist yet.
> This README describes what is being built. The feature list below describes the plan; the Status table records what works today.

## What is bingsu?

Bingsu (빙수) is a Korean shaved-ice dessert: a bowl of fine ice with toppings piled on top.
The project follows the same shape. A small **engine** is the ice, and everything you see will be a **topping** you choose:
color flavors, prompt layouts, information segments and plugins.

Most setups today split the look of a terminal across many tools.
The terminal emulator has one palette, the prompt has another, and `ls`, `bat`, `delta` and `fzf` each have their own.
Change one and the rest no longer match.
bingsu is designed to start from a single set of color tokens and generate all of them, so the prompt, the terminal colors and your CLI tools can stay in step.

## Goals

| Goal | What it means |
| -- | -- |
| Same everywhere | One config draws the same prompt in bash, zsh and fish, on macOS and Linux |
| Everything lines up | Colors, separators, icon widths and right-aligned segments follow one set of rules, down to the last terminal cell |
| Customize by looking | Change a few knobs or pick from a catalog in a visual Studio, and the whole theme stays balanced |
| Share and reproduce | Share a theme with a link, and reproduce the same setup on a remote server with a lock file |
| Fast | The prompt never makes you wait, even in very large git repositories |

## Planned features

### Color flavors

- Color tokens defined in **OKLCH**, with dark and light modes generated together.
- Role-based colors (path, git, error, warning, ...) with contrast checks: 4.5:1 for text, 3:1 for non-text marks.
  Meaning is never carried by color alone.
- Generators for terminal color schemes and CLI tool configs from the same tokens.
- Your own flavors use the same format as the built-in ones, so they work everywhere a built-in flavor does.

### Prompt

- Default layout: two-line powerline with a transient prompt.
- Block styles from lean to powerline triangles, rounded pills, slants and brackets.
  Go further with option combinations or a free-form template.
- A theme bundles colors, layout, block style, segment placement, icons and states.
  Themes can be partial and mixed, for example the layout of one with the colors of another.
- Icon sets: Nerd Font by default, with lighter sets and automatic fallback to Unicode or ASCII.
- A time budget for git status. When it runs out, the last known value is shown while the new one is computed in the background.

### Toppings

- **Segments:** directory, git, exit status, duration, jobs, user and host, Python virtual environments, language versions, cloud contexts and more.
- **User-defined segments:** fixed text, environment variables, commands with timeouts and caching.
- **Plugins:** data packs first, then sandboxed WebAssembly plugins that declare their permissions up front.

### Customization and config

- A web **Studio** for live previews and a segment catalog, a terminal **wizard** for the basics,
  and a local Studio that can preview on your real terminal (also over SSH port forwarding).
- **TOML** config with a JSON Schema for editor completion. YAML and JSON are read too.
- Layered configs with `extends`, share links, and a `bingsu.lock` file for reproducible setups.

## Status

| Area | State |
| -- | -- |
| Product definition and design decisions | In progress |
| Color system (palette, dark and light, contrast rules) | Designed |
| Prompt layout and block styles | Designed |
| Implementation language | Rust |
| Record path and shell hooks (M1) | Done |
| Core renderer (M2: layout, width, colors, per-shell output) | Done, used by `bingsu prompt` |
| Config, snapshot and refresh helper (M3a) | Done: TOML config files (`config.toml`, `conf.d/*.toml`, `config.local.toml`, `extends`) with a JSON Schema; a background helper compiles them into a snapshot the prompt reads; `bingsu config check`, `config path`, `config use`, `config schema` and `bingsu reload` |
| Background collection (M3b) | Done: the helper runs a separate collector process with time, memory and file limits (and a system-call filter on Linux), and the prompt shows only results finished before it started |
| Git and folder collection (M3c) | Done: the collector reads git state through bounded, read-only file access (no `git` process) and reports branch or commit, staged, modified, untracked and conflicted counts, ahead/behind and stash, plus whether the folder is read-only or inside a repository; values it cannot finish in time show as unknown (`?`) |
| Git segment | Shown after the folder in the built-in default theme from the second prompt in a repository |
| Performance and process gates (M3d) | Done for Linux: CI runs gates for filesystem call budgets per role, child process count, inherited descriptors, helper lifetime, zombies, snapshot read bytes, trust revocation, execution approval deadlines, the marker update rule and instruction counts, and fails when one breaks. Not complete: memory certification, macOS latency, cold-cache runs and a network home directory were not certified. No published numbers yet |
| Performance measurement (M1 Part B) | Measurement tools in place; no published numbers yet |
| zsh integration (M4) | Done for zsh 5.8 and 5.9: shell notices, exit status and duration, a transient line for past prompts, vi mode prompt switching, redraw when the terminal width changes, and runs next to a pinned oh-my-zsh. Not complete: the shell time gate runs on Linux only, records its verdict without failing the job, and some runs can end BLOCKED; the redraw time has no recorded value on Linux or macOS. bash and fish already handle the exit status and duration; they get the notices, transient line, vi mode switch and width redraw in M5, which comes after M7 |
| User-visible prompt | Built-in default theme or your config in bash, zsh and fish; folder, failure status, duration from 2 seconds and nonzero jobs, subject to available width; your text, command and environment variable segments, and node, python, rust and go versions where a layout draws them |
| User commands and segments (M6) | Done on Linux and macOS: text, command and `env` segments are drawn, commands run in the background with a cleaned environment, time limits, caching and `match`, and the built-in language segments show versions. User-defined language segments run their version command where their project files are found. See [docs/config.md](docs/config.md), which also says how a team shares a config, and [docs/writing-command-segments.md](docs/writing-command-segments.md) for writing a command segment others will use. Not complete: on macOS the helper's check of the folders on `PATH` takes about 20 ms per round (p50 of helper rounds measured on one Mac), which delays the first value of a command segment (the prompt does not wait for it); on macOS, prompt time comes from a record-only run, not a pass or fail verdict: outside a git repository the prompt's p50 is about 0.98 times M4's (about 3.73 ms to 3.67 ms), inside that run's noise of about 6.4%, so no difference can be called; the other cases are still to be measured, and the Linux CI prompt gate gives the verdict. The share of command segments, from raw samples outside any verdict, is about 0.5–0.6 ms at p50 |
| Theme selection and customization | Partly: style presets, templates, colors, layout, width bands and icons from the config; no theme catalog yet |
| Terminal and CLI generators, Studio | Not started |
| Releases | None yet |

Windows is checked in CI. First-class support targets macOS and Linux.

On Linux, the prompt installs a seccomp system call filter before rendering. A kernel without seccomp support still renders
the prompt; a failed filter check or installation gives a minimal prompt with `degraded:sandbox` and a shell notice once per session.
Without a usable runtime folder, the prompt still renders with `degraded:runtime-root`; `init` warns that saved state is unavailable.

## Installing and refreshing shell hooks

Use bash 5.1+, zsh 5.8+ or fish 3.6+. Put the matching init line in your shell startup file
(`.bashrc`, `.zshrc` or `config.fish`); keep the bash and zsh line after other prompt hooks:

```bash
# bash
eval "$(bingsu init bash)"
# zsh
eval "$(bingsu init zsh)"
# fish
bingsu init fish | source
```

After upgrading or downgrading the binary, open a new shell or evaluate the matching init line again in each
running shell. Hooks and the binary must come from the same version: newer hooks can pass arguments an older
binary does not know, and older hooks can leave a newer binary unable to trust saved settings until init runs again.
The record reader can accept older compatible records; that does not promise compatibility between hook and binary versions.

Keep `bingsu-prompt` and `bingsu-collect` in the same folder as `bingsu`, from the same build. `bingsu-prompt` draws the
prompt with only the prompt code, so it starts faster than `bingsu`. Init checks the files beside `bingsu` once, when it
runs: their owner and permissions, and that they come from the same build. It writes the path of `bingsu-prompt` into the
hooks. Without a matching `bingsu-prompt`, the hooks call `bingsu prompt`, which draws the same prompt more slowly. The
hooks also name `bingsu` as the program that refreshes the prompt's data. Nothing checks these files again while the shell
runs, so run init again after you replace them.

For global Git excludes, init also pins `HOME` and `XDG_CONFIG_HOME` into the hooks. Later environment changes
(including direnv) do not select different global config or ignore files; run init again to change these locations.
Unset or empty values stay empty. Invalid values (relative paths, including literal `~/.config`, or more than
64 KiB) are pinned as unknown with one stderr notice per variable naming the reason; init still prints the script.
An empty XDG pin falls back to `HOME/.config`; an empty HOME stays absent. An older hook without these arguments
uses its pinned `--home` with a newer binary, with no XDG override. A newer hook with an older binary can produce `error:bad-args`; refresh the hooks after a downgrade.

The helper sends global excludes bytes with a known/unknown flag in IPC v5. A missing file is known-empty;
other skipped inputs are unknown. The collector still scans untracked files for unknown input, but publishes
untracked as Pending and stage B as partial. `gitdir:` and `gitdir/i:` conditions are not evaluated; conditional
includes that change `core.excludesFile` make the global input unknown unless a later unconditional value resolves it.

Init pins the executable and the runtime, settings, state and log folder paths. After changing XDG paths or replacing
a settings-folder symlink (for example with stow), evaluate init again or open a new shell. A changed symlink target
is refused until then; roots are not automatically selected again. `bingsu reload` refreshes settings for the pinned
folders. `bingsu config use PATH` saves which file stands in `config.toml`'s place; it does not edit that file, and
`conf.d/*.toml` and `config.local.toml` still apply. Without the exported pins, user commands discover folders from
the current environment and warn that these can differ from the prompt's folders.

Use `bingsu config check` to see diagnostics and folder safety details, and `bingsu config path` to see the applied
file order. `bingsu config check --explain` adds, for each command and language segment, whether it runs and why
not, its command, working folder, time limits and the names of the environment it gets, each with the file and line
it came from, and the file it would run. The values of environment entries are not printed; paths such as the file to run can still come from `HOME`, XDG or `PATH`. The file is looked up as from a folder
outside any repository; a prompt inside a repository leaves out executables inside it. For each builtin language segment
(`node`, `python`, `rust`, `go`) the layout draws, it also says what a prompt in the current folder would do now: show a
version without running anything, run a probe (which file, with which arguments), or hide it and why. It decides with the
folder facts the last prompt collected for this folder, says how old they are, and runs nothing; with no such facts it
says so. Here executables are looked up as a prompt in this folder does, inside the repository rules. A folder whose safety cannot be confirmed can supply colors and layout only; choosing a file inside it
with `config use` does not grant execution trust. Check the ownership, permissions and access lists named by the
diagnostic before running init again. External text in diagnostics is sanitized for terminal display; path arguments
in the hooks retain their original bytes. Displayed paths with removed control characters are not exact copies of the names.

## Current limits

- The default prompt remains two lines at narrow widths, including in fish; segments move or disappear as width permits.
- User segments (text, command, `env`, language) have their own limits, such as values showing one prompt late and
  the environment size; [docs/config.md](docs/config.md) lists them.
- If a shape-only source fails checking or compilation during config inspection, it and its descendants are dropped
  and the already loaded data is merged, checked and compiled again; the remaining files are not read again.
- Local config value edits preserve bytes outside the changed value, including comments, order and other quotes.
  The changed value uses the caller's TOML spelling, including its quotes.
- `config check` and `config path` have no command deadline and can wait on a stalled mount; `config check` also
  opens the executables a command segment would run, which can wait the same way. `config check --explain` also
  reads the saved folder facts, looks for repositories above the current folder and opens the `PATH` folders a
  builtin language would be looked up in, each of which can wait the same way. Commands that change
  settings have a three-second limit. The prompt's 50 ms and refresh work's 500 ms budgets are unchanged.
- A deadline cannot interrupt kernel I/O in uninterruptible sleep, including hard NFS or some FUSE operations.
  macOS timer coalescing can delay alarm delivery by several milliseconds. On Linux, a blocked write during suspend
  may take up to roughly another 50 ms after resume to stop. These are not hard wall-clock guarantees.
- A prompt deadline or write failure can end output silently; the shell falls back if it does not receive a complete
  record. An unwind during the output loop also ends silently, even before the first byte; it does not append a panic
  record.
- Linux needs an accessible `/proc` for the refresh helper to start. If it is missing, the helper may fail to start
  without a notice and settings may not refresh. Logging is best effort: without a usable state/log folder, errors
  may leave no log. `config check` provides a direct inspection even when no helper log is available.
- `BINGSU_ROOTS` exports pinned paths to child processes, much like XDG variables. Code running in the shell can
  change these values; they are not a boundary against that code. In fish, non-UTF-8 path round trips depend on
  fish's encoding behavior; a failed round trip falls back rather than applying unverified settings.
- Root-owned targets in `/nix/store` with mode 1775 are refused by the current ownership rules.
  Re-initializing does not relax those rules.

## How bingsu compares

| Tool | Closest to bingsu in | Where bingsu differs |
| -- | -- | -- |
| [Starship](https://starship.rs) | Cross-shell binary, TOML config | Theme covers terminal and tool colors too, visual customization tools |
| [Oh My Posh](https://ohmyposh.dev) | Cross-shell engine with themes | Color tokens shared across every tool, a Studio for previewing |
| [Powerlevel10k](https://github.com/romkatv/powerlevel10k) | Configuration wizard, powerline layouts | Not tied to zsh |

## Contributing

Every change to bingsu goes through a pull request.
Read [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow, commit conventions and CI checks.
Report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

---

<div align="center">

Made by [ai-screams](https://github.com/ai-screams) 🍦

</div>
