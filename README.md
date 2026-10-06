<div align="center">

# 🍧 bingsu

**One theme, every shell.**
A cross-shell terminal theme and prompt engine for bash, zsh and fish.

[![CI](https://github.com/ai-screams/Bingsu/actions/workflows/ci.yml/badge.svg)](https://github.com/ai-screams/Bingsu/actions/workflows/ci.yml)
[![Security](https://github.com/ai-screams/Bingsu/actions/workflows/security.yml/badge.svg)](https://github.com/ai-screams/Bingsu/actions/workflows/security.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

</div>

> [!WARNING]
> **bingsu is in early development (M1).** The record path and the bash, zsh and fish hooks exist,
> but there is no release, nothing to install and no user-visible prompt yet. Performance has not been measured.
> This README describes what is being built. Features listed below are planned, not shipped.

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
| Engine core (M1: record path and shell hooks) | In progress |
| Performance measurement (M1 Part B) | Not started |
| User-visible prompt, themes, segments and colors | Not started |
| Terminal and CLI generators, Studio | Not started |
| Releases | None yet |

Windows is checked in CI. First-class support targets macOS and Linux.

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
