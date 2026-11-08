# User segments

Besides the built-in segments (folder, git, status, duration and others), a config can define its own segments
under `[segment."custom/NAME"]` and draw them in a layout like any other segment. Each one says what it is with `kind`.

```toml
[segment."custom/kube"]
kind = "command"
command = ["kubectl", "config", "current-context"]
cache = "30s"
match = "([^/]+)$"

[segment."custom/aws"]
kind = "env"
env = "AWS_PROFILE"

[segment."custom/tag"]
kind = "text"
text = "prod"

[layout.line1]
left = ["dir", "git", "custom/kube", "custom/aws", "custom/tag"]
```

`bingsu config check` reports mistakes in these keys, and `bingsu config check --explain` shows, for each command
and language segment, whether it runs, why not, and where each key came from. Editors that read JSON Schema complete
the keys from `bingsu config schema`.

## Kinds and keys

| `kind` | Shows | Keys |
| -- | -- | -- |
| `text` | A fixed text | `text` |
| `command` | The first line a command prints | `command` or `shell` (with `unsafe_shell = true`), `cwd`, `env_allow`, `timeout`, `cache`, `match` |
| `env` | The value of one variable of the shell's environment | `env` |
| `language` | A language version for projects marked by a file | `detect_files`, `interpreter`, `version`, `cwd`, `env_allow`, `timeout`, `cache` |

Every kind also takes `enabled = false`, which turns the segment off. A value is cut to 64 terminal cells, with an
ellipsis, and control, bidirectional and invisible characters are removed before it is drawn. A segment with nothing
to show is left out together with its separators. A config draws at most 256 user segments.

### `text`

`text` is shown as written.

### `env`

`env` names one variable, such as `"AWS_PROFILE"`: a letter or `_`, then letters, digits and `_`, at most 64 bytes.
The prompt reads the variable from the environment the shell gave it, so a change shows on the next prompt,
including after a terminal resize. An unset or empty variable shows nothing.

### `command`

`command` is the program and its arguments as an array; no shell reads it. A bare name is looked up in a cleaned
`PATH` (see [How commands run](#how-commands-run)). `{dir}`, as a whole element, becomes the shell's folder.

`shell` runs a line through `/bin/sh -c` instead. It needs `unsafe_shell = true` next to it, and `config check` warns
that shell text can run anything it says. Prefer `command`.

| Key | Default | Meaning |
| -- | -- | -- |
| `cwd` | `"neutral"` | `"neutral"` runs in an empty private folder. `"untrusted-current"` runs in the shell's folder, with a warning: files there, such as a cloned repository's, can change what the command does |
| `env_allow` | none | More variables to pass. Loader, language and shell startup settings (`LD_*`, `DYLD_*`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV` and others) are never passed, and naming one is an error |
| `timeout` | `"200ms"` | How long the command may run; at most one second |
| `cache` | `"0s"` | How long a result is reused before the command runs again |
| `match` | none | A regular expression that picks the value from the first line (see [match](#match)) |

### `language`

```toml
[segment."custom/deno"]
kind = "language"
detect_files = ["deno.json", "deno.jsonc"]
interpreter = "deno"
version = ["--version"]
```

`detect_files` lists the file names that mark the language's project: 1 to 16 plain file names, none twice. They are
looked for in the shell's folder and the folders above it, up to the repository root and at most 32 folders up.
`interpreter` and `version` are the program that prints the version and its arguments.

The segment runs its interpreter only where one of these files was found, and shows the first word of the first line
that, after one leading `v`, starts with a digit and reads as a version: `deno 2.1.4 (stable)` shows `2.1.4`,
`v20.1.0` shows `20.1.0`. A line without such a word shows nothing.

- `interpreter` is looked up as a command's first word: an absolute path (it may hold spaces), or a name without
  spaces searched in the cleaned `PATH`. A relative path such as `./deno` never runs.
- `cwd`, `env_allow`, `timeout` and `cache` work as for a command, with the same defaults.
- The folder collection finds the files, so the version shows from the prompt after the round that found them. When
  the files are gone, the segment hides from the next round on; with `cache` set, it keeps its last value until the
  cache time ends.
- With `cwd = "untrusted-current"`, an interpreter that is a version manager's shim (mise's links, for example) lets
  the repository's files choose which version, and so which program, runs. A command carries the same risk, but a
  language segment is where this setting is likely to be chosen, to show each project's version.

The built-in language segments `node`, `python`, `rust` and `go` need no keys. They show a version when the folder
holds a project of that language. When a version manager's selection can be read without running anything
(pyenv, rustup), the version comes from it; otherwise the interpreter itself runs with fixed arguments. A version
that cannot be told safely is hidden; `config check --explain` says why.

## Where segments come from

The key that decides what runs or what is shown (`kind`, the command keys, `env`, `match`, `enabled`) counts only
from your own config files: `config.toml`, `conf.d/*.toml`, `config.local.toml` and the files they extend inside the
config folder, when the safety check passes. A file outside the config folder (for example a theme a repository ships)
can set colors and layout only; its execution keys are ignored with a warning. A file that fails the safety check turns
the segments whose keys it sets off.

A command, language or `env` segment is used only where a layout from your own files draws it, at a width where that
layout is chosen. Naming it only in a theme's layout does not run the command or show the variable.

## How commands run

The refresh helper runs commands, and the version commands of language segments, in the background after a
prompt is drawn; the prompt never waits for a command. A value shows from the next prompt on.
The refresh helper is `bingsu` itself, and the prompt is drawn by `bingsu-prompt` beside it. Keep `bingsu`,
`bingsu-prompt` and `bingsu-collect` in one folder and run init again after replacing them (see
[Installing and refreshing shell hooks](../README.md#installing-and-refreshing-shell-hooks)).

- Each round runs at most 8 commands, those tried longest ago first. A config may draw at most 32 command and
  language segments, counting those a layout from your own files draws at some width; past that, the config is
  invalid. Declared segments no layout draws do not count.
- A command gets a cleaned environment: `HOME`, `USER`, `LANG`, `LC_*`, `TERM`, `TZ`, a cleaned `PATH`, and the
  names in `env_allow`.
- The cleaned `PATH` keeps only absolute folders that nobody but you and root can change, and leaves out the folders
  inside the repository the shell is in, so a checked-out repository cannot place a program under a command's name.
- Scripts must name an absolute interpreter on their first line; `#!/usr/bin/env` is refused because it would look
  the interpreter up in `PATH`.
- The first line of the output, at most 4 KB, is the value. A failed command (nonzero exit, timeout) shows nothing
  and is not run again for 10 seconds.
- A result is reused while it is newer than `cache` and was made with the same command and the same values of the
  passed variables. Another shell with other values runs the command again.
- On Linux each command runs in its own cgroup when the system allows it, so it ends with everything it started.

### match

`match` picks the value from the first line: the group named `value` if the pattern has one, else the first capture
group, else the whole match. A line the pattern does not match, or an empty pick, shows nothing.

```toml
match = "go([0-9.]+)"            # "go version go1.23.1 darwin/arm64" shows 1.23.1
match = "(?P<value>[^/]+)$"      # "arn:aws:eks:…/prod" shows prod
```

The syntax is that of the Rust `regex` crate, with Unicode classes. A pattern may be at most 256 bytes, compile to at
most 64 KiB, and have at most 16 capture groups; `config check` reports one past these limits and turns only that
segment off. Long repeats of Unicode classes, such as `\w{10}`, are past the limit; `\w+` is not.

Changing only `match`, or removing it, does not run the command again: the next round applies the new pattern to
the stored line, or shows the whole line again. Right after the edit the prompt can still show the old value until
that round publishes the new one; it never shows a value picked by a pattern other than the one in the config it reads.

## Current limits

- Values appear one prompt late: after a command's first run, after a config edit, and after a version selection file
  (`.python-version`, `rust-toolchain.toml`) changes.
- A shell environment over 64 KiB is not passed to the helper: command and `env` segments then show nothing. A
  variable named twice in the environment is not shown and not passed.
- Patterns are applied within about 250 ms per round. Past that, the remaining results of the round are published
  as failures, which show nothing and run again after 10 seconds; a config with many slow patterns can see some of
  them hidden in every round.
- A cached value can be reused within `cache` even if `{dir}` now means another folder, `PATH` now finds another
  program, or a script's contents changed. The default `cache` of 0 is not affected.
- A repository that has no `.git` entry (a bare repository, or one placed with `GIT_DIR`) does not keep its folders
  out of the cleaned `PATH` unless the folder collection found it.
- Built-in languages: a manager shim the rules cannot read (nodenv, goenv) hides the version; a pyenv version given
  as a prefix (`3.12`) without that exact installed folder is hidden. In very deep folders some languages may not be
  found within the collection's time limit.
- On macOS, commands do not run on a system without `AT_SYMLINK_NOFOLLOW_ANY`, and an executable you cannot read is
  not run.
- Each shell session leaves a small lock file in the runtime folder, and on Linux an empty cgroup folder; nothing
  removes them yet.
- `config check` can wait on a stalled network mount while it opens the programs a command segment would run.

## Group-writable files

Many systems create files and folders writable by your group (umask `002`). A config file, config folder or program
that your group can write is accepted only when every member of that group is you or root; a private group that has
your name and no other members counts. On a shared group, `config check` names the file; remove the group write
bit (`chmod g-w`) or change the group.
