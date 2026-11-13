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

For the commands that help write and check a config (`setup`, `list`, `explain`, `doctor`, `help`), see
[Commands that help with a config](#commands-that-help-with-a-config) below.

`bingsu config edit` opens your settings file in `$VISUAL`, or `$EDITOR` when that is unset (there is no default
editor), then checks what you saved like `config check` and applies it like `reload`. The file is the one `config use`
chose, else the one file of the settings place, `config.toml` or `config.json`; with both there it opens neither and points
at E308 (`bingsu help E308`). It is never created (run `bingsu setup`). The editor value is not run by a shell: it is split
into words and quotes are removed; `; & | < > ( )` outside single quotes are refused, and so are `$` and backquotes
even inside double quotes (only single quotes keep them; point the variable at a script instead). A program name is
looked up only in absolute `PATH` folders. If the saved file is
not valid it is not applied: the prompt keeps the previous settings and commands stop running until a valid save. While the editor runs, Ctrl-C and Ctrl-\ go to the editor and `bingsu` ignores them; if you suspend the editor (Ctrl-Z), `bingsu` waits and stops with it, and `fg` resumes both.

Writing a command segment for other people to use? See
[Writing a command segment for others](writing-command-segments.md).

## Kinds and keys

| `kind` | Shows | Keys |
| -- | -- | -- |
| `text` | A fixed text | `text` |
| `command` | The first line a command prints | `command` or `shell` (with `unsafe_shell = true`), `cwd`, `env_allow`, `timeout`, `cache`, `match` |
| `env` | The value of one variable of the shell's environment | `env` |
| `language` | A language version for projects marked by a file | `detect_files`, `interpreter`, `version`, `cwd`, `env_allow`, `timeout`, `cache` |

Every kind also takes `enabled = false`, which turns the segment off. A value is cut to 64 terminal cells, with an
ellipsis, and control, bidirectional and invisible format characters are removed before it is drawn (a zero-width
joiner and variation selectors stay, for emoji). A segment with nothing to show is left out together with its
separators. A config draws at most 256 user segments.

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

An example segment (add a layout line that draws `custom/deno`; without one `bingsu config check` warns that the segment is not used):

```toml
[segment."custom/deno"]
kind = "language"
detect_files = ["deno.json", "deno.jsonc"]
interpreter = "deno"
version = ["--version"]
```

`detect_files` lists the file names that mark the language's project: 1 to 16 plain file names, none twice. They are
looked for in the shell's folder and, inside a repository, in the folders above it up to the repository root (at
most 32 folders up). Only a regular file counts; a link or a folder with that name does not. `interpreter` and
`version` are the program that prints the version and its arguments.

The segment runs its interpreter only where one of these files was found, and shows the first word of the first line
that, after one leading `v`, starts with a digit and reads as a version: `deno 2.1.4 (stable)` shows `2.1.4`,
`v20.1.0` shows `20.1.0`. A line without such a word shows nothing.

- `interpreter` is looked up as a command's first word: an absolute path (it may hold spaces), or a name without
  spaces searched in the cleaned `PATH`. A relative path such as `./deno` never runs.
- `cwd`, `env_allow`, `timeout` and `cache` work as for a command, with the same defaults.
- The folder collection finds the files, so the version shows from the prompt after the round that found them. When
  the files are gone, the segment hides after the next round that runs commands. With `cache` set and no other
  command or built-in language needing a round, that can wait until the cache time ends. A round whose collection
  did not answer (for example, out of time) keeps the last value.
- At most 16 user languages are looked for, in config order. The built-in languages drawn come first and count
  toward the same 16. A user language that does not fit beside them, or in the rest of the collection request, is
  not looked for (so it does not run); later ones that still fit are.
- With `cwd = "untrusted-current"`, an interpreter that is a version manager's shim (mise's links, for example) lets
  the repository's files choose which version, and so which program, runs. A command carries the same risk, but a
  language segment is where this setting is likely to be chosen, to show each project's version.

The built-in language segments `node`, `python`, `rust` and `go` need no keys. They show a version when the folder
holds a project of that language. When a version manager's selection can be read without running anything
(pyenv, rustup), the version comes from it; otherwise the interpreter itself runs with fixed arguments. A version
that cannot be told safely is hidden; `config check --explain` says why.

## Where segments come from

The keys that decide what runs or what is shown (`kind`, the command and language keys, `env`, `match`, `enabled`)
count only from files you trust, each when it passes the safety check:

- `config.toml`, `conf.d/*.toml` (and the YAML files there, see [YAML files](#yaml-files)), `config.local.toml` and
  the files they extend inside the config folder, including a link placed there that points to a file elsewhere;
- the file you chose with `bingsu config use`, wherever it is. It stays trusted when it changes in place, for example
  after a `git pull` when it sits in a repository: choose a file in a repository only if you trust everyone who can
  change it.

Any other extended file (for example a theme a repository ships) can set colors and layout only; its execution keys
are ignored with a warning. A file that fails the safety check turns the segments whose keys it sets off.

A command or language segment runs only when a layout from your own files draws it at some width; it then runs at
every terminal width, also where the layout chosen for a narrow terminal leaves it out. An `env` segment is allowed
the same way: once a layout from your own files draws it at some width, its value is shown wherever a layout draws
it, including a theme's layout at a narrow width. Naming a segment only in a theme's layout does not run the command
or show the variable.

## Narrow terminals

A layout band (`[layout.when.NAME]`) is chosen for a range of widths. It takes the lines of `[layout]` unless it has
a template of its own, and a template draws in place of those lines. The built-in theme has one band, `narrow`, for
widths under 60, and it has its own template: there the prompt shows the host, the folder and git on the upper line,
and the duration and the prompt character below, whatever `[layout.line1]` and `[layout.line2]` say. Your lines are
used from 60 columns on, and `bingsu config check` notes the widths where they are not (N504).

The built-in template stays unless the band gets another one. To draw your own segments under 60 columns too, write
a template for the band:

```toml
[layout.when.narrow.style]
template = "{dir} {git}{@nl}{char}"
```

`bingsu explain --width 40` shows what is drawn at a narrow width.

## YAML files

A file whose name ends in `.yaml` or `.yml` takes the same keys as a TOML file and is read the same way, in three
places: in `conf.d/` (applied in name order together with the `.toml` files there), through `extends`, and as the file
you choose with `bingsu config use`. The settings folder's own files are still `config.toml` and `config.local.toml`:
a `config.yaml` beside them is not read, and nothing reports it. Put a YAML file in `conf.d/`, or choose it with
`bingsu config use`.

```yaml
# conf.d/50-segments.yaml
segment:
  custom/kube:
    kind: command
    command: [kubectl, config, current-context]
    cache: 30s
  custom/tag:
    kind: text
    text: prod
layout:
  line1:
    left: [dir, git, custom/kube, custom/tag]
```

A setting is read only from what is written where it is used, so these YAML features are refused with E108:
anchors (`&name`), aliases (`*name`, also as a merge key `<<: *name`), tags (`!tag`, `!!str`), a second document in
the same file (`---`) and a key that is a mapping or a list. E107 reports the rest of what a YAML settings file cannot
hold: a syntax error, a key written twice in one mapping, a value that is `null` (`~`, `null` or nothing after the
colon), a file whose top level is not a mapping, and a NUL character. `bingsu help E107` and `bingsu help E108` explain
both.

Values follow the YAML 1.2 core schema: `true` and `false` are booleans, numbers (`42`, `0x1F`, `0o17`, `0.74`) are
numbers, and everything else is a string, including `yes`, `no` and `on`. Quote a value to keep it a string
(`"214"`). Keys are taken exactly as written, whatever they look like: `~`, `null` and `""` are three different keys,
and so are `1` and `0x1`. A byte order mark at the start of the file is allowed.

## Sharing a config with a team

A file outside your config folder can set colors and layout only, because a command in a file that other people can
change would run as you. A team that wants one look, and commands of its own, has two ways to share.

### A shared look, your own commands

Keep the shared file free of commands: icons, style, options of built-in segments, and layout lines of built-in
segments. Everyone extends it from their own `config.toml` and adds their commands there.

The team's file, for example `~/src/team-prompt/team.toml` in the team's repository:

```toml
icons = "ascii"

[style]
preset = "lean"

[segment.dir]
shorten = ["repo"]

[layout.line1]
left = ["dir", "git"]
```

Your `config.toml` (this example needs the team file to exist; without it `bingsu config check` reports that the `extends` entry cannot be used):

```toml
extends = ["~/src/team-prompt/team.toml"]

[segment."custom/email"]
kind = "command"
command = ["git", "config", "user.email"]
cache = "60s"

[layout.line1]
right = ["custom/email"]
```

Tables merge and each array is replaced whole, so the team's `left` stays and your `right` is added to the same line.
`bingsu config check` lists the team's file as "colors and layout only". Draw your commands in a layout line of your
own file: a command that only the team's layout names does not run (W404).

### A copy of your own

When the team's file has commands, read it, then copy it into `conf.d/` (for example `conf.d/team.toml`). The copy
is yours, and its commands run. What to read are the keys that decide what runs: `kind`, `command`, `shell`,
`unsafe_shell`, `cwd`, `env_allow`, and a `language` segment's `detect_files`, `interpreter` and `version`.

The cost: a copy does not follow the team's changes. To update it, read the change and copy the file again.

`bingsu config use` on the team's file trusts it in place instead (see "Where segments come from"): its later changes
run without another look, so use it only if you trust everyone who can change that file.

### Turning a segment off

To turn off one of the team's segments, set `enabled = false` in a file of your own that applies after it, for
example `conf.d/90-mine.toml` (the `conf.d` files apply in name order). This is a piece to add to a config that already defines the segment, not a complete file:

```toml
[segment."custom/email"]
enabled = false
```

`bingsu config check --explain` shows each file as "trusted" or "colors and layout only", and for each command
segment, whether it runs and which file each key came from.

## How commands run

The refresh helper starts with each prompt (not with a redraw, such as after a terminal resize) and runs commands,
and the version commands of language segments, in the background; the prompt never waits for a command. A value shows on a later prompt once its round has finished:
usually the next one, and after several when a round has more segments to run than it takes at once.
The refresh helper is `bingsu` itself, and the prompt is drawn by `bingsu-prompt` beside it. Keep `bingsu`,
`bingsu-prompt` and `bingsu-collect` in one folder and run init again after replacing them (see
[Installing and refreshing shell hooks](../README.md#installing-and-refreshing-shell-hooks)).

- Each round runs at most 8 command and language segments, those tried longest ago first, besides up to 4 version
  programs of the built-in languages. A config may draw at most 32 command and language segments; past that, the
  config is invalid. Only segments that can run count: drawn by a layout from your own files at some width and not
  turned off.
- A command gets a cleaned environment: `HOME`, `USER`, `LANG`, `LC_*`, `TERM`, `TZ`, a cleaned `PATH`, and the
  names in `env_allow`. The run information the helper hands over, the passed variables, the folder and the
  interpreter among it, must fit in about 16 KiB; past that, the command does not run. The arguments are passed
  separately and do not count.
- The cleaned `PATH` keeps only absolute folders that nobody but you and root can change, and leaves out the folders
  inside the repository the shell is in, so a checked-out repository cannot place a program under a command's name.
- Scripts must name an absolute interpreter on their first line; `#!/usr/bin/env` is refused because it would look
  the interpreter up in `PATH`.
- A program that is setuid or setgid, or on Linux carries file capabilities (for example `ping` on Debian), does not
  run, as a command or as a built-in language's version program, on every system. Neither does a script whose
  interpreter is such a program. `config check` names a command segment's program with that reason (W411), and
  `config check --explain` shows it on the `executable` line.
- A program changed after bingsu checked it (`chmod`, `setcap`, or another file moved over its name) is refused
  when the command starts. A change in the last instant before the start itself, by someone allowed to change that
  folder, is not caught.
- The first line of the output, at most 4 KB, is the value. A failed command (nonzero exit, timeout) shows nothing
  and is not run again for 10 seconds, unless its keys or the values its result depends on change (the passed
  variables, `TERM` aside unless `env_allow` names it).
- A result is reused while it is newer than `cache` and was made in the same folder with the same command and the
  same values of the passed variables; `TERM` does not count unless `env_allow` names it. Another shell with other
  values runs the command again.
- On Linux each command runs in its own cgroup when the system allows it, so it ends with everything it started.

### match

`match` picks the value from the first line: the group named `value` if the pattern has one, else the first capture
group, else the whole match. A line the pattern does not match, or an empty pick, shows nothing. These are pieces to add
to a config; draw the segments in a layout line to see them:

```toml
[segment."custom/go"]
kind = "command"
command = ["go", "version"]
match = "go([0-9.]+)"            # "go version go1.23.1 darwin/arm64" shows 1.23.1

[segment."custom/cluster"]
kind = "command"
command = ["kubectl", "config", "current-context"]
match = "(?P<value>[^/]+)$"      # "arn:aws:eks:…/prod" shows prod
```

The syntax is that of the Rust `regex` crate, with Unicode classes. A pattern may be at most 256 bytes, compile to at
most 64 KiB, and have at most 16 capture groups; `config check` reports one past these limits and turns only that
segment off. Long repeats of Unicode classes, such as `\w{10}`, are past the limit; `\w+` is not.

While the stored result is still within `cache`, changing only `match`, or removing it, does not run the command
again: the next round applies the new pattern to the stored line, or shows the whole line again. With the default
`cache` of 0, or once it has passed, the command runs again as usual. Right after the edit the prompt can still show
the old value until that round publishes the new one; it never shows a value picked by a pattern other than the one in
the config it reads.

## Commands that help with a config

### First settings: `bingsu setup`

`bingsu setup` makes a first settings file from two questions: whether you can see Nerd Font symbols, and the color
mode (it asks the terminal for its background color and shows what it found). It writes
`$XDG_CONFIG_HOME/bingsu/config.toml` (folder 0700, file 0600) only when there is no such file. Answering "no" to the
symbols question writes `icons = "unicode"` and `preset = "lean"`. The file starts with a `#:schema` line, so editors
that read JSON Schema complete the keys, and every line has a comment.

When the file is there, `setup` changes nothing and lists how it differs from what it would have written. It does not
edit your shell startup file: it prints the line to add.

```console
$ bingsu setup --yes --icons unicode --mode light
bingsu: ~/.config/bingsu/config.toml is already there, so nothing was written.
It differs from your choices here:
  icons: "nerd" now, "unicode" suggested
  style.preset: "triangle" now, "lean" suggested
  colors.mode: "dark" now, "light" suggested
Edit it yourself to change them; `bingsu config check` checks the result.
Add this to your shell's startup file to start bingsu:
eval "$(bingsu init zsh)"
```

Without a terminal it asks nothing and needs `--yes --icons nerd|unicode --mode auto|dark|light`. On a terminal,
`--icons` and `--mode` answer their question in advance and `--yes` skips the final confirmation.

### Editing: `bingsu config edit`

`bingsu config edit` opens your settings file in your editor, then runs `config check` on what you saved and, when it is
valid, applies it the way `reload` does. A file that is not valid is not applied: the prompt keeps drawing with the
last good settings, and the command exits 1 and says so.

It opens the file `config use` picked, or else the one file of the settings place: `config.toml` or `config.json`, whichever
is there. With both there it opens neither, points at E308 and exits 1. It does not make a file: when there is none it
points to `bingsu setup` and exits 1.

The editor is `$VISUAL`, or `$EDITOR` when `$VISUAL` is unset or empty; with neither set the command stops with an
example and does not try a default. The value is not given to a shell. It is split at spaces with quotes and backslashes
undone, and `$`, backticks, `;`, `&`, `|`, `<`, `>`, `(` and `)` outside single quotes are refused (point the variable at
a script instead); `~` and `*` are not expanded. A first word with a `/` must be an absolute path; otherwise it is
looked up in the absolute entries of `PATH`, in order, and only a regular file with an execute bit is run. The file's
path is added as the last argument. If the editor ends with a nonzero status or by a signal, nothing is applied.

```console
$ bingsu config edit
(the editor opens ~/.config/bingsu/config.toml; you save `icons = "unicode"`)
settings folder: ~/.config/bingsu
selection: config.toml or config.json in the settings folder
files, in the order they apply:
  1. (built-in) (trusted)
  2. ~/.config/bingsu/config.toml (trusted)
diagnostics: 0 error(s), 0 warning(s), 0 note(s)
result: valid
bingsu: edited; new settings published (generation 1)
```

After a save that is not valid, the check says so, nothing is published and the exit code is 1:

```console
$ bingsu config edit
(the editor opens the file; you save `colr = 1`)
diagnostics: 1 error(s), 0 warning(s), 0 note(s)
E201: unknown key `colr`
  where: ~/.config/bingsu/config.toml:1:1
  fix: check the key name
  code: E201 (bingsu help E201)
result: invalid; the prompt keeps the last good settings
bingsu: the saved settings are not valid, so they were not applied; the prompt keeps the previous settings
bingsu: the settings are not valid, so nothing changed and the prompt keeps the last good settings. Run: bingsu config check
```

The file you saved stays as it is, so run `bingsu config edit` again to fix it. If another refresh is running at the
moment you save, the new settings are not published; the command says "another refresh is running, so nothing changed. Try again in a moment", and `bingsu reload` publishes the saved file.

Two limits. While the editor is open, another shell's prompt can read a half-written file; if that file is invalid, the
commands of that shell stop until you save a valid one. And a key in a settings file can never choose the editor.

### Names: `bingsu list`

`bingsu list KIND` prints the names a config accepts, one row per line with the columns split by a tab. It reads the same tables the
config checker and the renderer read, so a name it prints is a name the config accepts.

| `KIND` | Columns |
| -- | -- |
| `presets` | The seven style presets: `lean`, `triangle`, `pill`, `slant`, `diamond`, `block`, `bracket` |
| `segments` | A built-in segment and the color role it draws with |
| `flavors` | The color flavors |
| `roles` | A color role and the palette colors it points to in dark and in light mode |
| `shorteners` | The ways `segment.dir.shorten` can shorten a path |
| `icons` | An icon name and its glyph in the `nerd`, `light`, `unicode` and `ascii` sets |

`bingsu list presets --preview` draws every preset once as the upper line of the default layout, with your current
folder; the other values (a branch, a duration, the time) are samples. On a terminal it uses color unless `NO_COLOR` is
set, and `--icons nerd|light|unicode|ascii` picks the icon set (`unicode` by default). The name takes 9 columns and the
line is drawn for `max(60, $COLUMNS - 9)` cells (71 when `COLUMNS` is not set), so in a terminal narrower than 69
columns the lines are wider than the terminal. It starts no command, reads no config and writes nothing.

```console
$ bingsu list presets --preview --icons unicode
lean     ~/projects/api main                                         2.3s 12:34
triangle  ~/projects/api ▸ main ▸                               ◂ 2.3s ◂ 12:34 
pill     ◂ ~/projects/api ▸ ◂ main ▸                         ◂ 2.3s ▸ ◂ 12:34 ▸
slant     ~/projects/api ▸ main ▸                               ◂ 2.3s ◂ 12:34 
diamond  ◂ ~/projects/api ▸ ◂ main ▸                         ◂ 2.3s ▸ ◂ 12:34 ▸
block      ~/projects/api     main                             2.3s     12:34  
bracket  [~/projects/api] [main]                                 [2.3s] [12:34]
```

### Why a segment is hidden: `bingsu explain`

`bingsu explain [SEGMENT] [--width N] [--config FILE] [--format json|text]` says what the layout decides at one
width, in words: which layout band applies, which overflow steps were taken, which segments are hidden and why, and
which are shortened. It decides with the same code the prompt uses, so the report is what the prompt does with the
same settings and values. Give a segment name to look at one segment; for a command or language segment you defined
it also says whether the unit would run and why not (the same words as `config check --explain`). The built-in language
segments (`node`, `python`, `rust`, `go`) have no such part in `explain`; `config check --explain` covers them.

Without `--width`, `explain` decides at `COLUMNS` when it holds a whole number from 1 to 65535, else at the width
of the terminal its output goes to, else at 80 columns. The `width:` line says which (`from COLUMNS`,
`from the terminal`, `assumed`), and so does `width_source` in the JSON form. Shells keep `COLUMNS` to themselves
unless it is exported, so in a terminal the width usually comes from the terminal; through a pipe it is 80.

`explain` runs nothing: no command, no collector, no helper, and nothing is written or published. Values a collector
or a command would bring are not there, so those segments show as `no-value`; read the result as "what the layout does
with the values a prompt has".

```console
$ bingsu explain --width 30
settings: the ones `bingsu config path` lists
basis: nothing is published yet, so this is what your files give; the next prompt publishes them
width: 30 cells
layout: band `narrow`
line 1:
  overflow step 1: shortened names
  hidden: git [no-value] (the segment sent no value)
  hidden: host [no-value] (the segment sent no value)
  shortened: dir with abbrev 1
line 2:
  hidden: duration [no-value] (the segment sent no value)
explain runs no command and collects no git or folder facts; a segment that needs them shows as no-value.
```

`--config FILE` reads that one file in place of your settings, as a config that cannot run anything: a file that uses
`extends` is refused, since it would read other files. This is the way to try a config someone sent you.

`--format json` prints the same facts as one JSON document with fixed field names (`bingsu` ships its JSON Schema in
`crates/bingsu-core/schema/diag-output-v1.json`). `bingsu config check --format json` uses the same document form for
diagnostics. Values of environment variables do not appear in either output.

### Problems with the installation: `bingsu doctor` and `bingsu help`

`bingsu doctor` checks the installation and the shell setup, one row per check. It runs no other executable, writes no
file and starts no process. The only thing it does besides reading is to ask the terminal two questions (see
[Terminal rows](#terminal-rows)). Each row has a status (`ok`, `warn`, `fail`, `unknown`, `skipped`), one
line, and, when there is something to do, a diagnostic code that `bingsu help CODE` explains.

```console
$ bingsu doctor
bingsu doctor
  ok      executable      ~/.local/bin/bingsu: only you and root can change it or the folders above it
  ok      bingsu on PATH  ~/.local/bin/bingsu: the bingsu on PATH is this executable
  warn    pinned folders  init has not run in this shell; commands read the current environment (W603; bingsu help W603)
  ok      one build       bingsu-prompt is not installed here; the hook calls `bingsu prompt`; bingsu-collect is from this build
  unknown shell           shell version not confirmed: no shell passed it to this command
  skipped seccomp         this platform has no seccomp
  ok      settings        the settings check out (0 warning(s))
result: 4 ok, 1 warning(s), 0 failed, 1 unknown, 1 skipped
```

| Check | What it looks at |
| -- | -- |
| `executable` | The path bingsu runs from, every link on the way and every folder above it: only you and root (or a group with no other member) may change them |
| `bingsu on PATH` | Whether the `bingsu` your shell finds on `PATH` is the one running now |
| `pinned folders` | The folders `bingsu init` pinned in this shell. The runtime folder is checked for being replaced (a different folder at the same path) or removed. The settings, state and log folders get the safety check the helper uses (owner, permissions, links); a state or log folder that does not exist yet is accepted |
| `one build` | That `bingsu`, `bingsu-prompt` and `bingsu-collect` come from the same build (read from the files, not by running them) |
| `shell` | The shell version. Today this is always `unknown`: no shell passes its version to `doctor` yet, and bingsu never guesses a version from a path or a folder name |
| `seccomp` | Whether the kernel supports seccomp (Linux; the example above is from macOS, where it is skipped). It does not check whether the prompt's own filter was installed |
| `settings` | A summary of `config check`; a settings folder that fails the safety check is a `fail` |
| `terminal width` | How many cells the terminal moves the cursor for probe characters, against `width.ambiguous` and `width.emoji` ([below](#terminal-rows)) |
| `background` | Whether the terminal's background is light or dark, against what the prompt draws for ([below](#terminal-rows)) |

The exit code is 1 when any check fails; warnings, `unknown` and `skipped` give 0. `--format json` prints the same
rows as a JSON document. The shell evidence a hook can give (hook order, the envelope a hook sent, the circuit
breaker) is not part of this table yet.

#### Terminal rows

The last two rows ask the terminal. They write a few characters to the screen, read the answers back and clear the line,
so they run only when standard output is a terminal, or when you pass `--terminal`, which asks the controlling terminal
(`/dev/tty`) even when the output goes to a pipe. Without a terminal, or when `bingsu` is not the job in the foreground,
both rows are `skipped`. A terminal that does not answer within about 0.2 seconds gives `unknown`, never a warning.
Ctrl-C stops the run with exit code 130 after the terminal is back in its normal state.

| Row | What it measures | A warning means |
| -- | -- | -- |
| `terminal width` | Writes twelve probe characters one after the other (ASCII, a Hangul syllable, three East Asian ambiguous characters, an emoji, an emoji made by U+FE0F, a joined emoji, a flag, a letter with a combining mark, two Nerd Font glyphs) and asks the cursor position after each. It runs when the terminal is at least 40 columns wide | The terminal draws something in another number of cells than `width.ambiguous` and `width.emoji` say (W613). The row names the characters and the values the terminal fits |
| `background` | Asks for the background color (OSC 11) and compares light or dark with what the prompt picks. It runs only when `colors.mode` is `auto`; with `dark` or `light` set, the prompt does not guess and the row is `skipped` | The prompt would draw for the other brightness (W614). Set `colors.mode` to `dark` or `light` |

With `--format json` the two rows carry a `details` object with the measured cells per probe and the values that fit
(`probes`, `recommended`, `inside_tmux`), or the two brightnesses (`terminal`, `prompt`, `colors_mode`).
Inside `tmux` the answers come from `tmux`, which may differ from the outer terminal; the width row says so.

<!-- G2-PENDING #306-follow-up: add a real `bingsu doctor --terminal` output here after the terminal rows are merged -->

`bingsu help CODE` explains a diagnostic code that `config check`, `explain` or `doctor` printed, in three parts: what
happened, why, and how to fix it. It does not read your settings. A code it does not know ends with exit code 2.

```console
$ bingsu help E201
E201 (error)

What happened
  A key in the file is not a bingsu key.

Why
  Unknown keys are errors, so a typo such as `colr` never passes silently and leaves you wondering why nothing changed.

How to fix
  Check the spelling against `bingsu config schema`. When a close key exists, the message suggests it.
  A key inside a user segment is written as `segment.<id>.command`, `segment.<id>.text` and so on.
```

## JSON config files

A file whose name ends in `.json` is read as JSON and then treated like the TOML one: the same keys, merging, `extends`,
trust and places in diagnostics. The places are `config.json` or `config.toml`, `conf.d/*.json` and `conf.d/*.toml`
(read together by name), and `config.local.json` or `config.local.toml`. If both forms of one place exist
(`config.toml` and `config.json`), bingsu reads neither and reports E308 (`bingsu help E308`); the last good settings stay
in use. `conf.d/a.toml` and `conf.d/a.json` are different names, so both are read. A file picked with `config use`
stands in for the whole place, so the two names beside it do not conflict.

The JSON must follow RFC 8259 strictly: no comments, no trailing commas, no `null`, no duplicate keys, an object at
the top. Anything else is E106. The limits are the same as for TOML (256 KiB per file, 32 levels). A top-level
`"$schema"` string is accepted for editors and ignored; `bingsu config schema` prints a schema that declares it.

```json
{
  "$schema": "https://raw.githubusercontent.com/ai-screams/Bingsu/main/crates/bingsu-core/schema/config-v1.json",
  "colors": { "mode": "dark" },
  "style": { "preset": "lean" },
  "segment": {
    "custom/label": { "kind": "text", "text": "work" }
  },
  "layout": { "line2": { "left": ["custom/label", "char"] } }
}
```

`bingsu config check` accepts this as `config.json` (0 errors, 0 warnings), and the file list names it like any other:

```console
$ bingsu config check
selection: config.toml or config.json in the settings folder
files, in the order they apply:
  1. (built-in) (trusted)
  2. ~/.config/bingsu/config.json (trusted)
diagnostics: 0 error(s), 0 warning(s), 0 note(s)
result: valid
```

With a `config.toml` beside it, neither is read:

```console
$ bingsu config check
diagnostics: 1 error(s), 0 warning(s), 0 note(s)
E308: `~/.config/bingsu/config.json` and `~/.config/bingsu/config.toml` are both here
  why: one place holds one settings file, and bingsu does not pick one of two
  fix: keep one of the two files
result: invalid; the prompt keeps the last good settings
```

## Version: `bingsu --version`

`bingsu --version` says which build this is and whether the two programs beside it come from the same build. It starts
neither of them: it reads the build mark inside each file, the same mark `bingsu init` reads before it pins the
program.

```console
$ bingsu --version
bingsu 0.1.0-rc.1 (18b26c1e1d6ba89f7f95bc769c5eb8d3afa2c52d8a88a53074fb7eb44f9fa583, aarch64-apple-darwin, rustc 1.98.1 48a229cea)
bingsu-prompt: same build
bingsu-collect: same build
```

The first line is the version, the build identity (64 hex digits), the target and the compiler. Each of the next two
lines is one of:

| Status | Meaning |
| -- | -- |
| `same build` | The file has exactly one build mark and one role mark, the build is this one and the role matches the name |
| `differs (build ...)` | The marks are whole but belong to another build; the line shows that build's identity |
| `missing` | There is no file of that name beside `bingsu` |
| `symlink, not read` | The name is a link, which `init` does not accept either |
| `not a bingsu-prompt build` (or `bingsu-collect`) | The marks are absent, belong to another role, appear twice, are cut off, or disagree |
| `unreadable (reason)` | It is not a regular file, is over 64 MiB, or cannot be opened |

The exit code is 0 whatever the two lines say. `same build` looks at the marks only; it does not say that `init` will
pin the file, because `init` also checks the owner, the permission bits and that the folder is local.

## Current limits

- Command and language values appear on a later prompt, not the current one: after a command's first run, after a
  config edit, and after a version selection file (`.python-version`, `rust-toolchain.toml`) changes. Text and `env`
  values do not wait for a command to run.
- A shell environment over 64 KiB is not passed to the helper: command and `env` segments then show nothing. A
  variable named twice in the environment is not shown and not passed.
- Patterns are applied within about 250 ms per round. Past that, the round's remaining new results that need a
  pattern are published as failures, which show nothing and run again after 10 seconds; results without a pattern
  are kept, and re-matching stored lines waits for a later round. A config with many slow patterns can see some of
  them hidden in every round.
- Shells in terminals with different `TERM` share command values, so a command whose output depends on `TERM` can
  briefly show the value made in another terminal.
- A cached value can be reused within `cache` even if `PATH` now finds another program, a script's contents changed,
  or the folder at the same path was replaced. The default `cache` of 0 is not affected.
- A repository that has no `.git` entry (a bare repository, or one placed with `GIT_DIR`) does not keep its folders
  out of the cleaned `PATH` unless the folder collection found it.
- Built-in languages: a manager shim the rules cannot read (nodenv, goenv) hides the version; a pyenv version given
  as a prefix (`3.12`) without that exact installed folder is hidden. In very deep folders some languages may not be
  found within the collection's time limit.
- On macOS, commands do not run on a system without `AT_SYMLINK_NOFOLLOW_ANY`, and an executable you cannot read is
  not run.
- Each shell session that runs commands leaves a small lock file in the runtime folder, and on Linux, where the
  system allows cgroups, a cgroup folder. The cleanup after a later collection or command round removes, a few at a
  time, a lock made more than a day ago that no round holds at that moment (its session makes it again on its next
  round), with its empty cgroup folder when that folder is in the cleaning shell's own cgroup. A cgroup folder in
  another shell's cgroup (another terminal tab, a `tmux` server) stays until that cgroup ends. When bingsu cannot
  tell where its own cgroup is, it keeps the lock.
- `config check` can wait on a stalled network mount while it opens the programs a command segment would run.

## Group-writable files

Many systems create files and folders writable by your group (umask `002`). A config file, config folder or program
that your group can write is accepted when it is your primary group, has your name and `/etc/group` lists no other
members; otherwise only when every member of that group is you or root.
On a shared group, `config check` names a config file it refuses, and `config check --explain` shows a program it
would not run; remove the group write bit (`chmod g-w`) or change the group.
