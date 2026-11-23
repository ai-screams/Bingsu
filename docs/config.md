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

## Block shapes

`style.preset` chooses the whole shape of the blocks. Four keys under `[style]` each change one part of it and leave
the rest to the preset:

| Key | Values | What it changes |
| -- | -- | -- |
| `outer_end` | `none`, `triangle`, `round`, `slant`, `flat` | The end of each run of blocks at the edge of the screen |
| `separator` | `triangle`, `round`, `slant`, `flat`, `none`, `caps` | The joint between two blocks: a separator of that shape, nothing (`none`, the blocks touch), or the ends again (`caps`, every block repeats the outer and the inner end) |
| `inner_end` | the same as `outer_end` | The end of each run of blocks that faces the middle of the line |
| `gap` | `true`, `false` | One blank cell between blocks that have ends of their own |

A run of blocks is the segments on one side of a line. The right side mirrors the left: the outer end of the left
run is at the left edge of the screen, the outer end of the right run at the right edge, and both inner ends face the
fill between them.

```text
[outer end] dir [joint] git [inner end]      fill      [inner end] status [joint] duration [outer end]
^ left edge of the screen                                              right edge of the screen ^
```

The lines below were drawn by zsh at 60 columns with `icons = "unicode"`, `left = ["dir", "git"]` and
`right = ["status", "duration"]` on line 1 and the folder shortened to its repository name (`api`), after a command
that failed after 2.1 seconds:

```text
# no style keys: the triangle preset
 api ▸ main ▸                                   ◂ 1 ◂ 2.1s
# outer_end = "round"
◂ api ▸ main ▸                                 ◂ 1 ◂ 2.1s ▸
# inner_end = "none"
 api ▸ main                                       1 ◂ 2.1s
# outer_end = "round", separator = "none", inner_end = "round"
◂ api  main ▸                                   ◂ 1  2.1s ▸
```

A key you write lays over the preset's value, key by key, and that includes the joint: `preset = "pill"` with
`separator = "triangle"` draws exactly what `preset = "capsule"` draws. A template (`style.template`) replaces the
preset and all of these keys.

`separator = "caps"` repeats the outer and the inner end on every block, so each segment sits in a block of its own
and the blocks touch; `pill` and `diamond` draw that way. No built-in preset turns `gap` on: `gap = true` puts one
blank cell between such blocks:

```text
# preset = "pill"
◂ api ▸◂ main ▸                               ◂ 1 ▸◂ 2.1s ▸
# preset = "pill", gap = true
◂ api ▸ ◂ main ▸                             ◂ 1 ▸ ◂ 2.1s ▸
```

On blocks with a background, `gap` changes nothing with a separator shape or with `none`: a separator takes the
colors of the blocks on both sides, and a blank cell between them would cut that.

Without a background (`lean`, `bracket`) there are no ends: the end keys change nothing, and `bracket` puts `[` and
`]` around every segment except `char` on both sides whatever they say. There a separator shape draws one blank cell,
`none` and `caps` make the segments touch, and `gap = true` puts the blank cell back. Text that touches is not
reported, since a segment of your own may bring its own spacing:

```text
# preset = "lean"
api main                                             1 2.1s
# preset = "lean", separator = "none"
apimain                                               12.1s
# preset = "bracket"
[api][main]                                       [1][2.1s]
# preset = "bracket", gap = true
[api] [main]                                     [1] [2.1s]
```

These keys are read under `[style]` only, not under `[layout.when.NAME.style]`. They lay over a band's own preset as
well, so a band with `preset = "triangle"` under `separator = "caps"` at the top draws a mix of the two. A band's
template replaces them like any template: the built-in `narrow` band draws its own template under 60 columns, and
`bingsu config check` notes that (N501) when you write one of these keys.

In the `unicode` and `ascii` icon sets `triangle`, `round` and `slant` all draw as `◂` and `▸` (`<` and `>` in
`ascii`), so `pill` and `diamond`, or `triangle` and `slant`, look the same there; `flat` is a blank cell on the
block's color in every set. The keys take every value in any icon set, since one config may be used in several
terminals.

## Narrow terminals

A layout band (`[layout.when.NAME]`) is chosen for a range of widths. It takes the lines of `[layout]` unless it has
a template of its own, and a template draws in place of those lines. The built-in theme has one band, `narrow`, for
widths under 60, and it has its own template: there the prompt shows the host, the folder and git on the upper line,
and the duration and the prompt character below, whatever `[layout.line1]` and `[layout.line2]` say. Your lines are
used from 60 columns on, and `bingsu config check` notes the widths where they are not (N504).

To draw your own lines under 60 columns too, turn the band off. A width then goes to the first band that fits it, as
always, and to the default layout (your `[layout]` lines) only when no band does. With the built-in theme alone, no
other band fits, so your lines are drawn at every width:

```toml
[layout.when.narrow]
enabled = false
```

`enabled = false` turns off any band, the built-in one or one a file of yours adds. Bands are on by default, so write
`enabled` only to turn a band off. Only a file you trust sets it: in a theme or another shape-only file it is dropped
with a warning (W401), and a file that fails the safety check (which `bingsu config check` lists as "nothing in it
runs") neither turns a band off nor turns back on a band your trusted file turned off. A theme can still change which
band a width draws with `min_cols`, `max_cols`, `order` or a band of its own; that changes how the prompt looks, not
what runs. A band that is off still counts toward the limit of bands a config may have.

Or keep the band and give it a template of your own:

```toml
[layout.when.narrow.style]
template = "{dir} {git}{@nl}{char}"
```

`bingsu explain --width 40` shows what is drawn at a narrow width, and `bingsu config check` lists the bands and the
widths each one covers.

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

### Asking for a bingsu version: `requires`

A config can say which bingsu it needs with a top-level `requires`, for example `requires = ">=0.2"`. The only form
accepted is `>=MAJOR.MINOR` or `>=MAJOR.MINOR.PATCH`. When the running bingsu is older, `bingsu config check` reports E306
with the version asked for, and what happens next depends on the file's trust. A trusted file makes the whole read fail:
the prompt keeps drawing with the last good settings. A file that is trusted for colors and layout only is dropped on
its own, with a warning (W406), and the other files are applied. `bingsu config check --explain` shows which each file
is.

For example, `~/.config/bingsu/config.toml` extends `~/themes/theme.toml`, which is outside the config folder and has
`requires = ">=9.0"`. The check reports the error and the warning, the result is still `valid`, the exit code is 0, and
the theme is not in the list of files that apply (the rest of the settings are published):

```console
$ bingsu config check
settings folder: ~/.config/bingsu
selection: config.toml or config.json in the settings folder
files, in the order they apply:
  1. (built-in) (trusted)
  2. ~/.config/bingsu/config.toml (trusted)
diagnostics: 1 error(s), 1 warning(s), 0 note(s)
E306: this config requires bingsu >=9.0
  where: ~/themes/theme.toml:1:12
    via ~/.config/bingsu/config.toml
  why: the file asks for a newer bingsu
  fix: upgrade bingsu
  code: E306 (bingsu help E306)

W406: this shape-only file is not used: E306
  where: ~/themes/theme.toml:1:1
    via ~/.config/bingsu/config.toml
  why: a shape-only file that does not check is dropped alone
  fix: fix the file, or remove it from `extends`
  code: W406 (bingsu help W406)

widths (columns -> layout):
  0-59       narrow
  60+        (default layout)
result: valid; some files are left out (see above)
```

The running version is compared as SemVer says: a pre-release is lower than the release with the same numbers. So
`0.1.0-rc.1` does not satisfy `requires = ">=0.1.0"` (or `">=0.1"`), while `0.1.1-rc.1` does satisfy `">=0.1.0"`, and
`0.1.0` itself satisfies both.

On `0.1.0-rc.1`, `requires = ">=0.1.0"` (and `">=0.1"` the same way) is refused, while `">=0.0.9"` is accepted:

```console
$ bingsu config check
settings folder: ~/.config/bingsu
selection: config.toml or config.json in the settings folder
files, in the order they apply:
diagnostics: 1 error(s), 0 warning(s), 0 note(s)
E306: this config requires bingsu >=0.1.0
  where: ~/.config/bingsu/config.toml:1:12
  why: the file asks for a newer bingsu
  fix: upgrade bingsu
  code: E306 (bingsu help E306)

widths (columns -> layout):
  (not available while an error remains)
result: invalid; the prompt keeps the last good settings
```

With `requires = ">=0.0.9"` the same command ends with `result: valid`.
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

The outputs below were copied from real runs, with the home folder written as `~` (and the path of a development build
shortened). The `setup` editor screens were copied from a terminal model on Linux, without their colors, for an
account whose home is `/home/tester` on a machine named `box`; the editor shows the full path of the file. A line in parentheses in the `config edit` examples says what the editor did. One kind of line is left out of
the `config check`, `config edit` and `doctor` examples: in a shell that has not run `bingsu init`, each command also
prints on standard error a notice that it found its folders from the environment now, not from what `init` pinned.

### First settings: `bingsu setup`

`bingsu setup` makes a first settings file. It writes `$XDG_CONFIG_HOME/bingsu/config.toml` (folder 0700, file 0600)
only when there is no such file. The file starts with a `#:schema` line, so editors that read JSON Schema complete the
keys, and every line has a comment. It does not edit your shell startup file: it prints the line to add.

How it asks depends on where it runs:

| Where | What happens |
| -- | -- |
| A terminal of at least 40 columns and 16 rows, with `TERM` set and not `dumb` | The one-screen editor below |
| `--plain`, `TERM` unset, empty or `dumb`, a smaller window, or one whose size is unknown | Two questions on lines: can you see Nerd Font symbols, and the color mode |
| `--yes --icons nerd\|light\|unicode\|ascii --mode auto\|dark\|light`, on a terminal or not | Nothing is asked |
| No terminal, and any of the three missing | Nothing is written; the command names what is missing and exits 2 |

```console
$ bingsu setup --yes --icons nerd
bingsu setup: there is no terminal to ask, so it needs --mode too
usage: bingsu setup [--yes] [--plain] [--icons nerd|light|unicode|ascii] [--mode auto|dark|light]
```

`--icons` and `--mode` also answer their question in advance on a terminal: the editor starts from them, and the line
questions skip them. `--yes` skips the last question of the line questions (whether to write the file); the editor always
asks before it writes. The starter takes the `triangle` preset with `nerd` or `light` and `lean` with `unicode` or `ascii`.

The exit status is 0 when the file was written or was already there, 1 when it was refused or failed, 2 for a usage
mistake and 130 when you cancelled.

#### The editor

Each row of the editor is one choice, with the key it sets in the file:

| Key | Row | Values | Sets |
| -- | -- | -- | -- |
| `s` | style | `lean`, `triangle`, `pill`, `capsule`, `slant`, `diamond`, `block`, `bracket` | `style.preset` |
| `o` | outer | `none`, `triangle`, `round`, `slant`, `flat` | `style.outer_end` |
| `j` | joint | `triangle`, `round`, `slant`, `flat`, `none`, `caps` | `style.separator` |
| `n` | inner | `none`, `triangle`, `round`, `slant`, `flat` | `style.inner_end` |
| `g` | gap | `off`, `on` | `style.gap` |
| `i` | icons | `nerd`, `light`, `unicode`, `ascii` | `icons` |
| `c` | colors | `auto`, `dark`, `light` | `colors.mode` |
| `l` | lines | `2 lines`, `1 line` | `layout.line1.left` and `layout.line2.enabled` (one line puts `host`, `dir`, `git` and `char` on it) |

[Block shapes](#block-shapes) says what the outer, joint, inner and gap keys draw. The preview above the rows draws
the prompt with your folder and this machine's name and sample values for the rest (git, duration, status), at the
width of your window. In color, each row's value is drawn on a colored block. A value in brackets is chosen but has no
effect with the current style, and the note at the end of the row says why. `*` marks the rows the file will set, and
`>` the row the arrow keys change. This is an 80 × 24 window, without its colors:

```text
 bingsu setup                 /home/tester/.config/bingsu/config.toml  new file







 preview  80 columns, auto: dark (no COLORFGBG), sample values
box ~/projects/api main !1 ?1                                            2.1s 1
❯

>* s style     lean  triangle  pill  capsule  slant  diamond  block  bracket
   o outer    [none] triangle  round  slant  flat  no ends without a background
   j joint     triangle  round  slant [flat] none  caps  one blank cell
   n inner    [none] triangle  round  slant  flat  no ends without a background
   g gap      [off] on  only with none or caps
 * i icons     nerd  light  unicode  ascii
   c colors    auto  dark  light
   l lines     2 lines  1 line

 writes 2 keys: style.preset, icons

 s o j n g i c l change  arrows move  ? keys  u undo  enter save  q quit
```

<!-- PLACEHOLDER(opening): the empty rows under the title hold the opening picture once it ships; describe it here then, with `--no-motion` if that is its switch. -->
`?` lists the keys:

```text
 Keys

 s o j n g i c l    change that row (upper case: back)
 up down, tab       move between the rows
 left right, space  change the value
 1-9                pick a value
 backspace          remove this file's value
 u                  undo the last change (again: redo)
 r                  back to the start
 enter              save
 q                  quit
 ctrl-l             draw again
 esc                close this list
```

Under 80 columns each row shows only its value and its place among the values, here at 60 columns. Under 60 columns
the preview draws the built-in narrow layout and says so (`narrow layout under 60 columns`).

```text
>* s style     < triangle >  2/8
   o outer     < none >  1/5
   j joint     < triangle >  1/6
```

Enter shows what will be written and asks once more (Enter writes, Esc goes back, `q` quits). After `s` (to
`triangle`) and Enter:

```text
 Write /home/tester/.config/bingsu/config.toml?

   style.preset = "triangle"
   icons = "unicode"
```

After the file is written, the terminal is back as it was and the editor prints:

```text
bingsu: wrote ~/.config/bingsu/config.toml
Add this to your shell's startup file to start bingsu:
eval "$(bingsu init zsh)"
bingsu: the new look shows once your shell loads bingsu
Line ends look off? `bingsu doctor` checks the character widths.
```

`q` leaves without writing (`bingsu: nothing written.` and the startup line, exit 0), and Ctrl-C cancels
(`bingsu: cancelled, nothing written.`, exit 130). Ctrl-Z suspends the editor like any program; `fg` draws it again.

#### The line questions

```console
$ bingsu setup --plain
These should look like three small symbols, not boxes or blanks:
      ❯
Can you see them? [Y/n] y
Color mode (the terminal looks dark): [a]uto, [d]ark or [l]ight? [d]
Write ~/.config/bingsu/config.toml? [Y/n]
bingsu: wrote ~/.config/bingsu/config.toml
Add this to your shell's startup file to start bingsu:
eval "$(bingsu init zsh)"
bingsu: the new look shows once your shell loads bingsu
Line ends look off? `bingsu doctor` checks the character widths.
```

Answering "no" to the symbols question writes `icons = "unicode"` and `preset = "lean"`.

#### The background color

To tell a dark terminal from a light one, `setup` asks the terminal for its background color (OSC 11) and waits 200 ms
for the answer. Without an answer in time the mode question says `the terminal did not say` and offers `auto`. An
answer that comes later is read and dropped, so it does not show up as typed text in your shell; an answer the terminal
sent in time still counts when `bingsu` itself, on a busy machine, comes to read it late.

#### When a file is there

A settings file that is already there (the one `config use` chose, else `config.toml` or `config.json` in the settings
folder) is never changed. On a terminal that can draw it, the editor opens on that file: the title says `exists: not
changed`, each row starts at the value the settings have now, and the line under the rows counts what you changed
(`no changes`, `changes 2 keys: style.preset, colors.mode`). Enter shows each changed key with its value now and the
one chosen, and the line to put in the file:

```text
 config.toml is already there; bingsu does not change it.

 style.preset: "triangle" now, "pill" chosen
   under [style]: preset = "pill"
 colors.mode: "dark" now, "light" chosen
   under [colors]: mode = "light"
```

Enter again prints the list and quits (Esc goes back). The list goes to standard error, and standard output gets only
the startup line, as on every path of `setup`:

```text
bingsu: config.toml is already there; bingsu does not change it.

style.preset: "triangle" now, "pill" chosen
  under [style]: preset = "pill"
colors.mode: "dark" now, "light" chosen
  under [colors]: mode = "light"
Edit it yourself: bingsu config edit
Add this to your shell's startup file to start bingsu:
eval "$(bingsu init zsh)"
```

With nothing changed, Enter says `It already has the choices you made.` A later file that sets the same key wins over
the change you would make, and the row and the list say so:

```text
   c colors    auto [dark] light  overridden by /home/tester/.config/bingsu/...
```

```text
colors.mode: "dark" now, "light" chosen
  under [colors]: mode = "light"
  /home/tester/.config/bingsu/config.local.toml sets this too, and wins.
```

The preview follows your picks in a TOML file. For a JSON or YAML file, or a TOML file that cannot be edited in
place, it keeps drawing the settings as they are and says so (`not updated for this format`), and the list names the
key to set (`style.preset: "pill"` for JSON).
<!-- PLACEHOLDER(new-file not-loading fix): when no settings file exists but the settings do not load (a `conf.d` file or `config.local.toml` does not parse), the editor does not open; describe the message when it ships, with a real run. -->

The line questions and the arguments list how the file differs from the starter:

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

#### If the terminal is left raw

While the editor is open the terminal is in raw mode, on the alternate screen, with the cursor hidden and bracketed
paste on. Saving, `q`, Ctrl-C, SIGINT, SIGTERM and SIGHUP put all of it back (the last three then end the command with that
signal, 130, 143 or 129 in a shell). A signal bingsu does not handle (SIGKILL, SIGQUIT, SIGSEGV) ends
it at once, and the terminal stays as the editor left it: what you type does not show, and the editor's screen stays.
Type `reset` and press Enter: it puts back the line settings and resets the screen. `stty sane` puts back only the line
settings, not the screen.

### Editing: `bingsu config edit`

`bingsu config edit` opens your settings file in your editor, then runs `config check` on what you saved and, when it is
valid, applies it the way `reload` does. A file that is not valid is not applied: the prompt keeps drawing with the
last good settings, and the command exits 1 and says so.

It opens the file `config use` picked, or else the one file of the settings place: `config.toml` or `config.json`, whichever
is there. With both there it opens neither, points at E308 and exits 1. It does not make a file: when there is none it
points to `bingsu setup` and exits 1.

The editor is `$VISUAL`, or `$EDITOR` when `$VISUAL` is unset or empty; with neither set the command stops with an
example and does not try a default. The value is not given to a shell. It is split at spaces. Single quotes keep
everything inside them. Inside double quotes everything is kept except `$` and a backquote, which are refused. Outside
quotes `$`, a backquote, `;`, `&`, `|`, `<`, `>`, `(` and `)` are refused unless a backslash comes right before them (the
backslash is dropped and the character stays plain text); to run something that needs them, point the variable at a
script. `~` and `*` are not expanded. A first word with a `/` must be an absolute path; otherwise it is
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
widths (columns -> layout):
  0-59       narrow
  60+        (default layout)
result: valid
bingsu: edited; new settings published (generation 1)
```

After a save that is not valid, the check says so, nothing is published and the exit code is 1:

```console
$ bingsu config edit
(the editor opens the file; you save `colr = 1`)
settings folder: ~/.config/bingsu
selection: config.toml or config.json in the settings folder
files, in the order they apply:
  1. (built-in) (trusted)
  2. ~/.config/bingsu/config.toml (trusted)
diagnostics: 1 error(s), 0 warning(s), 0 note(s)
E201: unknown key `colr`
  where: ~/.config/bingsu/config.toml:1:1
  why: unknown keys are errors, so a typo is never silently ignored
  fix: check the key name
  code: E201 (bingsu help E201)

widths (columns -> layout):
  0-59       narrow
  60+        (default layout)
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
| `presets` | The eight style presets: `lean`, `triangle`, `pill`, `capsule`, `slant`, `diamond`, `block`, `bracket` |
| `segments` | A built-in segment and the color role it draws with |
| `flavors` | The color flavors |
| `roles` | A color role and the palette colors it points to in dark and in light mode |
| `shorteners` | The ways `segment.dir.shorten` can shorten a path |
| `icons` | An icon name and its glyph in the `nerd`, `light`, `unicode` and `ascii` sets |

`bingsu list presets --preview` draws every preset once as the upper line of the default layout, with your current
folder; the other values (a branch, a duration, the time) are samples. On a terminal it uses color unless `NO_COLOR` is
set, and `--icons nerd|light|unicode|ascii` picks the icon set (`unicode` by default). The name takes 9 columns and the
line is drawn for `max(60, W - 9)` cells, where W is the width `bingsu explain` uses without `--width`: `COLUMNS`, else
the width of the terminal the output goes to, else 80 (71 cells through a pipe). A line leaves the last cell empty, so
it is never shorter than 68 columns with the name, and in a terminal narrower than 68 columns it is wider than the
terminal. It starts no command, reads no config and writes nothing.

```console
$ bingsu list presets --preview --icons unicode
lean     ~/projects/api main                                         2.3s 12:34
triangle  ~/projects/api ▸ main ▸                               ◂ 2.3s ◂ 12:34 
pill     ◂ ~/projects/api ▸◂ main ▸                           ◂ 2.3s ▸◂ 12:34 ▸
capsule  ◂ ~/projects/api ▸ main ▸                             ◂ 2.3s ◂ 12:34 ▸
slant     ~/projects/api ▸ main ▸                               ◂ 2.3s ◂ 12:34 
diamond  ◂ ~/projects/api ▸◂ main ▸                           ◂ 2.3s ▸◂ 12:34 ▸
block     ~/projects/api  main                                     2.3s  12:34 
bracket  [~/projects/api][main]                                   [2.3s][12:34]
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
$ bingsu doctor | cat
bingsu doctor
  ok      executable      ~/src/Bingsu/target/debug/bingsu: only you and root can change it or the folders above it
  skipped bingsu on PATH  no bingsu is found on PATH here; the hook uses the path pinned by init
  warn    pinned folders  init has not run in this shell; commands read the current environment (W603; bingsu help W603)
  warn    one build       bingsu-prompt beside bingsu is not from this build or fails the safety check (W605; bingsu help W605)
  unknown shell           shell version not confirmed: no shell passed it; run the shell function bingsu_doctor in your shell to check this
  unknown hook version    hook compatibility not confirmed: no shell passed it; run the shell function bingsu_doctor in your shell to check this
  unknown hook order      hook order not confirmed: no shell passed it; run the shell function bingsu_doctor in your shell to check this
  unknown envelope        the last envelope not confirmed: no shell passed it; run the shell function bingsu_doctor in your shell to check this
  unknown breaker         the collection breaker not confirmed: no shell passed it; run the shell function bingsu_doctor in your shell to check this
  skipped seccomp         this platform has no seccomp
  ok      settings        the settings check out (0 warning(s))
  skipped terminal width  standard output is not a terminal; `--terminal` asks the controlling terminal anyway
  skipped background      standard output is not a terminal; `--terminal` asks the controlling terminal anyway
result: 2 ok, 2 warning(s), 0 failed, 5 unknown, 4 skipped
```

This run is a development build outside a shell that ran `bingsu init`, with the output going to a pipe. In your own
shell, run `bingsu_doctor` (a zsh function that `bingsu init zsh` defines) instead of `bingsu doctor`: it hands the check
the facts only the shell knows, so the five `unknown` rows get an answer. The rows `terminal width` and `background` are
`skipped` here only because the output is a pipe (see [Terminal rows](#terminal-rows)).

| Check | What it looks at |
| -- | -- |
| `executable` | The path bingsu runs from, every link on the way and every folder above it: only you and root (or a group with no other member) may change them |
| `bingsu on PATH` | Whether the `bingsu` your shell finds on `PATH` is the one running now |
| `pinned folders` | The folders `bingsu init` pinned in this shell. The runtime folder is checked for being replaced (a different folder at the same path) or removed. The settings, state and log folders get the safety check the helper uses (owner, permissions, links); a state or log folder that does not exist yet is accepted |
| `one build` | That `bingsu`, `bingsu-prompt` and `bingsu-collect` come from the same build (read from the files, not by running them) |
| `shell` | The shell and its version, as the shell reports them through `bingsu_doctor`. Without it the row is `unknown`: bingsu never guesses a version from a path or a folder name. A zsh older than 5.8 is a warning (W611) |
| `hook version` | Whether the hook of your shell asks for a record version this bingsu reads (E608 when it does not: open a new shell or run `bingsu init` again in it) |
| `hook order` | That the hook functions stand in the order bingsu needs: the capture hook first and the install hook last in `precmd_functions`, each once (W609) |
| `envelope` | That the last words the hook gave the prompt call have the fields the prompt reads, in order (W610). It also carries the brightness hint (`COLORFGBG`) the prompt got, which the `background` row compares |
| `breaker` | Whether this shell session has stopped collecting git and folder facts in the folder you are in (W612): the same mount missed its deadline three times in a row, so for up to five minutes the prompt draws without those facts instead of waiting on it. The folder is the shell's `PWD`; it is never opened, since a stuck mount is just when the breaker is on. No breaker record, a wait that is over, or a record from another boot is not a warning |
| `seccomp` | Whether the kernel supports seccomp (Linux; the example above is from macOS, where it is skipped). It does not check whether the prompt's own filter was installed |
| `settings` | A summary of `config check`; a settings folder that fails the safety check is a `fail` |
| `terminal width` | How many cells the terminal moves the cursor for probe characters, against `width.ambiguous` and `width.emoji` ([below](#terminal-rows)) |
| `background` | Whether the terminal's background is light or dark, against what the prompt draws for ([below](#terminal-rows)) |

The exit code is 1 when any check fails; warnings, `unknown` and `skipped` give 0. `--format json` prints the same
rows as a JSON document. `--evidence-stdin` is what the shell function uses to pass its record; run the function, not that
flag.

#### Terminal rows

The last two rows ask the terminal. They write a few characters to the screen, read the answers back and clear the line,
so they run only when standard output is a terminal, or when you pass `--terminal`, which asks the controlling terminal
(`/dev/tty`) even when the output goes to a pipe. Without a terminal, or when `bingsu` is not the job in the foreground,
both rows are `skipped`. A terminal that does not answer within about 0.2 seconds gives `unknown`, never a warning.
Ctrl-C (the key, read as a character) stops the run with exit code 130 after the terminal is back in its normal state; a signal such as SIGTERM restores the terminal and ends the run by that signal (exit status 128 plus the signal, for example 143). No table is printed in either case.

| Row | What it measures | A warning means |
| -- | -- | -- |
| `terminal width` | Writes twelve probe characters one after the other (ASCII, a Hangul syllable, three East Asian ambiguous characters, an emoji, an emoji made by U+FE0F, a joined emoji, a flag, a letter with a combining mark, two Nerd Font glyphs) and asks the cursor position after each. It runs when the terminal is at least 40 columns wide | The terminal draws something in another number of cells than `width.ambiguous` and `width.emoji` say (W613). The row names the characters and the values the terminal fits |
| `background` | Asks for the background color (OSC 11) and compares light or dark with what the prompt picks. It runs only when `colors.mode` is `auto`; with `dark` or `light` set, the prompt does not guess and the row is `skipped` | The prompt would draw for the other brightness (W614). Set `colors.mode` to `dark` or `light` |

What each status means on these rows:

| Status | Meaning |
| -- | -- |
| `ok` | The terminal drew every probe in the number of cells the settings say (`terminal width`), or its background is the brightness the prompt draws for (`background`) |
| `warn` | W613 for width, W614 for background; `bingsu help W613` and `bingsu help W614` say what to set |
| `unknown` | The terminal did not answer in time, answered with something that is not a cursor position, or the cursor left the line while measuring; or the control characters moved the cursor by an unexpected number of cells, so the measurement is not trusted; or the settings could not be read |
| `skipped` | Nothing was asked. For both rows: standard output is not a terminal (and `--terminal` is not given), or there is no controlling terminal. For `terminal width` alone: the terminal is under 40 columns wide. For `background` alone: `colors.mode` is not `auto`. A narrow terminal does not stop the background question |

The usage is `bingsu doctor [--format json|text] [--terminal]`; the two options may come in either order, once each.

With `--format json` a row that finished its measurement carries a `details` object: the measured cells per probe and the
values that fit (`probes`, `recommended`, `inside_tmux`) for `terminal width`, or the two brightnesses (`terminal`,
`prompt`, `colors_mode`) for `background`. A skipped row, or a measurement that got no usable answer, has no `details`.
Inside `tmux` the answers come from `tmux`, which may differ from the outer terminal; the width row says so.

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

`bingsu config check` accepts this as `config.json`, and the file list names it like any other. The note (N504) is not
an error: at narrow widths the band draws its own template in place of the line the file writes (`bingsu help N504`).

```console
$ bingsu config check
settings folder: ~/.config/bingsu
selection: config.toml or config.json in the settings folder
files, in the order they apply:
  1. (built-in) (trusted)
  2. ~/.config/bingsu/config.json (trusted)
diagnostics: 0 error(s), 0 warning(s), 1 note(s)
N504: at widths 0-59 the band `narrow` draws its own template in place of layout.line2
  where: ~/.config/bingsu/config.json:8:34
  why: a band's template replaces the layout lines the band would take from `[layout]`
  fix: to draw your segments at those widths too, write `layout.when.narrow.style.template` yourself
  code: N504 (bingsu help N504)

widths (columns -> layout):
  0-59       narrow
  60+        (default layout)
result: valid
```

With a `config.toml` beside it, neither is read:

```console
$ bingsu config check
settings folder: ~/.config/bingsu
selection: config.toml or config.json in the settings folder
files, in the order they apply:
diagnostics: 1 error(s), 0 warning(s), 0 note(s)
E308: `~/.config/bingsu/config.json` and `~/.config/bingsu/config.toml` are both here
  where: ~/.config/bingsu/config.json:1:1
  why: one place holds one settings file, and bingsu does not pick one of two
  fix: keep one of the two files
  code: E308 (bingsu help E308)

widths (columns -> layout):
  (not available while an error remains)
result: invalid; the prompt keeps the last good settings
```

## Version: `bingsu --version`

`bingsu --version` says which build this is and whether the two programs beside it come from the same build. It starts
neither of them: it reads the build mark inside each file, the same mark `bingsu init` reads before it pins the
program.

```console
$ bingsu --version
bingsu 0.1.0-rc.1 (9c9a576bb41400e37390cce6970723f6703ffaacbae05025db024696f90fb890, aarch64-apple-darwin, rustc 1.98.1 48a229cea)
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
