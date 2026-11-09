# Writing a command segment for others

This page is for people who write a `kind = "command"` segment for someone else to use: a teammate, or anyone who
copies it from a README. The rules themselves live in [config.md](config.md); this page says what they mean for the
program you hand over.

The person who uses your segment reads it and puts it in a file they trust (see
[Where segments come from](config.md#where-segments-come-from)). Make that review short: one program, a few
arguments, no shell.

bingsu has no plugin system yet. Writing to the constraints below now keeps a segment ready to run the same way if
one comes; this page promises nothing about how plugins will run.

## What your program gets

| | What it is |
| -- | -- |
| Arguments | Exactly the `command` array, as separate arguments; no shell reads them ([`command`](config.md#command)) |
| Working folder | An empty private folder by default, not the shell's folder (`cwd`, [`command`](config.md#command)) |
| Environment | A short keep list and the names in `env_allow` ([How commands run](config.md#how-commands-run)) |
| Standard input | Empty: reading it ends at once |
| Standard error | Discarded |
| Time | 200 ms by default; `timeout` raises it to at most 1 second |

The program runs in the background, after a prompt is drawn, alongside the other segments of that round.

## What it must give back

| | What happens |
| -- | -- |
| The value | The first line of standard output; anything after the first newline is ignored |
| Size | At most 4 KB of output is read; the value is cut to 64 terminal cells, ending with `…` |
| Control characters | Removed. An escape code loses its ESC byte and the rest shows as text, so print plain text |
| An empty first line | Nothing is shown |
| A nonzero exit or a timeout | Nothing is shown, even if a line was printed; the command runs again after 10 seconds |
| When it shows | From a later prompt, once the round that ran it has finished |

## Designing it

- Finish fast. A program that needs more than about 200 ms should get a `cache` (for example `cache = "300s"`), so
  it does not run before every prompt. `cache` takes `ms` or `s`, up to `3600s`.
- Print nothing, or exit nonzero, when there is nothing to show. A placeholder such as `none` or `-` takes space in
  every prompt.
- Pick the value with [`match`](config.md#match) instead of piping through `grep`, `sed` or `awk`: there is no shell.
- Ask for the shell's folder (`cwd = "untrusted-current"`) only when the value is about that folder. Files there,
  such as a cloned repository's, can change what the program does, and `config check` says so.
- Name every variable the program needs in `env_allow`, and only those. Loader and language startup variables cannot
  be passed.
- Keep the output the same for any `TERM`: shells in different terminals share one value.
- Avoid scripts that start with `#!/usr/bin/env`, and setuid, setgid or capability programs: bingsu does not run
  them.
- Do not use `shell` and `unsafe_shell` in a segment you hand over.

An example that passes `bingsu config check` with no warning:

```toml
[segment."custom/email"]
kind = "command"
command = ["git", "config", "--global", "user.email"]
cache = "300s"

[layout.line1]
left = ["dir", "custom/email"]
```

## Before you hand it over

Run your program by hand the way bingsu runs it, from an empty folder with a short environment and no input:

```sh
cd "$(mktemp -d)" && env -i HOME="$HOME" PATH=/usr/bin:/bin TERM=dumb git config --global user.email < /dev/null
```

Then check each line:

- `bingsu config check --explain` lists the segment as `runs`, with no warning or error.
- `--explain` shows the `executable` you expect, found on the cleaned `PATH`.
- Run by hand as above, the program prints its value on the first line and exits 0.
- Piped through `cat -v`, that line shows no `^[` and no `^I`.
- With nothing to show, it prints an empty first line or exits nonzero.
- Timed with `time`, it finishes well within its `timeout` (200 ms by default), or the segment has a `cache`.
- Run with `TERM=dumb` and with `TERM=xterm-256color`, it prints the same line.
