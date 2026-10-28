#!/usr/bin/env python3
"""Time `init` adds to shell start (spec section 8, the "새 터미널 탭을 열 때" row).

The spec defines the row for a shell that finds a valid screen snapshot of the
same boot and settings context. So before any timing the first product prompt
publishes the snapshot (a normal `ok:none` record) and one `bingsu init` run
must finish without the cold-start notice. Then the same shell starts with an
rc that is empty and with an rc holding only the documented init line, in
alternating pairs under the controlled protocol (bench/protocol.py). The row
value is median(with) - median(without); p95 likewise. Run from the checkout:

  cargo build --release -p bingsu -p bingsu-collect
  python3 bench/init_cost.py --shell zsh --rounds 200 --out <outside the checkout>/init-zsh.json

Exit 2 and status BLOCKED when any prerequisite or sample is missing.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol

ROOT = Path(__file__).resolve().parents[1]
SHELLS = ("zsh", "bash", "fish")
VARIANTS = {"base": "without", "candidate": "with"}


def collector_product():
    spec = importlib.util.spec_from_file_location("init_cost_collector", Path(__file__).resolve().parent / "collector-product.py")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


M3B = collector_product()


def run_shell(command, **kwargs):
    return subprocess.run(command, capture_output=True, stdin=subprocess.DEVNULL, timeout=10, **kwargs)


def shell_version(shell, path):
    """bash older than 5.1 is below the supported minimum and is not timed."""
    if shell == "bash":
        text = run_shell([path, "-c", 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"']).stdout.decode().strip()
        major, minor = (int(n) for n in text.split("."))
        if (major, minor) < (5, 1):
            raise ValueError(f"bash {text} is older than the supported 5.1")
        return text
    return run_shell([path, "--version"]).stdout.decode(errors="replace").strip()


def init_line(shell, binary):
    """The README's init line for `shell`, with the absolute binary path."""
    quoted = shlex.quote(str(binary))
    if shell == "fish":
        return f"{quoted} init fish | source\n"
    return f'eval "$({quoted} init {shell})"\n'


def shell_commands(shell, path, directory, env):
    """Per variant: (argv, env). The variants differ only in the rc's content."""
    commands = {}
    for variant in ("without", "with"):
        home = directory / variant
        home.mkdir(mode=0o700)
        rc = home / {"zsh": ".zshrc", "bash": "bashrc", "fish": "config.fish"}[shell]
        if shell == "zsh":
            commands[variant] = ([path, "-i", "-c", "exit 0"], {**env, "ZDOTDIR": str(home)}, rc)
        elif shell == "bash":
            commands[variant] = ([path, "--noprofile", "--rcfile", str(rc), "-i", "-c", "exit 0"], env, rc)
        else:
            # XDG_CONFIG_HOME also names the settings root, so it stays the same
            # for both variants: fish reads no config and sources the rc instead.
            commands[variant] = ([path, "--no-config", "--init-command", "source " + shlex.quote(str(rc)),
                                  "-i", "-c", "exit 0"], env, rc)
    return commands


def time_shell(command, env, variant, expected_stderr):
    start = time.perf_counter_ns()
    result = run_shell(command, env=env)
    elapsed = time.perf_counter_ns() - start
    if result.returncode != 0 or result.stdout or result.stderr != expected_stderr:
        raise ValueError(f"{variant} shell start was not clean: exit {result.returncode}, "
                         f"stderr {result.stderr[:400]!r}")
    return elapsed


def valid_snapshot(binary, directory, shell):
    """First product prompt (normal ok:none record), then a warm init: no
    cold-start notice means a snapshot of this boot and context was ready."""
    command, env = M3B.prompt_context(binary, directory)
    init = run_shell([str(binary), "init", shell], env=env)
    if init.returncode != 0 or init.stderr or not init.stdout:
        raise ValueError("init did not find a valid snapshot: " + init.stderr.decode(errors="replace")[:400])
    return env


def measure(binary, shell, rounds, condition, shell_path=None):
    value = {"schema": 1, "milestone": "M3d", "row": "init 추가 시간", "shell": shell, "binary": str(binary),
             "status": "BLOCKED"}
    try:
        if shell not in SHELLS:
            raise ValueError("unknown shell")
        path = shell_path or shutil.which(shell)
        if not path:
            raise ValueError(f"{shell} not found")
        value["shell_path"], value["shell_version"] = path, shell_version(shell, path)
        (ROOT / "target").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="init-cost-", dir=ROOT / "target") as temp:
            temp = Path(temp)
            context = temp / "context"
            context.mkdir(mode=0o700)
            env = valid_snapshot(binary, context, shell)
            env = {**env, "HOME": str(context), "XDG_DATA_HOME": str(context / "data")}
            commands = shell_commands(shell, path, temp, env)
            value["rc"] = {}
            for variant, (_, _, rc) in commands.items():
                rc.write_text(init_line(shell, binary) if variant == "with" else "")
                value["rc"][variant] = rc.read_text()
            # Whatever the shell prints without init (bash without a terminal
            # warns about job control) is the only stderr allowed with it.
            argv, shell_env, _ = commands["without"]
            expected = run_shell(argv, env=shell_env).stderr
            def observe(name, _binary):
                variant = VARIANTS[name]
                argv, shell_env, _ = commands[variant]
                return dict(shell_start_ns=time_shell(argv, shell_env, variant, expected))
            paired = protocol.paired(binary, binary, rounds, condition, observe, required_metrics=("shell_start_ns",))
        value["paired"] = paired
        value["status"] = paired["status"]
        if paired["status"] != "OBSERVED":
            value["reason"] = paired.get("reason", "protocol blocked")
            return value
        summaries = {VARIANTS[n]: v["summary"]["shell_start_ns"] for n, v in paired["variants"].items()}
        value["variants"] = summaries
        value["init_added_ns"] = {"n": rounds, "p50": summaries["with"]["p50"] - summaries["without"]["p50"],
                                  "p95": summaries["with"]["p95"] - summaries["without"]["p95"],
                                  "basis": "median(with init) - median(without init); p95 likewise"}
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        value["status"], value["reason"] = "BLOCKED", str(error)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--shell", choices=SHELLS, required=True)
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/bingsu")
    parser.add_argument("--shell-path")
    parser.add_argument("--mode", choices=("gate", "experiment"), default="gate")
    parser.add_argument("--condition", type=json.loads)
    args = parser.parse_args()
    protocol.validate_output(args.out.resolve().parent)
    condition = {**protocol.DEFAULT, **(args.condition or {}), "mode": args.mode}
    value = measure(args.binary.resolve(), args.shell, args.rounds, condition, args.shell_path)
    protocol.write_output(args.out.resolve(), value)
    return 0 if value["status"] == "OBSERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
