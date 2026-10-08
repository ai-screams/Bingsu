#!/usr/bin/env python3
"""Baseline (record only) of one install-hook run per shell, with the fake
binary printing a fixed record (spec section 8: shell-side time, frame in M1)."""
import json
import pathlib
import platform
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/shell"))
from conftest import SHELL_CMD, Install, minimal_record, trusted_env  # noqa: E402

LOOP = {
    "zsh": b"zmodload zsh/datetime; for i in {1..220}; do t=$EPOCHREALTIME; _bingsu_install; print -r -- $(( (EPOCHREALTIME - t) * 1e9 )); done\n",
    "bash": b"for i in $(seq 220); do t=${EPOCHREALTIME/[.,]/}; _bingsu_install; n=${EPOCHREALTIME/[.,]/}; echo $(( (n - t) * 1000 )); done\n",
}
# fish has no sub-millisecond clock without an external command (BSD date
# has no %N), so fish is timed from outside: (T(220 runs) - T(20 runs)) / 200.
FISH_LOOP = "for i in (seq {n}); fish_prompt >/dev/null; end\n"
# The in-shell clock the loops read. Without it (bash before 5, or a sh
# standing in for bash) both reads are empty and every sample is 0 ns, which
# would pass for a measurement.
CLOCK = {
    "zsh": "zmodload zsh/datetime && [[ $EPOCHREALTIME == <->[.,]<-> ]]",
    "bash": '(( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 501 )) && [[ $EPOCHREALTIME =~ ^[0-9]+[.,][0-9]+$ ]]',
}


OS = {"Darwin": "macos", "Linux": "linux"}[platform.system()]


def row(shell, **kw):
    return json.dumps({"matrix": "hook", "row": shell, "os": OS, **kw})


def run(shell, f, env):
    """Runs one loop script; an exit other than 0 is an error (its samples
    are not a measurement)."""
    r = subprocess.run(SHELL_CMD[shell] + [str(f)], env=env, capture_output=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"{shell} exited {r.returncode}: {r.stderr[-200:]!r}")
    return r.stdout


def check_clock(shell, env):
    """RuntimeError unless `shell` (as SHELL_CMD runs it) has the clock."""
    if shell not in CLOCK:
        return
    r = subprocess.run(SHELL_CMD[shell] + ["-c", CLOCK[shell]], env=env, capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"{shell} has no EPOCHREALTIME clock (zsh/datetime, or bash 5.1+)")


def fish_mean_ns(script_head, env, base):
    times = {}
    for n in (20, 220):
        f = base / f"loop{n}.fish"
        f.write_bytes(script_head + b"\n" + FISH_LOOP.format(n=n).encode())
        t = time.monotonic_ns()
        run("fish", f, env)
        times[n] = time.monotonic_ns() - t
    return (times[220] - times[20]) // 200


def nearest_rank(sorted_vals, p):
    return sorted_vals[max(1, -(-p * len(sorted_vals) // 100)) - 1]


def measure(shell, base):
    env = trusted_env(base)
    check_clock(shell, env)
    inst = Install(base)
    script = inst.init(shell, env)
    inst.use_fake(minimal_record())
    if shell == "fish":
        return row("fish", n=200, mean_ns=fish_mean_ns(script, env, base), timed="outside, mean")
    f = base / f"s.{shell}"
    f.write_bytes(script + b"\n" + LOOP[shell])
    ns = sorted(int(float(x)) for x in run(shell, f, env).split()[20:])
    if len(ns) != 200:
        raise RuntimeError(f"{shell}: {len(ns)} samples, expected 200")
    return row(shell, n=len(ns), median_ns=nearest_rank(ns, 50), p95_ns=nearest_rank(ns, 95))


def main():
    for shell in sys.argv[1:] or ["zsh", "fish"]:
        with tempfile.TemporaryDirectory() as td:
            try:
                print(measure(shell, pathlib.Path(td)))
            except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as e:
                print(row(shell, na=str(e)))


if __name__ == "__main__":
    main()
