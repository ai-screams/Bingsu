#!/usr/bin/env python3
"""Shell-side time gate (spec section 8): Enter to the next prompt in a real
interactive zsh, with bingsu replaced by a stand-in that prints a fixed record,
so the hooks are what is timed. The base and candidate hooks alternate in the
controlled protocol (bench/protocol.py), blocks it does not admit stay in the
output, and a verdict compares candidate and base. Absolute time is recorded
only. Rows: `prompt` (a record with no transient) and `transient-enter`.

The CLI measures, or with --measurement judges a measurement it wrote.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import protocol
import size_gate

METRIC = "enter_ns"
EDITOR_ON = b"\x1b[?2004h"  # the line editor is back
TIMEOUT = 10
RECORDS = {
    "prompt": ("LONG> ", "", ""),
    "transient-enter": ("LONG> ", "T> ", "UPPER"),
}


def record(left, transient, upper):
    fields = ["B1", "8", left, "", transient, "", "", "", upper, "ok:none"]
    return "\037".join(fields) + "\036"


def stand_in(text):
    """A stand-in that only prints: a shell builtin, so it adds one exec and no more."""
    octal = "".join(f"\\{ord(c):03o}" for c in text)
    return f"#!/bin/sh\nprintf '{octal}'\n"


class Session:
    """zsh -f -i in a PTY with the hooks of one binary and a fixed record."""

    def __init__(self, binary, case, root):
        folder = root / "bin"
        folder.mkdir(parents=True)
        exe = folder / "bingsu"
        exe.symlink_to(Path(binary).resolve())
        env = {"PATH": os.environ["PATH"], "TERM": "xterm-256color", "HOME": str(root), "LC_ALL": "C.UTF-8",
               **{f"XDG_{n}_HOME": str(root / n.lower()) for n in ("CONFIG", "STATE", "CACHE")},
               "XDG_RUNTIME_DIR": str(root / "run")}
        init = subprocess.run([str(exe), "init", "zsh"], env=env, capture_output=True, timeout=30)
        if init.returncode != 0 or not init.stdout:
            raise ValueError("init failed: " + init.stderr[-200:].decode(errors="replace"))
        (root / "init.zsh").write_bytes(init.stdout)
        fake = root / "fake"
        fake.write_text(stand_in(record(*RECORDS[case])))
        fake.chmod(0o700)
        exe.unlink()
        exe.symlink_to(fake)
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
        self.shell = subprocess.Popen(["zsh", "-f", "-i"], stdin=slave, stdout=slave, stderr=slave, env=env, cwd=root,
                                      start_new_session=True, close_fds=True,
                                      preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        os.close(slave)
        try:
            self.read_prompt()
            os.write(self.master, f'source "{root / "init.zsh"}"\r'.encode())
            self.read_prompt()
            self.enter()
            self.seen = self.output
        except (OSError, ValueError):
            self.close()
            raise

    def read_until(self, done):
        data = b""
        deadline = time.monotonic() + TIMEOUT
        while not done(data):
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.master], [], [], left)[0]:
                raise ValueError("no prompt in time")
            try:
                data += os.read(self.master, 65536)
            except OSError as error:
                raise ValueError("the shell ended") from error
        return data

    def read_prompt(self):
        return self.read_until(lambda data: EDITOR_ON in data)

    def enter(self):
        start = time.perf_counter_ns()
        os.write(self.master, b"\r")
        self.output = self.read_prompt()
        return time.perf_counter_ns() - start

    def close(self):
        try:
            os.killpg(self.shell.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.shell.wait(timeout=10)
        os.close(self.master)


def measure_case(case, base, candidate, rounds, condition):
    root = Path(tempfile.mkdtemp(prefix="bingsu-shell-gate-"))
    sessions = {}
    try:
        for name, binary in (("base", base), ("candidate", candidate)):
            sessions[name] = Session(binary, case, root / name)
        drawn = {name: b"LONG> " in s.seen for name, s in sessions.items()}
        if not all(drawn.values()):
            raise ValueError("the hooks did not draw the record: " + str(drawn))
        transient = {name: b"T> " in s.seen for name, s in sessions.items()}
        # A hook that skips the work would pass on the time it saved.
        if case == "transient-enter" and not all(transient.values()):
            raise ValueError("no transient drawn: " + str(transient))
        result = protocol.paired(base, candidate, rounds, condition, lambda name, _: {METRIC: sessions[name].enter()},
                                 required_metrics=(METRIC,))
        return {**result, "transient_drawn": transient, "shell": subprocess.run(["zsh", "--version"], capture_output=True, text=True).stdout.strip()}
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return dict(status="BLOCKED", reason=str(error), variants={}, blocks=[])
    finally:
        for session in sessions.values():
            session.close()
        shutil.rmtree(root, ignore_errors=True)


def measure(base, candidate, rounds, condition):
    cases = {case: measure_case(case, base, candidate, rounds, condition) for case in RECORDS}
    return dict(schema=1, metric=METRIC, cases=cases,
                status="OBSERVED" if all(c.get("status") == "OBSERVED" for c in cases.values()) else "BLOCKED")


def verdict(measurement, threshold):
    """One row per case; a missing case is BLOCKED, never PASS."""
    cases = measurement.get("cases") if isinstance(measurement, dict) else None
    cases = cases if isinstance(cases, dict) else {}
    rows = {case: size_gate.relative_gate(cases.get(case), METRIC, threshold, target_ms=None) for case in RECORDS}
    return dict(status=size_gate.aggregate(list(rows.values())), rows=rows)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--base")
    p.add_argument("--candidate")
    p.add_argument("--rounds", type=int, default=200)
    p.add_argument("--admission", choices=("default", "ci-r2"), default="default")
    p.add_argument("--measurement", type=Path, help="judge this output instead of measuring")
    p.add_argument("--ratio-p50", type=float)
    p.add_argument("--ratio-p95", type=float)
    p.add_argument("--enforce", action="store_true", help="exit 1 unless the verdict is PASS")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    if args.measurement is None:
        condition = {**protocol.DEFAULT, "admission": args.admission}
        result = measure(args.base, args.candidate, args.rounds, condition)
        protocol.write_output(args.out, result)
        return 0 if result["status"] == "OBSERVED" else 2
    threshold = None if args.ratio_p50 is None or args.ratio_p95 is None else (args.ratio_p50, args.ratio_p95)
    try:
        measurement = json.loads(args.measurement.read_text())
    except (OSError, ValueError):
        measurement = {}
    result = verdict(measurement, threshold)
    protocol.write_output(args.out, result)
    print(json.dumps({"status": result["status"], "rows": {
        case: {k: row.get(k) for k in ("status", "ratio_p50", "ratio_p95", "reason", "absolute")}
        for case, row in result["rows"].items()}}, indent=2))
    return 1 if args.enforce and result["status"] != "PASS" else 0


if __name__ == "__main__":
    sys.exit(main())
