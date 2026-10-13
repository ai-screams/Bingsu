#!/usr/bin/env python3
"""PTY session-stall probe (Task R0). Runs the bodies of the PTY tests that
stalled, many rounds, and records every stall. Two things can be swapped to
tell causes apart:

  --product  what answers the hooks' `bingsu prompt` call: the real binary,
             a shell function named like the pinned path (bash only), the
             test double fake_bingsu.sh, or no bingsu init at all
  --driver   the existing pty_session.Session, or a minimal driver whose
             reader thread drains the PTY all the time

A stall is a wait that runs past --timeout (pexpect TIMEOUT or EOF). For
each stall the round folder gets the screen, the process tree at the stall
and 20 s later, stacks (macOS `sample`), whether one more typed character
is echoed, the tty settings and the transcript. Nothing is retried.

Exit status: 0 when every round is ok or n/a, 1 when any round stalled or
failed, 2 on bad arguments."""
import argparse
import io
import os
import pathlib
import random
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
SHELL_DIR = HERE.parent
ROOT = SHELL_DIR.parents[1]
sys.path[:0] = [str(SHELL_DIR), str(ROOT / "tests/hostile")]

import pexpect  # noqa: E402
import pyte  # noqa: E402

import conftest  # noqa: E402
import matrix  # noqa: E402
import pty_session  # noqa: E402
import test_hostile_matrix as thm  # noqa: E402  (record, drawn, MINIMAL and the NUL pins, as the test uses them)
from pty_session import ANSWERS, ARGV, QUERIES, sends_prompt_end, visible  # noqa: E402

CASES = ("bash-nonzero", "fish-nothing", "fish-nul")
FISH_LINES = ("", "   ", "# c", ";")
COLS = 200
SEED = re.compile(r"[0-9]{1,9}")


class Stall(Exception):
    """A wait ran past the timeout, or the shell ended early."""


def spawn_argv(shell, trace_file):
    """Program and arguments for `shell`; under strace the shell is strace's
    child (no attach)."""
    if trace_file is None:
        return shell, ARGV[shell]
    return "strace", ["-f", "-tt", "-o", str(trace_file), shell, *ARGV[shell]]


class SessionDriver(pty_session.Session):
    """The PTY tests' own driver, optionally under strace."""

    def __init__(self, shell, env, cols, trace_file=None, owner=None):
        real = pexpect.spawn

        def spawn(cmd, args, **kw):
            prog, argv = spawn_argv(shell, trace_file)
            p = real(prog, argv, **kw)
            # Known to the round before the first wait, so a stall in the
            # constructor's marker is still captured.
            if owner is not None:
                owner.session = self
            return p

        pty_session.pexpect.spawn = spawn
        try:
            super().__init__(shell, env, cols=cols)
        finally:
            pty_session.pexpect.spawn = real


class DrainDriver:
    """Same marker protocol as Session, but a reader thread empties the PTY
    all the time and answers fish's terminal queries; waits only look at
    what it collected."""

    def __init__(self, shell, env, cols, trace_file=None, owner=None):
        self.shell = shell
        self.log = io.BytesIO()
        self.lock = threading.Lock()
        self.eof = threading.Event()
        self.pos = 0
        self.n = 0
        version = ""
        if shell == "fish":
            version = subprocess.run(["fish", "--version"], capture_output=True, text=True, env=env).stdout
        self.respond = shell == "fish"
        self.prompt_end = sends_prompt_end(version)
        prog, argv = spawn_argv(shell, trace_file)
        self.p = pexpect.spawn(prog, argv, env={"TERM": "xterm-256color", **env}, dimensions=(24, cols), timeout=15)
        self.reader = threading.Thread(target=self._drain, daemon=True)
        self.reader.start()
        if owner is not None:
            owner.session = self
        self._mark()

    def _drain(self):
        fd = self.p.child_fd
        tail = b""
        while True:
            try:
                b = os.read(fd, 65536)
            except OSError:
                break
            if not b:
                break
            with self.lock:
                self.log.write(b)
            if self.respond:
                chunk = tail + b
                for q, a in zip(QUERIES, ANSWERS):
                    # Only queries that end in the new bytes: one in the
                    # kept tail was answered on the last read.
                    for m in re.finditer(q, chunk):
                        if m.end() > len(tail):
                            os.write(fd, a)
                tail = chunk[-8:]
        self.eof.set()

    def expect(self, pattern, timeout=15):
        rx = re.compile(pattern) if isinstance(pattern, bytes) else pattern
        deadline = time.monotonic() + timeout
        while True:
            with self.lock:
                data = self.log.getvalue()
            m = rx.search(data, self.pos)
            if m:
                self.pos = m.end()
                return
            if self.eof.is_set():
                raise pexpect.EOF("shell ended")
            if time.monotonic() >= deadline:
                raise pexpect.TIMEOUT(f"no match for {pattern!r} within {timeout}s")
            time.sleep(0.02)

    def _ready(self):
        if not self.prompt_end:
            return
        try:
            self.expect(re.compile(rb"\x1b\]133;B"), timeout=2)
        except pexpect.TIMEOUT:
            pass

    def _mark(self, timeout=15):
        self._ready()
        self.n += 1
        tok = f"BINGSU_MARK_{self.n}"
        self.p.sendline(f'echo BINGSU_""MARK_{self.n}')
        self.expect(tok.encode(), timeout=timeout)

    def run(self, line, timeout=15):
        self._ready()
        self.p.sendline(line)
        self._mark(timeout)

    def close(self):
        self.p.sendline("exit")
        self.eof.wait(15)
        if not self.eof.is_set():
            raise pexpect.TIMEOUT("no EOF after exit")
        self.kill()
        with self.lock:
            return self.log.getvalue()

    def kill(self):
        if self.p.isalive():
            self.p.terminate(force=True)
        if not self.p.closed:
            self.p.close(force=True)


DRIVERS = {"session": SessionDriver, "drain": DrainDriver}


def transcript(s):
    if isinstance(s, DrainDriver):
        with s.lock:
            return s.log.getvalue()
    return s.log.getvalue()


def octal(b):
    return "".join(f"\\{c:03o}" for c in b)


def quote(shell, path):
    """`path` as one word for `shell`: POSIX quoting for bash, fish's single
    quotes (backslash and quote escaped) for fish."""
    s = str(path)
    if shell == "fish":
        return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"
    return shlex.quote(s)


SAFE_NAME = re.compile(r"[A-Za-z0-9_./-]+")


def wait_call(ctx, inst, start, pred):
    """test_fish_hooks.wait_call with the round's timeout: the index of the
    first bingsu call at or after `start` that matches `pred`. Running past
    the timeout is a stall."""
    deadline = time.monotonic() + ctx.timeout
    while True:
        calls = inst.calls()
        for k in range(start, len(calls)):
            if pred(calls[k]):
                return k
        if time.monotonic() >= deadline:
            raise Stall(f"no matching call after index {start} within {ctx.timeout}s: {calls[start:]!r}")
        time.sleep(0.05)


def ms_between(lo, hi):
    def pred(c):
        for a, b in zip(c, c[1:]):  # pairs of neighbours; the last has none
            if a == b"--duration-ms":
                return lo <= int(b) < hi
        return False
    return pred


def ready(ctx, s):
    """Session._ready as the tests use it (fish 4.1+ only: wait up to 2 s for
    OSC 133;B). The tests go on after a missing mark, so this does too, but
    each miss is counted in the round's notes."""
    if not s.prompt_end:
        return
    try:
        s.expect(re.compile(rb"\x1b\]133;B"), timeout=2)
    except pexpect.TIMEOUT:
        ctx.notes.append("no 133;B in 2 s")


def delayed_fake(work, seconds, min_ms):
    """fake_bingsu.sh that sleeps before it logs and answers when the call
    carries --duration-ms of at least `min_ms` (--inject delay): the prompts
    before the body stay fast, the body's is late past the 15 s waits. A
    copy, not a wrapper: the double finds its files next to $0."""
    text = conftest.FAKE.read_text().split("\n", 1)
    path = work / f"fake_sleep_{seconds}_{min_ms}.sh"
    late = (f'prev=\nfor a in "$@"; do\n'
            f'  if [ "$prev" = --duration-ms ] && [ "$a" -ge {min_ms} ]; then sleep {seconds}; fi\n'
            f'  prev=$a\ndone\n')
    path.write_text(f"{text[0]}\n{late}{text[1]}")
    path.chmod(0o755)
    return path


def prepare(ctx, shell, record):
    """Install, init script and rc lines for this round's product, as each
    test's start() does. Returns (inst, env, init path or None, rc)."""
    inst = conftest.Install(ctx.dir)
    env = conftest.trusted_env(ctx.dir)
    if ctx.product == "none":
        return inst, env, None, ""
    init = ctx.dir / f"init.{shell}"
    init.write_bytes(inst.init(shell, env))
    rc = f"source {quote(shell, init)}\n"
    if ctx.product == "stub":
        if ctx.inject == "delay":
            real_fake = conftest.FAKE
            # fish-nothing: only the `sleep 0.3` prompt (the markers before
            # it run in a few ms); the other bodies: their command's prompt.
            conftest.FAKE = delayed_fake(ctx.work, 16, 250 if ctx.case == "fish-nothing" else 0)
            try:
                inst.use_fake(record)
            finally:
                conftest.FAKE = real_fake
        else:
            inst.use_fake(record)
    elif ctx.product == "function":
        # The hooks call the pinned path; a function by that name answers
        # first. A name with other characters is not tried.
        if not SAFE_NAME.fullmatch(str(inst.exe)):
            raise NotApplicable(f"pinned path not usable as a function name: {inst.exe}")
        rc += f"function {inst.exe} {{ printf '{octal(record)}'; }}\n"
    return inst, env, init, rc


class NotApplicable(Exception):
    """This body cannot run with this product."""


def body_bash_nonzero(ctx):
    """test_bash_hooks.test_nonzero_middle_hook_does_not_change_status: start()
    sources rc.bash in Session.run (15 s), run("false") (15 s), close() (EOF,
    15 s), then the PROBE assertion."""
    _, env, _, rc = prepare(ctx, "bash", conftest.minimal_record())
    first = '"${PROMPT_COMMAND[0]}" ' if ctx.product != "none" else ""
    rest = ' "${PROMPT_COMMAND[@]:1}"' if ctx.product != "none" else ""
    probe = 'echo "PROBE:7"' if ctx.inject == "fail" else 'echo "PROBE:$?"'
    rc += (f"_seven() {{ return 7; }}\n_probe() {{ {probe}; }}\n"
           f"PROMPT_COMMAND=({first}_seven _probe{rest})\n")
    (ctx.dir / "rc.bash").write_text(rc)
    s = ctx.open("bash", env)
    ctx.stage = "source"
    s.run(f"source {quote('bash', ctx.dir / 'rc.bash')}", timeout=ctx.timeout)
    ctx.stage = "body"
    s.run("false", timeout=ctx.timeout)
    ctx.stage = "close"
    out = visible(s.close())
    if not (b"PROBE:1" in out and b"PROBE:7" not in out):
        return "fail"
    return "ok"


def body_fish_nothing(ctx, line):
    """test_fish_hooks.test_line_that_runs_nothing_sends_no_duration, step by
    step: start() (source rc.fish, 15 s), _ready, count calls, `sleep 0.3`,
    wait_call 250–550 ms (15 s), _ready, the line, _ready, `sleep 0.6`,
    wait_call 550–3000 ms (15 s), close(), then the assertions on the calls
    in between. It watches the double's argv log, so it runs with the stub
    only."""
    if ctx.product != "stub":
        raise NotApplicable("the body reads the stub's argv log")
    inst, env, _, rc = prepare(ctx, "fish", conftest.minimal_record())
    (ctx.dir / "rc.fish").write_text(rc)
    s = ctx.open("fish", env)
    ctx.stage = "source"
    s.run(f"source {quote('fish', ctx.dir / 'rc.fish')}", timeout=ctx.timeout)
    ctx.stage = "body"
    ready(ctx, s)
    n = len(inst.calls())
    s.p.sendline("sleep 0.3")
    i = wait_call(ctx, inst, n, ms_between(250, 550))
    ready(ctx, s)
    s.p.sendline(line)
    ready(ctx, s)
    s.p.sendline("sleep 0.6")
    j = wait_call(ctx, inst, i + 1, ms_between(550, 3000))
    between = inst.calls()[i + 1:j]
    ctx.stage = "close"
    s.close()
    if not between or any(b"--duration-ms" in c for c in between):
        return "fail"
    return "ok"


def body_fish_nul(ctx):
    """test_hostile_matrix.test_hostile_class[nul_cmdsub-en_US.UTF-8-fish]:
    Install, init, use_fake(record), Session, run(source init) and run("true")
    (15 s each for an observe row), close(), then every assertion of the
    test: the canary was not created; no shell warning on screen; the cell is
    pinned in nul_expected.tsv; the screen matches the pin (fish: "minimal",
    the record is rejected and the minimal prompt drawn). The bingsu init is
    the body, so it runs with the stub and the real binary; with the real
    binary the record is not the test's, so only the canary and warning
    assertions apply (noted)."""
    if ctx.product not in ("stub", "real"):
        raise NotApplicable("the body sources bingsu init")
    row = next(r for r in matrix.rows() if r[0] == "nul_cmdsub")
    canary = conftest.short_dir() / "c"
    ctx.cleanup.append(canary.parent)
    data = matrix.payload(row[1], str(canary).encode())
    if ctx.inject == "screen":
        # The record without its NUL: the reader accepts it and draws it,
        # which the pin ("minimal") forbids.
        data = data.replace(b"\x00", b"")
    _, env, init, _ = prepare(ctx, "fish", thm.record("fish", data))
    env["LC_ALL"] = "en_US.UTF-8"
    s = ctx.open("fish", env)
    ctx.stage = "source"
    s.run(f"source {quote('fish', init)}", timeout=ctx.timeout)
    ctx.stage = "body"
    s.run("true", timeout=ctx.timeout)
    if ctx.inject == "canary":
        # What an executed payload would leave behind.
        s.run(f"touch {quote('fish', canary)}", timeout=ctx.timeout)
    ctx.stage = "close"
    out = visible(s.close())
    if row[2] == "yes" and canary.exists():
        ctx.notes.append("canary created")
        return "fail"
    if b"null byte" in out or b"warning:" in out:
        ctx.notes.append("shell warning on screen")
        return "fail"
    if ctx.product != "stub":
        ctx.notes.append("screen pin not compared: the real binary draws its own record")
        return "ok"
    pinned = thm.nul_override(thm.nul_rows(), "hostile_nul_cmdsub", "fish", thm.shell_version("fish"),
                              env["LC_ALL"], column="pty")
    if pinned is None:
        ctx.notes.append("no pty pin in nul_expected.tsv")
        return "fail"
    if pinned == "noexec":
        ok = thm.drawn("fish", out, data)
    else:
        ok = b"L<" not in out and thm.MINIMAL in out
    if not ok:
        ctx.notes.append(f"screen does not match the pin {pinned}")
        return "fail"
    return "ok"


class Round:
    def __init__(self, args, case, n, work):
        self.case, self.n = case, n
        self.product, self.timeout, self.inject = args.product, args.timeout, args.inject
        self.driver = DRIVERS[args.driver]
        self.trace = args.trace
        self.work = work
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix=f"{case}-{n}-", dir=work))
        self.out = args.out / f"{case}-{n}"
        self.stage = "start"
        self.session = None
        self.notes = []
        self.cleanup = []

    def open(self, shell, env):
        trace_file = None
        if self.trace == "strace":
            self.out.mkdir(parents=True, exist_ok=True)
            trace_file = self.out / "strace.txt"
        return self.driver(shell, env, COLS, trace_file, owner=self)


def tree(root):
    ps = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,pgid=,tpgid=,stat=,wchan=,nice=,tty=,command="],
                        capture_output=True, text=True).stdout
    rows = [line.split(None, 8) for line in ps.splitlines() if line.strip()]
    keep, pids = [], {str(root)}
    grew = True
    while grew:
        grew = False
        for r in rows:
            if (r[0] in pids or r[1] in pids) and r not in keep:
                keep.append(r)
                pids.add(r[0])
                grew = True
    return keep


def screen_of(data):
    sc = pyte.Screen(COLS, 24)
    pyte.ByteStream(sc).feed(data)
    rows = [r.rstrip() for r in sc.display]
    return "\n".join(rows) + f"\ncursor {sc.cursor.x},{sc.cursor.y}\n"


def stty(tty):
    if not tty or tty in ("?", "??"):
        return "no tty\n"
    flag = "-f" if sys.platform == "darwin" else "-F"
    r = subprocess.run(["stty", "-a", flag, f"/dev/{tty}"], capture_output=True, text=True)
    return r.stdout + r.stderr


def capture(rd):
    """Records one stall into the round folder, then ends the session."""
    s = rd.session
    rd.out.mkdir(parents=True, exist_ok=True)
    if s is None:
        (rd.out / "screen.txt").write_text("no session\n")
        return
    pid = s.p.pid
    rows0 = tree(pid)
    (rd.out / "ps-0.txt").write_text("\n".join(" ".join(r) for r in rows0) + "\n")
    (rd.out / "screen.txt").write_text(screen_of(transcript(s)))
    tty = rows0[0][7] if rows0 else ""
    (rd.out / "tty-0.txt").write_text(stty(tty))
    if sys.platform == "darwin" and shutil.which("sample"):
        for r in rows0:
            subprocess.run(["sample", r[0], "1", "-file", str(rd.out / f"stack-{r[0]}.txt")],
                           capture_output=True)
    before = len(transcript(s))
    try:
        s.p.send("#")
    except OSError:
        pass
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if not isinstance(s, DrainDriver):
            try:
                s.p.read_nonblocking(65536, timeout=0.5)
            except (pexpect.TIMEOUT, pexpect.EOF):
                pass
        else:
            time.sleep(0.5)
    after = transcript(s)
    echoed = b"#" in after[before:]
    (rd.out / "input.txt").write_text(f"echoed={int(echoed)} new_bytes={len(after) - before}\n")
    rows20 = tree(pid)
    (rd.out / "ps-20.txt").write_text("\n".join(" ".join(r) for r in rows20) + "\n")
    (rd.out / "tty-20.txt").write_text(stty(tty))
    (rd.out / "transcript.bin").write_bytes(after)
    # The whole tree: a command substitution's child outlives its shell.
    for r in reversed(tree(pid)):
        try:
            os.kill(int(r[0]), signal.SIGKILL)
        except ProcessLookupError:
            pass
    s.kill()


def run_round(args, case, n, item, work):
    rd = Round(args, case, n, work)
    t0 = time.monotonic()
    try:
        if case == "bash-nonzero":
            result = body_bash_nonzero(rd)
        elif case == "fish-nothing":
            result = body_fish_nothing(rd, item)
        else:
            result = body_fish_nul(rd)
    except NotApplicable as e:
        result = "n/a"
        rd.notes.append(str(e))
    except (pexpect.TIMEOUT, pexpect.EOF, Stall):
        result = "stall"
        capture(rd)
    except Exception as e:  # noqa: BLE001 - any other error is a failed round, recorded, and the run goes on
        result = "fail"
        rd.out.mkdir(parents=True, exist_ok=True)
        (rd.out / "error.txt").write_text(f"{type(e).__name__}: {e}\n")
        capture(rd)
    finally:
        if rd.session is not None:
            rd.session.kill()
        shutil.rmtree(rd.dir, ignore_errors=True)
        for d in rd.cleanup:
            shutil.rmtree(d, ignore_errors=True)
    return rd.stage, result, time.monotonic() - t0, "; ".join(rd.notes)


def run_suite(args):
    env = dict(os.environ, BINGSU_BIN=str(args.bin), PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-m", "pytest", "tests/shell", "tests/golden/record/test_overrides.py",
                        "-q", "-rf", "-p", "no:cacheprovider"], cwd=ROOT, env=env, capture_output=True, text=True)
    (args.out / "suite.txt").write_text(r.stdout + r.stderr)
    return "ok" if r.returncode == 0 else "fail"


def self_test(args, work):
    """One bash round whose stub sleeps past the timeout: the capture path
    must leave a full round folder."""
    sleeper = work / "sleep_bingsu.sh"
    sleeper.write_text("#!/bin/sh\nsleep 30\n")
    sleeper.chmod(0o755)
    real_fake = conftest.FAKE
    conftest.FAKE = sleeper
    try:
        args.product, args.driver, args.inject = "stub", "session", "none"
        return run_round(args, "bash-nonzero", 1, None, work)
    finally:
        conftest.FAKE = real_fake


def parse(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--case", default="all", choices=("all", *CASES, "suite"))
    ap.add_argument("--rounds-bash", type=int, default=1000)
    ap.add_argument("--rounds-fish-group", type=int, default=100)
    ap.add_argument("--rounds-fish-nul", type=int, default=200)
    ap.add_argument("--product", default="stub", choices=("real", "function", "stub", "none"))
    ap.add_argument("--driver", default="session", choices=tuple(DRIVERS))
    ap.add_argument("--trace", default="", choices=("", "strace"))
    ap.add_argument("--seed", default="1")
    ap.add_argument("--timeout", type=float, default=15)
    ap.add_argument("--bin", type=pathlib.Path, default=conftest.real_bin())
    ap.add_argument("--work", type=pathlib.Path, default=None)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--self-test", action="store_true")
    # Checks that the probe sees what fails the original test: `fail` makes
    # the bash body's probe print PROBE:7, `delay` makes the stub sleep 16 s
    # before it answers a call with --duration-ms (past every 15 s wait).
    # `canary` (fish-nul) touches the canary as an executed payload would;
    # `screen` (fish-nul) drops the record's NUL so the reader draws it.
    ap.add_argument("--inject", default="none", choices=("none", "fail", "delay", "canary", "screen"))
    args = ap.parse_args(argv)
    # The seed comes from a workflow input: digits only.
    if not SEED.fullmatch(args.seed):
        ap.exit(2, f"--seed must be 1 to 9 digits, got {args.seed!r}\n")
    if args.trace == "strace" and not sys.platform.startswith("linux"):
        ap.exit(2, "--trace strace runs on Linux only\n")
    return args


def main(argv=None):
    args = parse(argv)
    os.environ["BINGSU_BIN"] = str(args.bin.resolve())
    args.out.mkdir(parents=True, exist_ok=True)
    own_work = args.work is None
    work = pathlib.Path(tempfile.mkdtemp(prefix="stall-work-")) if own_work else args.work
    work.mkdir(parents=True, exist_ok=True)
    summary = args.out / "summary.tsv"
    summary.write_text("case\tproduct\tdriver\tround\tstage\tresult\tseconds\tseed\tnotes\n")
    bad = rounds = 0

    def record(c, n, stage, result, secs, notes):
        nonlocal bad, rounds
        rounds += 1
        bad += result not in ("ok", "n/a")
        # One line per round as it ends: a later crash keeps the earlier rows.
        with open(summary, "a") as f:
            f.write(f"{c}\t{args.product}\t{args.driver}\t{n}\t{stage}\t{result}\t{secs:.2f}\t{args.seed}\t{notes}\n")

    try:
        if args.self_test:
            record("bash-nonzero", 1, *self_test(args, work))
        elif args.case == "suite":
            t0 = time.monotonic()
            record("suite", 1, "pytest", run_suite(args), time.monotonic() - t0, "")
        else:
            items = []
            cases = CASES if args.case == "all" else (args.case,)
            for c in cases:
                if c == "bash-nonzero":
                    items += [(c, n, None) for n in range(1, args.rounds_bash + 1)]
                elif c == "fish-nothing":
                    items += [(c, n, line) for n in range(1, args.rounds_fish_group + 1) for line in FISH_LINES]
                else:
                    items += [(c, n, None) for n in range(1, args.rounds_fish_nul + 1)]
            random.Random(int(args.seed)).shuffle(items)
            for c, n, item in items:
                # Fish groups have four rounds each; number them apart.
                rn = n if c != "fish-nothing" else f"{n}.{FISH_LINES.index(item)}"
                record(c, rn, *run_round(args, c, rn, item, work))
    finally:
        # Only a folder this run made; a given --work is the caller's.
        if own_work:
            shutil.rmtree(work, ignore_errors=True)
    print(f"{rounds} rounds, {bad} stalled or failed; summary {summary}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
