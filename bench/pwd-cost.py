"""Worst-case $PWD cost of `bingsu prompt`: every case but `short` is
exactly 65,536 bytes (the envelope cap), passed as raw argv bytes, which
hyperfine -N cannot do. Runs the cases in turn, round by round, and records
wall time and the child's peak RSS (os.wait4). Usage:
bench/pwd-cost.py BINARY [ROUNDS]"""
import os
import statistics
import sys
import time

CAP = 65536
BASE = [b"prompt", b"--ctx", b"1", b"--record", b"B1", b"--width", b"100", b"--runtime-root=1:2:/r",
        b"--shell", b"zsh", b"--home=/Users/x", b"--status", b"1", b"--pwd"]
CASES = {
    "short": b"/Users/x/Works/AiScream/themes",
    "slashes": b"/a" * (CAP // 2),
    "controls": b"/" + b"\x1b\x01\x7f" * ((CAP - 1) // 3) + b"a" * ((CAP - 1) % 3),
    "invalid-utf8": b"/" + b"\xff" * (CAP - 1),
    "one-long-name": b"/" + b"a" * (CAP - 1),
}


def run(binary, pwd):
    t = time.perf_counter_ns()
    pid = os.fork()
    if pid == 0:
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, 1)
        os.execv(binary, [binary.encode()] + BASE + [pwd])
    _, status, ru = os.wait4(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    rss = ru.ru_maxrss if sys.platform == "darwin" else ru.ru_maxrss * 1024
    return (time.perf_counter_ns() - t) / 1e6, rss


def main():
    binary = sys.argv[1]
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 200
    for name, pwd in CASES.items():
        assert name == "short" or len(pwd) == CAP, (name, len(pwd))
    out = {k: ([], []) for k in CASES}
    for _ in range(10):
        for pwd in CASES.values():
            run(binary, pwd)
    for r in range(rounds):
        names = list(CASES) if r % 2 == 0 else list(reversed(CASES))
        for k in names:
            ms, rss = run(binary, CASES[k])
            out[k][0].append(ms)
            out[k][1].append(rss)
    for k, (ms, rss) in out.items():
        ms.sort()
        print(f"{k}\tmedian {statistics.median(ms):.3f} ms\tp95 {ms[int(len(ms) * 0.95)]:.3f} ms\tpeak RSS {max(rss) / 2**20:.2f} MiB")


if __name__ == "__main__":
    main()
