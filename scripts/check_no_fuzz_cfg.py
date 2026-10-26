#!/usr/bin/env python3
"""A product build's own rustc invocations never enable cfg(collector_fuzz).

Input: the output of `cargo build -v` after the collector was touched, so
that bingsu-collect's rustc line is printed rather than reported Fresh.
Only fuzz/collector/build.rs may set the cfg, and no product crate depends
on that crate. A log without a bingsu_collect rustc line proves nothing and
fails.
"""
import re
import shlex
import sys


# CSI (ESC [ … final byte) and two-byte ESC sequences. Cargo colours
# "Running" under CARGO_TERM_COLOR=always (as in CI), and a colour code
# inside a command line must not hide a flag from the check.
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")


def check(log):
    # 이것을 실패시키는 것: ANSI를 지우지 않아 색 입힌 CI 로그를 빈 로그로 보거나,
    # 색 코드 사이에 낀 --cfg collector_fuzz를 놓치는 것.
    log = ANSI.sub("", log)
    lines = [line for line in log.splitlines() if re.search(r"Running `.*\brustc\b.*--crate-name ", line)]
    errors = []
    if not any("--crate-name bingsu_collect " in line for line in lines):
        errors.append("no bingsu_collect rustc invocation; touch the crate before cargo build -v")
    for line in lines:
        command = line.split("Running `", 1)[1].rsplit("`", 1)[0]
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        pairs = list(zip(tokens, tokens[1:]))
        # 이것을 실패시키는 것: build script·RUSTFLAGS·config로 --cfg collector_fuzz를 넘기는 것.
        enabled = [b for a, b in pairs if a == "--cfg" and re.match(r"collector_fuzz(?![\w])", b)]
        enabled += [t for t in tokens if re.fullmatch(r"--cfg=collector_fuzz.*", t)]
        if enabled:
            name = re.search(r"--crate-name (\S+)", command)[1]
            errors.append(f"{name}: --cfg collector_fuzz")
    return errors


def main():
    errors = check(open(sys.argv[1], encoding="utf-8", errors="replace").read())
    for error in errors:
        print("product cfg gate FAILED:", error, file=sys.stderr)
    if errors:
        return 1
    print("product rustc invocations without collector_fuzz:", "ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
