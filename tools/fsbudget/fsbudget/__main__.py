"""python3 -m fsbudget run --rules RULES.json [--markers] -o REPORT.json -- CMD..."""
import argparse
import json
import pathlib
import subprocess
import sys
import tempfile

from .attribute import attribute
from .strace_parse import STRACE_FLAGS, parse


def main():
    ap = argparse.ArgumentParser(prog="fsbudget")
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--rules", required=True)
    run.add_argument("--markers", action="store_true")
    run.add_argument("-o", "--out", required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.command[1:] if a.command and a.command[0] == "--" else a.command
    with tempfile.TemporaryDirectory() as td:
        trace = pathlib.Path(td) / "trace"
        r = subprocess.run(["strace", *STRACE_FLAGS, "-o", str(trace), "--"] + cmd,
                           stdout=subprocess.PIPE)
        sys.stdout.buffer.write(r.stdout)  # roles report their axes on stdout (a pipe, not counted)
        rules = json.loads(pathlib.Path(a.rules).read_text())
        got = attribute(parse(trace.read_text(errors="replace")), rules, markers=a.markers)
    pathlib.Path(a.out).write_text(json.dumps({"exit": r.returncode, "counts": got.counts, "errors": got.errors}, indent=2))
    for e in got.errors:
        print(f"fsbudget: {e}", file=sys.stderr)
    return r.returncode or (3 if got.errors else 0)


if __name__ == "__main__":
    sys.exit(main())
