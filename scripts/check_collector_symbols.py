#!/usr/bin/env python3
"""Audit only the shipped Mach-O worker; optionally check sibling build IDs."""
import argparse
import pathlib
import re
import subprocess
import sys

TAG = b"BNGSIBLING-ID02\0"
FORBIDDEN = re.compile(r"^(?:posix_spawn.*|exec.*|fork|vfork|system|popen|dlsym)$")


def forbidden_imports(text):
    return sorted({line.split()[-1].lstrip("_").split("$", 1)[0]
                   for line in text.splitlines() if line.split()
                   and FORBIDDEN.fullmatch(line.split()[-1].lstrip("_").split("$", 1)[0])})


def build_id(path):
    data = pathlib.Path(path).read_bytes()
    if data.count(TAG) != 1:
        raise ValueError("binary must contain exactly one sibling manifest tag")
    at = data.index(TAG) + len(TAG)
    value = data[at:at + 32]
    if len(value) != 32:
        raise ValueError("truncated build identity")
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?")
    parser.add_argument("--sibling")
    parser.add_argument("--symbols-file", type=pathlib.Path)
    args = parser.parse_args()
    if args.symbols_file:
        symbols = args.symbols_file.read_text()
    else:
        if not args.binary or pathlib.Path(args.binary).name != "bingsu-collect":
            parser.error("audit the shipped bingsu-collect binary")
        symbols = subprocess.run(["nm", "-u", args.binary], check=True, capture_output=True, text=True).stdout
        build_id(args.binary)
    bad = forbidden_imports(symbols)
    print(f"forbidden imports: {len(bad)}")
    if bad:
        print("\n".join(bad), file=sys.stderr)
    if args.sibling and build_id(args.binary) != build_id(args.sibling):
        print("sibling build identity mismatch", file=sys.stderr)
        return 1
    return int(bool(bad))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
