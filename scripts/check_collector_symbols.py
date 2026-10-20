#!/usr/bin/env python3
"""Audit the shipped Mach-O worker; optionally check sibling identities and roles."""
import argparse
import pathlib
import re
import subprocess
import sys

TAG = b"BNGSIBLING-ID02\0"
ROLE = b"BNGROLE-ID02\0\0\0\0"
FORBIDDEN = re.compile(r"^(?:posix_spawn.*|exec.*|fork|vfork|system|popen|dlsym|dlopen|syscall)$")


def forbidden_imports(text):
    return sorted({line.split()[-1].lstrip("_").split("$", 1)[0]
                   for line in text.splitlines() if line.split()
                   and FORBIDDEN.fullmatch(line.split()[-1].lstrip("_").split("$", 1)[0])})


def build_id(path, role):
    data = pathlib.Path(path).read_bytes()
    if data.count(TAG) != 1:
        raise ValueError("binary must contain exactly one sibling manifest tag")
    at = data.index(TAG) + len(TAG)
    value = data[at:at + 32]
    if len(value) != 32:
        raise ValueError("truncated build identity")
    if data.count(ROLE) != 1:
        raise ValueError("binary must contain exactly one role tag")
    at = data.index(ROLE) + len(ROLE)
    if data[at:at + 33] != bytes([role]) + value:
        raise ValueError("binary role or role build identity mismatch")
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
        build_id(args.binary, 1)
    bad = forbidden_imports(symbols)
    print(f"forbidden imports: {len(bad)}")
    if bad:
        print("\n".join(bad), file=sys.stderr)
    if args.sibling and build_id(args.binary, 1) != build_id(args.sibling, 2):
        print("sibling build identity mismatch", file=sys.stderr)
        return 1
    return int(bool(bad))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
