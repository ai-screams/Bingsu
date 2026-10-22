#!/usr/bin/env python3
"""Audit shipped Mach-O/ELF imports and the front's linked Git boundary.

Static ELF requires its full symbol table (save the same linked file before
stripping). An empty dynamic table alone is not evidence of process freedom.
"""
import argparse
import pathlib
import re
import shutil
import subprocess
import sys

TAG = b"BNGSIBLING-ID02\0"
ROLE = b"BNGROLE-ID02\0\0\0\0"
FORBIDDEN = re.compile(r"^(?:(?:libc_|GI_)?(?:posix_spawn.*|exec.*|fork|vfork|system|popen)|dlsym|dlopen)$")
GIT_SYMBOL = re.compile(r"(?:gix_[a-z_]+(?:::|[0-9])|[0-9]gix_[a-z_]+)")
COMMAND_SYMBOL = re.compile(r"std::(?:sys::.*::process|process::Command)|gix_path::.*git_cmd")


def symbol_names(text):
    # readelf can append a version index after the versioned symbol name.
    text = re.sub(r"[ \t]+\(\d+\)$", "", text, flags=re.M)
    return {re.split(r"[$@]", line.split()[-1].lstrip("_"), maxsplit=1)[0]
            for line in text.splitlines() if line.split()}


def forbidden_imports(text, *, elf=False):
    # Linux's existing seccomp/Landlock/close_range/capability setup calls the
    # syscall gateway. Its call numbers/arguments remain kernel-filtered; this
    # is not a new syscall permission. Mach-O keeps the original syscall ban.
    return sorted(name for name in symbol_names(text)
                  if FORBIDDEN.fullmatch(name) or (not elf and name == "syscall"))


def prompt_git_symbols(text):
    return sorted(line for line in text.splitlines() if GIT_SYMBOL.search(line))


def command_symbols(text):
    return sorted(line for line in text.splitlines() if COMMAND_SYMBOL.search(line))


def output(command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def binary_kind(path):
    magic = pathlib.Path(path).read_bytes()[:4]
    if magic == b"\x7fELF":
        return "elf"
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
        return "macho"
    raise ValueError("expected a thin shipped Mach-O or ELF binary: " + str(path))


def full_symbols(path):
    symbols = output(["nm", "-C", str(path)])
    # A stripped static ELF can produce an empty successful nm result.
    if not any(len(line.split()) >= 3 for line in symbols.splitlines()):
        raise ValueError("full linked symbols required before stripping: " + str(path))
    return symbols


def imports(path, kind):
    if kind == "macho":
        return output(["nm", "-u", str(path)])
    # readelf succeeds even without .dynsym; require that absence to agree
    # with a static link (no interpreter or needed shared objects).
    dynamic = output(["readelf", "--dyn-syms", "--wide", str(path)])
    headers = output(["readelf", "--program-headers", "--dynamic", "--wide", str(path)])
    has_dynamic = "Symbol table '.dynsym'" in dynamic
    if not has_dynamic and ("INTERP" in headers or "(NEEDED)" in headers):
        raise ValueError("dynamic ELF is missing its dynamic symbol table")
    print(f"ELF dynamic symbol table: {'present' if has_dynamic else 'absent (static)'}")
    return dynamic


def audit_pair(binary, sibling=None, unstripped_dir=None):
    kind = binary_kind(binary)
    elf = kind == "elf"
    bad = forbidden_imports(imports(binary, kind), elf=elf)
    build_id(binary, 1)
    # ELF needs a full-symbol audit even when its dynamic table is empty.
    # With --sibling, also prove that Git code did not enter the prompt binary.
    if elf or sibling:
        full = pathlib.Path(unstripped_dir) / pathlib.Path(binary).name if unstripped_dir else binary
        if binary_kind(full) != kind or build_id(full, 1) != build_id(binary, 1):
            raise ValueError("unstripped collector identity or format mismatch")
        symbols = full_symbols(full)
        bad += forbidden_imports(symbols, elf=elf) + command_symbols(symbols)
    if sibling:
        if binary_kind(sibling) != kind or build_id(binary, 1) != build_id(sibling, 2):
            raise ValueError("sibling build identity or format mismatch")
        full = pathlib.Path(unstripped_dir) / pathlib.Path(sibling).name if unstripped_dir else sibling
        if binary_kind(full) != kind or build_id(full, 2) != build_id(sibling, 2):
            raise ValueError("unstripped front identity or format mismatch")
        front_bad = prompt_git_symbols(full_symbols(full))
        print(f"front Git symbols: {len(front_bad)}")
        bad += front_bad
    print(f"forbidden imports/code: {len(bad)}")
    if bad:
        raise ValueError("\n".join(sorted(set(bad))))


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
    parser.add_argument("--unstripped-dir", type=pathlib.Path)
    parser.add_argument("--strip", action="store_true", help="audit, save full symbols, strip, re-audit")
    args = parser.parse_args()
    if args.symbols_file:
        bad = forbidden_imports(args.symbols_file.read_text())
        print(f"forbidden imports: {len(bad)}")
        return int(bool(bad))
    else:
        if not args.binary or pathlib.Path(args.binary).name != "bingsu-collect":
            parser.error("audit the shipped bingsu-collect binary")
        if args.strip:
            if not args.sibling or not args.unstripped_dir:
                parser.error("--strip requires --sibling and --unstripped-dir")
            audit_pair(args.binary, args.sibling)
            args.unstripped_dir.mkdir(parents=True, exist_ok=True)
            for binary in (args.binary, args.sibling):
                saved = args.unstripped_dir / pathlib.Path(binary).name
                shutil.copyfile(binary, saved)
                subprocess.run(["strip", binary], check=True)
        audit_pair(args.binary, args.sibling, args.unstripped_dir)
        if args.sibling:
            sizes = {pathlib.Path(p).name: pathlib.Path(p).stat().st_size
                     for p in (args.binary, args.sibling)}
            print(f"binary bytes: {sizes}; total={sum(sizes.values())}")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
