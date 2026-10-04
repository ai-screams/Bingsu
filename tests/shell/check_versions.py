#!/usr/bin/env python3
"""Fail fast if an image ships a different shell version than the plan needs.

Usage: check_versions.py bash=5.1 zsh=5.8   (exact MAJOR.MINOR match)
Also provides version() and rule_matches() for other test tools.
"""
import re
import subprocess
import sys

PROBE = {
    "bash": ["bash", "-c", 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"'],
    "zsh": ["zsh", "-fc", 'echo "${ZSH_VERSION}"'],
    "fish": ["fish", "--version"],
}


def parse(text):
    m = re.search(r"(\d+)\.(\d+)", text)
    if m is None:
        raise ValueError(f"no MAJOR.MINOR in {text!r}")
    return (int(m.group(1)), int(m.group(2)))


def version(shell):
    """Installed MAJOR.MINOR of `shell` as a tuple of ints."""
    out = subprocess.run(PROBE[shell], capture_output=True, text=True).stdout
    return parse(out)


def rule_matches(rule, v):
    """Does version tuple `v` satisfy `rule` ('*', '>=M.m' or '<M.m')?"""
    if rule == "*":
        return True
    if rule.startswith(">="):
        return v >= parse(rule[2:])
    if rule.startswith("<"):
        return v < parse(rule[1:])
    raise ValueError(f"unknown version rule {rule!r}")


def main():
    bad = []
    for spec in sys.argv[1:]:
        shell, want = spec.split("=")
        got = version(shell)
        print(f"{shell}: {got[0]}.{got[1]} (want {want})")
        if got != parse(want):
            bad.append(shell)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
