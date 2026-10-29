#!/usr/bin/env python3
"""Writes attributes-15k.txt: a 480-line .gitattributes of about 15 KB.

Deterministic (no randomness): a rerun writes the same bytes. The shape is a
large repository's attributes file: a comment header every 40 lines, a blank
line closing each section, and pattern lines of five path forms (anchored
globstar, plain directory glob, suffix, bracket class, directory tree) that
repeat 14 attribute names with one to three assignments, so the name scan
stays on the collector's short list of at most 16 names.
Usage: python3 -I make_attributes_15k.py > attributes-15k.txt
"""
import sys

EXTS = [("rs", "text eol=lf diff=rust"), ("py", "text diff=python"),
        ("md", "text linguist-documentation"), ("png", "binary"),
        ("json", "text -diff"), ("lock", "-text merge=union"),
        ("sh", "text eol=lf"), ("svg", "-diff linguist-generated"),
        ("bat", "text eol=crlf"), ("pdf", "binary export-ignore"),
        ("txt", "working-tree-encoding=UTF-8"), ("psd", "lockable filter=lfs"),
        ("go", "text whitespace=tab-in-indent"), ("js", "linguist-vendored")]
AREAS = ["src", "lib", "tools", "docs", "vendor", "assets", "web", "tests"]


def line(n):
    if n % 40 == 0:
        return f"# Section {n // 40:02d}: {AREAS[n // 40 % len(AREAS)]}"
    if n % 40 == 39:
        return ""
    area = AREAS[n % len(AREAS)]
    ext, attrs = EXTS[n % len(EXTS)]
    form = n % 5
    if form == 0:
        return f"/{area}/m{n:03d}/**/*.{ext} {attrs}"
    if form == 1:
        return f"{area}/p{n:03d}/*.{ext} {attrs}"
    if form == 2:
        return f"*.{n:03d}.{ext} {attrs}"
    if form == 3:
        return f"{area}/c{n:03d}/[a-z]*.{ext} {attrs}"
    return f"{area}/k{n:03d}/** -diff"


def main():
    sys.stdout.write("".join(line(n) + "\n" for n in range(480)))


if __name__ == "__main__":
    main()
