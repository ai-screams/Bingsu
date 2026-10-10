#!/usr/bin/env bash
# Download the Unicode 17.0.0 inputs of gen.py into DIR (default
# target/ucd-17.0.0). gen.py checks their sha256 before it reads them.
# Network is a preparation step, never part of a test.
set -euo pipefail
dir=${1:-target/ucd-17.0.0}
mkdir -p "$dir"
base=https://www.unicode.org/Public/17.0.0/ucd
for f in EastAsianWidth.txt extracted/DerivedGeneralCategory.txt emoji/emoji-data.txt; do
  curl -fsSL --retry 3 -o "$dir/$(basename "$f")" "$base/$f"
done
echo "$dir"
