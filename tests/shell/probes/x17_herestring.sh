#!/usr/bin/env bash
# X-17: does bash put a here-string of a given size into a temp file?
# Usage: x17_herestring.sh BYTES   (prints "x17 BYTES temp-file|no-temp-file")
set -euo pipefail
size=$1
tmp=$(mktemp -d)
big=$(head -c "$size" /dev/zero | tr '\0' x)
TMPDIR=$tmp strace -f -qq -e trace=openat,open -o "$tmp/trace" \
  bash --noprofile --norc -c 'IFS=$'"'"'\x1f'"'"'; read -r -a f <<<"$1"; test "${#f[0]}" -gt 0' _ "$big"
if grep -q "$tmp/" "$tmp/trace"; then echo "x17 $size temp-file"; else echo "x17 $size no-temp-file"; fi
rm -rf "$tmp"
