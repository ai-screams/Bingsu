#!/bin/sh
# Test double for `bingsu prompt`. Installed as the symlink target, so $0 is
# the pinned install path. Logs argv (each arg NUL-terminated, then "END\0")
# and prints record.bin from the install dir.
here=${0%/*}
for a in "$@"; do printf '%s\0' "$a"; done >> "$here/argv.log"
printf 'END\0' >> "$here/argv.log"
cat "$here/record.bin"
