#!/usr/bin/env bash
# Snapshot-present runtime folder for the M1 estimates (dummy bytes of the
# assumed sizes; the real format is M3a): snapshot = header 64 + section
# 16,384, marker 128, session 2,048. The section and session sizes are an
# assumption for the default theme's compiled settings (UNVERIFIED until M3a).
# Usage: make-snapshot-present.sh DIR   (absolute; a new folder, never reused)
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: make-snapshot-present.sh DIR" >&2; exit 2; }
dir=$1
case $dir in /*) ;; *) echo "make-snapshot-present.sh: DIR must be absolute: $dir" >&2; exit 2 ;; esac
# mkdir without -p refuses a folder that already exists.
mkdir -m 700 -- "$dir"
head -c $((64 + 16384)) /dev/zero > "$dir/snapshot"
head -c 128 /dev/zero > "$dir/marker"
head -c 2048 /dev/zero > "$dir/session"
echo "$dir"
