#!/usr/bin/env bash
# Build a throwaway repository whose single pack holds BLOBS (default 64)
# incompressible 4 MiB blobs, roughly 256 MiB, and print the pack path.
# Usage: make-pack-fixture.sh DIR [BLOBS]
# DIR must not exist yet: this script never removes anything, so a wrong
# path cannot cost data. Remove DIR yourself after the measurement.
set -euo pipefail
dir=${1:?DIR}
blobs=${2:-64}
[[ $blobs =~ ^[1-9][0-9]{0,3}$ ]] || { echo "BLOBS must be 1-9999: $blobs" >&2; exit 2; }
[[ ! -e $dir && ! -L $dir ]] || { echo "$dir exists; pass a new path" >&2; exit 2; }
mkdir -p "$dir"
cd "$dir"
# The user's git config (hooks, signing, gc settings) must not shape the pack.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
git init -q .
for i in $(seq 1 "$blobs"); do head -c 4194304 /dev/urandom > "blob-$i.bin"; done
git add .
git -c user.name=m1 -c user.email=m1@example.invalid commit -qm fixture
# One pack of every object, no delta search (random blobs have no deltas).
git repack -a -d -q --window=0
git prune-packed -q
ls "$dir"/.git/objects/pack/pack-*.pack
