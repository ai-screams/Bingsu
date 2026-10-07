#!/usr/bin/env bash
# Build a throwaway repository whose single pack holds BLOBS (default 64)
# incompressible 4 MiB blobs, roughly 256 MiB, and print the pack path.
# Usage: make-pack-fixture.sh DIR [BLOBS]
# DIR must be an absolute path that does not exist yet; it is created here
# (its parents too) and the script writes only inside it. Git variables that
# would point git at another repository (GIT_DIR, GIT_OBJECT_DIRECTORY, ...)
# and the user's git config are ignored. Nothing is removed: remove DIR
# yourself after the measurement.
set -euo pipefail
usage() { echo "usage: make-pack-fixture.sh /ABSOLUTE/NEW/DIR [BLOBS 1-9999]" >&2; exit 2; }
[[ $# -eq 1 || $# -eq 2 ]] || usage
dir=$1
blobs=${2-64}
[[ $dir == /* ]] || usage
[[ $blobs =~ ^[1-9][0-9]{0,3}$ ]] || usage
# shellcheck disable=SC2046 # one variable name per word
unset $(git rev-parse --local-env-vars)
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
mkdir -p -- "$(dirname -- "$dir")"
mkdir -- "$dir" || { echo "$dir: cannot create a new folder there" >&2; exit 2; }
cd -- "$dir"
git init -q --template= .
for i in $(seq 1 "$blobs"); do head -c 4194304 /dev/urandom > "blob-$i.bin"; done
git add .
git -c user.name=m1 -c user.email=m1@example.invalid commit -qm fixture
# One pack of every object, no delta search (random blobs have no deltas).
git repack -a -d -q --window=0
git prune-packed -q
ls "$dir"/.git/objects/pack/pack-*.pack
