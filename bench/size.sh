#!/usr/bin/env bash
# Stripped size of the three combinations (spec section 8 capacity table):
# base; base + regex; base + regex + YAML/JSON. The last is compared with
# 6 MB by summarize.py. Release builds with the probe's own Cargo.lock, in a
# new target folder (removed on exit), so neither CARGO_TARGET_DIR nor an old
# build can stand in for this one.
# Usage: bench/size.sh OUT_DIR   (absolute; writes OUT_DIR/size-<os>.jsonl, which must not exist)
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: size.sh OUT_DIR" >&2; exit 2; }
out=$1
case $out in /*) ;; *) echo "size.sh: OUT_DIR must be absolute: $out" >&2; exit 2 ;; esac
case "$(uname -s)" in Darwin) os=macos ;; Linux) os=linux ;; *) echo "size.sh: unsupported OS" >&2; exit 2 ;; esac
dest="$out/size-$os.jsonl"
mkdir -p -- "$out"
[ ! -e "$dest" ] || { echo "size.sh: $dest exists; give a new OUT_DIR" >&2; exit 1; }
manifest=$(cd -- "$(dirname -- "$0")/size-probe" && pwd -P)/Cargo.toml
tgt=$(mktemp -d)
trap 'rm -rf -- "$tgt"' EXIT
rows=()
for combo in "base:" "regex:regex" "regex-yaml-json:regex,yaml-json"; do
  name=${combo%%:*}; feats=${combo#*:}
  cargo build --quiet --release --locked --manifest-path "$manifest" --target-dir "$tgt" ${feats:+--features "$feats"}
  bytes=$(wc -c < "$tgt/release/bingsu-size-probe" | tr -d ' ')
  rows+=("$(printf '{"matrix":"size","row":"%s","os":"%s","arch":"%s","features":"%s","bytes":%s}' \
    "$name" "$os" "$(uname -m)" "$feats" "$bytes")")
done
printf '%s\n' "${rows[@]}" > "$dest"
cat "$dest"
