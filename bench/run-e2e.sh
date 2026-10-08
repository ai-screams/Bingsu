#!/usr/bin/env bash
# M1 end-to-end timings (spec section 8): empty prompt, redraw, init
# generator and init added time per shell. Warm, 300 runs, /usr/bin/true
# floor. Needs hyperfine (-N, 1.13 or later), zsh and fish; bash is timed
# only when the bash on PATH is 5.1 or later (otherwise the meta line says
# why it was not).
# Usage: bench/run-e2e.sh OUT_DIR [--cold-once]
#   OUT_DIR  absolute path of a new folder (its parent must exist; an
#            existing folder, even an empty one, is refused). A --cold-once
#            run takes its own new folder too; summarize.py merges the
#            folders it is given (summarize.py WARM_DIR COLD_DIR ...).
#   BINGSU_BIN  the binary to time (default: target/release/bingsu)
# The timed shells and `bingsu init` run with HOME and the XDG folders in a
# new temporary folder, so they read and write nothing of the user's.
set -euo pipefail
usage() { echo "usage: run-e2e.sh OUT_DIR [--cold-once]" >&2; exit 2; }
[ $# -ge 1 ] && [ $# -le 2 ] || usage
out=$1
cold=${2:-}
[ -z "$cold" ] || [ "$cold" = "--cold-once" ] || usage
case $out in /*) ;; *) echo "run-e2e.sh: OUT_DIR must be absolute: $out" >&2; exit 2 ;; esac
while IFS= read -r v; do unset "$v"; done < <(compgen -e | grep '^GIT_' || true)

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
bin=${BINGSU_BIN:-$root/target/release/bingsu}
case $bin in /*) ;; *) echo "run-e2e.sh: BINGSU_BIN must be absolute: $bin" >&2; exit 2 ;; esac
[ -x "$bin" ] || { echo "run-e2e.sh: no executable $bin (cargo build --release -p bingsu)" >&2; exit 1; }
for t in hyperfine zsh fish; do
  command -v "$t" >/dev/null || { echo "run-e2e.sh: $t not found" >&2; exit 1; }
done

suffix=${cold:+-cold}
# mkdir without -p refuses a folder (or a link) that already exists, so no
# earlier result can end up next to this run's.
mkdir -- "$out" || { echo "run-e2e.sh: OUT_DIR must be a new folder: $out" >&2; exit 1; }

runs=(--warmup 20 --runs 300)
[ -n "$cold" ] && runs=(--warmup 0 --runs 1)

tmp=$(mktemp -d)
tmp=$(cd -- "$tmp" && pwd -P)
trap 'rm -rf -- "$tmp"' EXIT
# hyperfine -N splits each command on spaces: no path may hold one.
case "$tmp$bin" in *" "*) echo "run-e2e.sh: a path holds a space: $tmp $bin" >&2; exit 1 ;; esac
mkdir -p "$tmp/home" "$tmp/xdg/config" "$tmp/xdg/data" "$tmp/xdg/state" "$tmp/xdg/cache" "$tmp/run"
chmod 700 "$tmp/run"
H=(env HOME="$tmp/home" XDG_CONFIG_HOME="$tmp/xdg/config" XDG_DATA_HOME="$tmp/xdg/data"
   XDG_STATE_HOME="$tmp/xdg/state" XDG_CACHE_HOME="$tmp/xdg/cache" XDG_RUNTIME_DIR="$tmp/run"
   hyperfine -N --style basic "${runs[@]}")

case "$(uname -s)" in
  Darwin) os=macos; di=$(stat -f '%d:%i' "$tmp/run"); sha=$(shasum -a 256 "$bin") ;;
  *) os=linux; di=$(stat -c '%d:%i' "$tmp/run"); sha=$(sha256sum "$bin") ;;
esac
args="prompt --ctx 1 --record B1 --width 80 --runtime-root=$di:$tmp/run"

bash_ok=$(bash -c 'if (( BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1] >= 501 )); then echo yes; else echo "$BASH_VERSION"; fi')
skipped=
[ "$bash_ok" = yes ] || {
  skipped="bash $bash_ok on PATH is older than 5.1"
  echo "run-e2e.sh: init-bash not timed: $skipped" >&2
}

json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\t\n' '  ')"; }
uptime_before=$(uptime)
commit=$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)

if [ -z "$cold" ]; then
  "${H[@]}" --export-json "$out/prompt.json" "$bin $args" "/usr/bin/true"
  "${H[@]}" --export-json "$out/redraw.json" "$bin $args --redraw"
  # The generator process that `eval "$(bingsu init SHELL)"` runs inside the
  # shell's added start-up time: a measured sub-path of X-23 init.
  "${H[@]}" --export-json "$out/init-gen.json" "$bin init zsh" "$bin init bash" "$bin init fish"
fi

# The rc lines keep $(...) for the timed shell to expand, not this one (SC2016).
mkdir -p "$tmp/zsh-empty" "$tmp/zsh-init" "$tmp/fish-empty/fish" "$tmp/fish-init/fish"
: > "$tmp/zsh-empty/.zshrc"
# shellcheck disable=SC2016
printf 'eval "$(%q init zsh)"\n' "$bin" > "$tmp/zsh-init/.zshrc"
: > "$tmp/fish-empty/fish/config.fish"
printf '%q init fish | source\n' "$bin" > "$tmp/fish-init/fish/config.fish"
"${H[@]}" --export-json "$out/init-zsh$suffix.json" \
  "env ZDOTDIR=$tmp/zsh-empty zsh -i -c exit" "env ZDOTDIR=$tmp/zsh-init zsh -i -c exit"
"${H[@]}" --export-json "$out/init-fish$suffix.json" \
  "env XDG_CONFIG_HOME=$tmp/fish-empty fish -i -c exit" "env XDG_CONFIG_HOME=$tmp/fish-init fish -i -c exit"
if [ "$bash_ok" = yes ]; then
  : > "$tmp/bash-empty.rc"
  # shellcheck disable=SC2016
  printf 'eval "$(%q init bash)"\n' "$bin" > "$tmp/bash-init.rc"
  "${H[@]}" --export-json "$out/init-bash$suffix.json" \
    "bash --noprofile --rcfile $tmp/bash-empty.rc -i -c exit" "bash --noprofile --rcfile $tmp/bash-init.rc -i -c exit"
fi

printf '{"meta":{"os":"%s","arch":%s,"kernel":%s,"commit":%s,"bingsu":%s,"bingsu_sha256":%s,"hyperfine":%s,"zsh":%s,"fish":%s,"bash":%s,"runs":%s,"bash_skipped":%s,"uptime_before":%s,"uptime_after":%s}}\n' \
  "$os" "$(json_str "$(uname -m)")" "$(json_str "$(uname -r)")" "$(json_str "$commit")" \
  "$(json_str "$bin")" "$(json_str "${sha%% *}")" "$(json_str "$(hyperfine --version)")" \
  "$(json_str "$(zsh --version)")" "$(json_str "$(fish --version)")" "$(json_str "$(bash --version | head -n 1)")" \
  "$(json_str "${runs[*]}")" "$(json_str "$skipped")" "$(json_str "$uptime_before")" "$(json_str "$(uptime)")" \
  > "$out/e2e-meta$suffix.jsonl"
echo "wrote $out"
