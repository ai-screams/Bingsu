#!/usr/bin/env bash
# Host side of .github/workflows/pty-stall.yml. Subcommands:
#   prepare <macos|linux>      build bingsu and set up the shells
#   load-start | load-stop     a cargo build loop as background load
#   probe <macos|linux> ARGS   run session_stall.py with ARGS (see its --help)
#   accept <macos|linux> --seed S --out DIR
# Records go only under --out (the runner's temp folder), never into the
# checkout: process lists carry absolute paths.
set -euo pipefail
cmd=${1:?subcommand}
shift
tmp=${RUNNER_TEMP:?RUNNER_TEMP is set by Actions}
image=bingsu-cur-d13

# Exits 2 unless $1 is 1 to 9 digits (the seed comes from a workflow input).
check_seed() {
  [[ $1 =~ ^[0-9]{1,9}$ ]] || { echo "seed must be 1 to 9 digits: $1" >&2; exit 2; }
}

# Value of option $1 in the remaining arguments.
opt() {
  local name=$1
  shift
  while (($#)); do
    if [[ $1 == "$name" ]]; then
      printf '%s\n' "$2"
      return
    fi
    shift
  done
}

# Runs session_stall.py on the host or in the container, writing to $out.
# ARGS may carry --out already: the last --out (added here) wins.
run_probe() {
  local host=$1 out=$2
  shift 2
  mkdir -p "$out"
  if [[ $host == macos ]]; then
    "$BINGSU_PY" tests/shell/probes/session_stall.py --bin "$PWD/target/debug/bingsu" --work "$tmp/stall-work" "$@" --out "$out"
  else
    local cap=()
    # strace runs the shell as its child; SYS_PTRACE only, as in shell.yml.
    if [[ $(opt --trace "$@") == strace ]]; then cap=(--cap-add SYS_PTRACE); fi
    docker run --rm "${cap[@]}" -v "$PWD:/w" -v "$out:/out" -w /w -e PYTHONDONTWRITEBYTECODE=1 -e LC_ALL=C.UTF-8 "$image" \
      sh -c 'install -m 0755 target/x86_64-unknown-linux-musl/debug/bingsu /usr/local/bin/bingsu &&
        exec python3 tests/shell/probes/session_stall.py --bin /usr/local/bin/bingsu --work /root/stall-work "$@" --out /out' sh "$@"
  fi
}

case $cmd in
  prepare)
    if [[ ${1:?host} == macos ]]; then
      brew install bash fish
      python3 -m venv "$tmp/venv"
      "$tmp/venv/bin/python" -m pip install --require-hashes --only-binary=:all: -r tests/shell/requirements.txt
      echo "$(brew --prefix)/bin" >> "$GITHUB_PATH"
      echo "BINGSU_PY=$tmp/venv/bin/python" >> "$GITHUB_ENV"
      cargo build -p bingsu
    else
      cargo build -p bingsu --target x86_64-unknown-linux-musl
      tests/shell/containers/check-digests.sh
      docker build -f tests/shell/containers/cur-d13.Dockerfile -t "$image" tests/shell/containers
    fi
    ;;
  load-start)
    # Lives from this step until load-stop (an always() step): rebuilds
    # bingsu-core in its own target folder, two jobs at a time. It leads its
    # own process group (setsid through python3: macOS has no setsid
    # command), so load-stop ends cargo and rustc with it. A failed build
    # ends the loop: no load would be measured as load.
    # shellcheck disable=SC2016 # $1 expands in the inner shell
    nohup python3 -c 'import os, sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' \
      bash -c 'while :; do
        cargo build -q -j 2 -p bingsu-core --target-dir "$1" || exit 1
        cargo clean -q -p bingsu-core --target-dir "$1" || exit 1
      done' sh "$tmp/load-target" > "$tmp/load.log" 2>&1 &
    echo $! > "$tmp/load.pgid"
    ;;
  load-stop)
    [[ -f $tmp/load.pgid ]] || exit 0
    pgid=$(cat "$tmp/load.pgid")
    kill -TERM -- "-$pgid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      pgrep -g "$pgid" > /dev/null || break
      sleep 1
    done
    if pgrep -g "$pgid" > /dev/null; then
      echo "load group $pgid still has processes:" >&2
      ps -o pid=,command= -g "$pgid" >&2 || true
      exit 1
    fi
    ;;
  probe)
    host=${1:?host}
    shift
    check_seed "$(opt --seed "$@")"
    run_probe "$host" "$(opt --out "$@")" "$@"
    ;;
  accept)
    host=${1:?host}
    shift
    out=$(opt --out "$@")
    seed=$(opt --seed "$@")
    check_seed "$seed"
    # The test double, the existing Session driver: what the PTY tests use.
    rc=0
    run_probe "$host" "$out/bodies" --case all --rounds-bash 1000 --rounds-fish-group 100 --rounds-fish-nul 200 \
      --product stub --driver session --trace "" --seed "$seed" --timeout "$STALL_TIMEOUT" || rc=1
    for i in 1 2 3 4 5; do
      run_probe "$host" "$out/suite-$i" --case suite --seed "$seed" --timeout "$STALL_TIMEOUT" || rc=1
    done
    # session_stall.py exits 1 on any stall or failure; the bodies run is checked too.
    python3 - "$out" <<'EOF' || rc=1
import pathlib, sys
bad = [p for p in pathlib.Path(sys.argv[1]).glob("*/summary.tsv")
       if any(l.split("\t")[5] != "ok" for l in p.read_text().splitlines()[1:])]
sys.exit(f"stalls or failures in {bad}" if bad else 0)
EOF
    exit "$rc"
    ;;
  *)
    echo "unknown subcommand: $cmd" >&2
    exit 2
    ;;
esac
