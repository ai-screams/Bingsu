#!/usr/bin/env bash
# Run the record golden vectors for every shell, locale and option set.
# Usage: SHELLS="bash zsh fish" LOCALES="C.UTF-8 C ko_KR.UTF-8" run-all.sh
# Used by the Linux container job and the macOS job in shell.yml.
set -uo pipefail
cd "$(dirname "$0")/../../.."
shells=${SHELLS:-bash zsh fish}
locales=${LOCALES:-C.UTF-8 C ko_KR.UTF-8}
fail=0
run() { python3 tests/golden/record/run.py "$@" || fail=1; }
for sh in $shells; do
  for loc in $locales; do
    case $sh in
      zsh) for o in "" ksharrays nopromptpercent ksharrays,nopromptpercent; do
             run --shell zsh --locale "$loc" --opts "$o"; done ;;
      bash) for o in "" nocasematch; do
              run --shell bash --locale "$loc" --opts "$o"; done ;;
      fish) run --shell fish --locale "$loc" ;;
      *) echo "unknown shell: $sh" >&2; fail=1 ;;
    esac
  done
done
exit "$fail"
