#!/bin/sh
# Test double for a bingsu binary from before M3a (main 119578e and older):
# its envelope parser refuses any argument it does not know, so the display
# words of M3a (--shell, --pwd, --colorterm, --home=) give the minimal
# record with error:bad-args (crates/bingsu/tests/cli_prompt.rs pins the
# same rule for unknown arguments). Logs argv like fake_bingsu.sh.
here=${0%/*}
for a in "$@"; do printf '%s\0' "$a"; done >> "$here/argv.log"
printf 'END\0' >> "$here/argv.log"
status=ok:none
for a in "$@"; do
  case $a in
    --shell|--pwd|--colorterm|--home=*) status=error:bad-args ;;
  esac
done
printf 'B1\0378\037> \037\037\037\037\037\037\037%s\036' "$status"
