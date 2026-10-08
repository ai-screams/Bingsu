# shellcheck shell=bash
# bingsu M1: log the init time of the first two shells after boot (record only):
# the first is phase=cold, the second phase=warm; later shells log nothing.
# Each phase is reserved before it is timed with `mkdir LOG.<boot>.<phase>`,
# which only one shell can win, so two shells starting together take cold
# and warm, never cold twice. A reservation is never given back: a failed
# `bingsu init` still writes its row with status=<rc> (the reader treats that
# boot's phase as not measured; a later shell is not cold any more, since the
# failed run already loaded the pages). A shell killed during init leaves a
# reservation and no row; that boot has no cold row, so reboot and measure
# again. The reservation folders sit next to the log; remove them with the
# log after the measurement.
# zsh, or bash 5 and later (EPOCHREALTIME); other shells log nothing and say so.
# Nothing here edits a shell rc: a person adds these two lines to the rc,
# *before* the bingsu init line, and removes them after the reboot measurement:
#   export BINGSU_M1_FIRST_SHELL_LOG="$HOME/bingsu-m1-manual/first-shell-<os>-<host>.tsv"
#   source "<checkout>/bench/first-shell-logger.sh"
# Columns (tab-separated): UTC time, boot identity (macOS kern.bootsessionuuid,
# Linux boot_id, as bench/probes/x05-boot-id.sh), shell, phase=, status=, time in us.

# Microseconds from one stored EPOCHREALTIME value (zsh prints 9 decimals,
# bash 6, some locales use a comma).
_m1_us_of() {
  _m1_f=${1#*[.,]}000000
  echo $(( ${1%[.,]*} * 1000000 + 10#${_m1_f:0:6} ))
}

if [ -n "${BINGSU_M1_FIRST_SHELL_LOG-}" ]; then
  [ -n "${ZSH_VERSION-}" ] && zmodload zsh/datetime
  if [ -z "${EPOCHREALTIME-}" ]; then
    echo "bingsu m1 first-shell logger: no EPOCHREALTIME in this shell (zsh, or bash 5+); nothing logged" >&2
  else
    case "$(uname -s)" in
      Darwin) _m1_boot=$(sysctl -n kern.bootsessionuuid) ;;
      *) _m1_boot=$(cat /proc/sys/kernel/random/boot_id) ;;
    esac
    _m1_phase=
    if [ -z "$_m1_boot" ]; then
      echo "bingsu m1 first-shell logger: no boot identity; nothing logged" >&2
    elif [ ! -d "${BINGSU_M1_FIRST_SHELL_LOG%/*}" ]; then
      echo "bingsu m1 first-shell logger: no folder ${BINGSU_M1_FIRST_SHELL_LOG%/*}; nothing logged" >&2
    else
      for _m1_p in cold warm; do
        if mkdir -- "$BINGSU_M1_FIRST_SHELL_LOG.$_m1_boot.$_m1_p" 2>/dev/null; then
          _m1_phase=$_m1_p
          break
        fi
      done
    fi
    if [ -n "$_m1_phase" ]; then
      _m1_sh=${ZSH_VERSION:+zsh}${BASH_VERSION:+bash}
      # The bracket: two raw clock reads around the measured command only (no
      # command substitution, no other process in between). Convert afterwards.
      _m1_clock0=$EPOCHREALTIME
      bingsu init "$_m1_sh" >/dev/null 2>&1
      _m1_rc=$?
      _m1_clock1=$EPOCHREALTIME
      _m1_t0=$(_m1_us_of "$_m1_clock0")
      _m1_t1=$(_m1_us_of "$_m1_clock1")
      printf '%s\t%s\t%s\tphase=%s\tstatus=%s\t%sus\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_m1_boot" "$_m1_sh" \
        "$_m1_phase" "$_m1_rc" "$(( _m1_t1 - _m1_t0 ))" >> "$BINGSU_M1_FIRST_SHELL_LOG"
    fi
  fi
  unset _m1_boot _m1_p _m1_phase _m1_sh _m1_t0 _m1_t1 _m1_rc _m1_f _m1_clock0 _m1_clock1
fi
unset -f _m1_us_of
