# bingsu M1: log the init time of the first two shells after boot (record only):
# the first is phase=cold, the second phase=warm; later shells log nothing.
# A row is written only when `bingsu init` exits 0 (its status is in the row).
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
    _m1_n=$(grep -c -F -- "$_m1_boot" "$BINGSU_M1_FIRST_SHELL_LOG" 2>/dev/null)
    case "${_m1_n:-0}" in
      0) _m1_phase=cold ;;
      1) _m1_phase=warm ;;
      *) _m1_phase= ;;
    esac
    [ -n "$_m1_boot" ] || _m1_phase=
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
      if [ "$_m1_rc" -eq 0 ]; then
        printf '%s\t%s\t%s\tphase=%s\tstatus=%s\t%sus\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$_m1_boot" "$_m1_sh" \
          "$_m1_phase" "$_m1_rc" "$(( _m1_t1 - _m1_t0 ))" >> "$BINGSU_M1_FIRST_SHELL_LOG"
      fi
    fi
  fi
  unset _m1_boot _m1_n _m1_phase _m1_sh _m1_t0 _m1_t1 _m1_rc _m1_f _m1_clock0 _m1_clock1
fi
unset -f _m1_us_of
