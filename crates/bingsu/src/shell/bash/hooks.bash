# bingsu hooks for bash 5.1+ (spec section 5). init redefines every
# function on each run; hook registration happens once (F-23).
: "${_bingsu_session:=@SESSION@}"
# Both may come from the environment. Only init's own shapes are kept: a
# 32-digit lowercase hex session and a short decimal counter (the counter
# goes through $(( )), which evaluates subscripts such as a[$(cmd)]).
# nocasematch would let `case` accept uppercase hex (F-18): save, clear,
# restore, as the reader does. The sets are spelled out, never ranges: with
# globasciiranges off a range follows the locale's collation ([0-9] takes
# U+0661 under fa_IR, [a-f] takes é under en_US).
_bingsu_nm=0
if shopt -q nocasematch; then _bingsu_nm=1; shopt -u nocasematch; fi
case $_bingsu_session in
  *[^0123456789abcdef]*) _bingsu_session=@SESSION@ ;;
esac
if (( _bingsu_nm )); then shopt -s nocasematch; fi
unset _bingsu_nm
(( ${#_bingsu_session} == 32 )) || _bingsu_session=@SESSION@
: "${_bingsu_seq:=0}"
_bingsu_rec=

# Runs the pinned binary once; the raw record goes to _bingsu_rec. The group
# redirect keeps bash's own "ignored null byte" warning off the terminal.
_bingsu_call() {
  case $_bingsu_seq in
    ''|*[^0123456789]*|0?*|????????????????*) _bingsu_seq=0 ;;
  esac
  _bingsu_seq=$(( _bingsu_seq + 1 ))
  { _bingsu_rec=$(@BIN@ prompt --ctx 1 --record @RECORD@ "$@" --session "$_bingsu_session" --seq "$_bingsu_seq" @RUNTIME_ROOT@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@; printf .); } 2>/dev/null
  _bingsu_rec=${_bingsu_rec%.}
}

# Hook state is reset on every init, never inherited: an environment value
# for _bingsu_t0 or _bingsu_t1 would make the first duration wrong, and
# either one goes through $(( )) (spec section 5).
_bingsu_s=0 _bingsu_t1= _bingsu_ps1=
_bingsu_p=()
# _bingsu_t0 is a one-element array: PS0 assigns it inside $(( )), and under
# `set -a` that assignment marks it for export before any hook can undo it.
# bash never puts an array in the environment. Element 0 is set (empty), as
# an unset one would make PS0 skip the assignment. A bare $_bingsu_t0, the
# ${_bingsu_t0:0:…} in PS0 and _bingsu_t0= all refer to element 0.
unset _bingsu_t0
_bingsu_t0=('')
# Does PS0 expand in POSIX mode with promptvars off? Fixed by the M1 probe
# tests/shell/probes/bash_ps0_posix.py (1 = expanded, 0 = literal): expanded
# on bash 5.1.16, 5.2.37 and 5.3.20.
_bingsu_ps0_posix=1
# Arithmetic assignment without a subshell; ${x:0:0} prints nothing
# (spec section 5 "bash execution start time"). _bingsu_t0 must be set (an
# unset one skips the assignment), so it is emptied above, never unset.
# With EPOCHREALTIME unset the arithmetic would fail and bash would skip
# every command line (bash 5.1 and 5.3), so the outer ${…+…} drops the
# whole prefix then; the duration is unknown. Every non-digit is removed: a
# locale's decimal point may be a multibyte character (fa_IR, ps_AF: U+066B),
# and any leftover byte is an arithmetic error that stops every command.
# The bracket negation is ^, not !: POSIX mode replaces ! in PS0 with the
# history number (bash 5.1, 5.2, 5.3).
_bingsu_ps0='${EPOCHREALTIME+${_bingsu_t0:0:$((_bingsu_t0=${EPOCHREALTIME//[^0123456789]/}, 0))}}'
# The owned flag says the original PS0 is already saved. A shell sets it
# without export, so an exported one came from the environment and is not
# ours: drop it, or a parent's _bingsu_ps0_orig would replace the user's PS0.
if [[ -n ${_bingsu_ps0_owned+1} && ${_bingsu_ps0_owned@a} == *x* ]]; then
  unset _bingsu_ps0_owned
fi
if [[ -z ${_bingsu_ps0_owned-} ]]; then
  _bingsu_ps0_orig=${PS0-}
  # A PS0 copied from a bingsu shell (an exported PS0, or one set by hand)
  # starts with a bingsu prefix, possibly from another bingsu version whose
  # inner text differs. Every version starts with the same head (the
  # constant up to its first `=`) and ends with the same tail (from its last
  # `,`: `, 0))}}`): cut each such prefix, or it doubles in every nested
  # shell. A PS0 that starts with the head but has no bingsu tail after it
  # is the user's own text and is kept whole. Head and tail are quoted, so
  # they are matched literally.
  _bingsu_nm=0
  if shopt -q nocasematch; then _bingsu_nm=1; shopt -u nocasematch; fi
  _bingsu_h=${_bingsu_ps0%%=*}=
  _bingsu_e=,${_bingsu_ps0##*,}
  while [[ $_bingsu_ps0_orig == "$_bingsu_h"* ]]; do
    _bingsu_r=${_bingsu_ps0_orig#"$_bingsu_h"}
    if [[ $_bingsu_r != *"$_bingsu_e"* ]]; then break; fi
    _bingsu_ps0_orig=${_bingsu_r#*"$_bingsu_e"}
  done
  if (( _bingsu_nm )); then shopt -s nocasematch; fi
  _bingsu_ps0_owned=1
fi

# Capture hook, first in PROMPT_COMMAND. Nothing may run before the first
# assignment, or $? and PIPESTATUS are lost. The end time is read here too,
# so hooks between this one and the install hook do not count as command
# time (spec section 5).
# Both hooks return 0: bash restores $? before each PROMPT_COMMAND element,
# so a hook's return value reaches no other hook, and a non-zero return only
# risks errexit (`set -e` would end the interactive shell). bingsu itself
# uses the saved status in _bingsu_s.
_bingsu_save() {
  _bingsu_s=$? _bingsu_p=("${PIPESTATUS[@]}")
  local t=${EPOCHREALTIME-}
  _bingsu_t1=${t//[^0123456789]/}
  # Under `set -a` every assignment above is marked for export.
  export -n _bingsu_s _bingsu_t1
  return 0
}

# Install hook, last in PROMPT_COMMAND. Options are read right before
# installing (spec section 3). nocasematch is saved and restored (F-18).
_bingsu_install() {
  local nm=0 exp=0 exp0=0 pst km=emacs jc='\j'
  local -a ctx
  if shopt -q nocasematch; then nm=1; shopt -u nocasematch; fi
  if shopt -q promptvars || [[ -o posix ]]; then exp=1; fi
  if shopt -q promptvars || { [[ -o posix ]] && (( _bingsu_ps0_posix )); }; then exp0=1; fi
  if [[ -o vi ]]; then km=viins; fi
  printf -v pst '%s,' "${_bingsu_p[@]}"
  pst=${pst%,}
  if [[ -z $pst ]]; then pst=$_bingsu_s; fi
  ctx=(--width "${COLUMNS:-0}" --status "$_bingsu_s" --pipestatus "$pst" --jobs "${jc@P}" --keymap "$km")
  # No PS0 expansion (Enter only, or expansion off): no duration.
  if [[ -n $_bingsu_t0 && -n $_bingsu_t1 ]]; then
    ctx+=(--duration-ms "$(( (_bingsu_t1 - _bingsu_t0) / 1000 ))")
  fi
  _bingsu_t0= _bingsu_t1=
  _bingsu_call "${ctx[@]}"
  if _bingsu_frame "$_bingsu_rec"; then
    if (( exp )); then
      # Expansion on: a reference, so the data is never expanded.
      _bingsu_ps1=${_bingsu_f[2]}
      PS1='${_bingsu_ps1}'
    else
      # Expansion off: only backslash escapes are decoded.
      PS1=${_bingsu_f[2]//\\/\\\\}
    fi
  else
    PS1='\w ❯ '
  fi
  # Exactly one bingsu prefix while PS0 expands, none otherwise.
  if (( exp0 )); then PS0=$_bingsu_ps0$_bingsu_ps0_orig; else PS0=$_bingsu_ps0_orig; fi
  if [[ ${PROMPT_COMMAND[-1]} != _bingsu_install && -z ${_bingsu_warned_last-} ]]; then
    _bingsu_warned_last=1
    printf '%s\n' @MSG_LATE_HOOK_BASH@ >&2
  fi
  if (( nm )); then shopt -s nocasematch; fi
  # PS1 and PS0 now hold bingsu's rendered strings, not the user's prompt: an
  # exported copy would be expanded by a child bash without bingsu (data run
  # as code with promptvars on, a PS0 prefix that fails under set -u). The
  # globals assigned here would be exported by `set -a`.
  export -n PS1 PS0 _bingsu_rec _bingsu_seq _bingsu_ps1 _bingsu_t1 _bingsu_warned_last
  return 0
}

# Register once (F-23). Function bodies above are redefined on every init.
# Registration is decided by PROMPT_COMMAND itself, not by a flag: a flag
# can arrive from the environment and silently switch bingsu off. A scalar
# PROMPT_COMMAND is element 0 and stays in the middle. nocasematch would
# make the name comparison case-insensitive (F-18).
_bingsu_nm=0 _bingsu_reg=1
if shopt -q nocasematch; then _bingsu_nm=1; shopt -u nocasematch; fi
for _bingsu_h in ${PROMPT_COMMAND[@]+"${PROMPT_COMMAND[@]}"}; do
  if [[ $_bingsu_h == _bingsu_install ]]; then _bingsu_reg=0; fi
done
if (( _bingsu_reg )); then
  # First registration: an inherited value would silence the warning.
  _bingsu_warned_last=
  _bingsu_a=(_bingsu_save)
  for _bingsu_h in ${PROMPT_COMMAND[@]+"${PROMPT_COMMAND[@]}"}; do
    if [[ $_bingsu_h != _bingsu_save ]]; then _bingsu_a+=("$_bingsu_h"); fi
  done
  PROMPT_COMMAND=("${_bingsu_a[@]}" _bingsu_install)
fi
if (( _bingsu_nm )); then shopt -s nocasematch; fi
unset _bingsu_nm _bingsu_reg _bingsu_h _bingsu_e _bingsu_r _bingsu_a
# Last, after every assignment above: an inherited export flag outlives the
# resets, and `set -a` marks each assignment and each function definition
# for export. Without this the rendered prompt, the timings and the hook
# functions reach the environment of every child.
export -n _bingsu_session _bingsu_seq _bingsu_rec _bingsu_f _bingsu_disp _bingsu_note _bingsu_key \
  _bingsu_s _bingsu_p _bingsu_t0 _bingsu_t1 _bingsu_ps0 _bingsu_ps0_orig _bingsu_ps0_owned \
  _bingsu_ps0_posix _bingsu_ps1 _bingsu_warned_last
export -n -f _bingsu_status_ok_core _bingsu_status_ok _bingsu_split _bingsu_frame_core _bingsu_frame \
  _bingsu_classify _bingsu_notice_due _bingsu_call _bingsu_save _bingsu_install
