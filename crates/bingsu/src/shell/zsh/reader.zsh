# bingsu record reader (spec section 3) and status receive semantics
# (spec section 5). Embedded by `bingsu init zsh`; @KNOWN_CODES@ is
# replaced with the known non-ok status strings as quoted words.
typeset -ga _bingsu_f
typeset -g _bingsu_disp= _bingsu_note= _bingsu_key=

_bingsu_status_ok() {
  emulate -L zsh
  local s=$1 cls code
  [[ $s == *:* ]] || return 1
  cls=${s%%:*} code=${s#*:}
  [[ -n $cls && -n $code ]] || return 1
  [[ $cls != *[^abcdefghijklmnopqrstuvwxyz]* ]] || return 1
  [[ $code != *[^abcdefghijklmnopqrstuvwxyz-]* ]]
}

_bingsu_frame() {
  emulate -L zsh
  local rec=$1
  (( ${#rec} <= 65536 )) || return 1
  [[ $rec == *$'\x1e' ]] || return 1
  rec=${rec%$'\x1e'}
  [[ $rec == *[$'\x1e\n']* ]] && return 1
  _bingsu_f=("${(@ps:\x1f:)rec}")
  (( ${#_bingsu_f} == 9 )) || return 1
  [[ $_bingsu_f[1] == B1 && $_bingsu_f[2] == 7 ]] || return 1
  _bingsu_status_ok "$_bingsu_f[9]"
}

# Call only after _bingsu_status_ok passed. The status string never selects
# code or text: only exact comparisons with constants embedded by init.
_bingsu_classify() {
  emulate -L zsh
  local st=$1 cls=${1%%:*} k
  _bingsu_note=
  if [[ $cls == ok ]]; then
    _bingsu_disp=ok _bingsu_key=
    return 0
  fi
  if [[ $cls == notice ]]; then _bingsu_disp=notice
  elif [[ $cls == degraded ]]; then _bingsu_disp=degraded
  elif [[ $cls == error ]]; then _bingsu_disp=error
  else _bingsu_disp=degraded
  fi
  _bingsu_key=$st _bingsu_note=generic
  for k in @KNOWN_CODES@; do
    if [[ $st == "$k" ]]; then _bingsu_note=$k; break; fi
  done
  return 0
}

_bingsu_notice_due() {
  [[ -n $2 && "$2" != "$1" ]]
}
