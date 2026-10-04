# bingsu record reader (spec section 3) and status receive semantics
# (spec section 5). Embedded by `bingsu init bash`; @KNOWN_CODES@ is
# replaced with the known non-ok status strings as quoted words.
_bingsu_f=()
_bingsu_disp= _bingsu_note= _bingsu_key=

_bingsu_status_ok() {
  local s=$1 cls code
  [[ $s == *:* ]] || return 1
  cls=${s%%:*} code=${s#*:}
  [[ -n $cls && -n $code ]] || return 1
  [[ $cls != *[!abcdefghijklmnopqrstuvwxyz]* ]] || return 1
  [[ $code != *[!abcdefghijklmnopqrstuvwxyz-]* ]]
}

# Variant R (spec text): read -a on a here-string. Drops a trailing empty
# field, which is harmless because the status is never empty.
_bingsu_split() {
  local IFS=$'\x1f'
  read -r -a _bingsu_f <<<"$1"
}

_bingsu_frame_core() {
  local rec=$1
  (( ${#rec} <= 65536 )) || return 1
  [[ $rec == *$'\x1e' ]] || return 1
  rec=${rec%$'\x1e'}
  [[ $rec == *[$'\x1e\n']* ]] && return 1
  _bingsu_split "$rec"
  (( ${#_bingsu_f[@]} == 9 )) || return 1
  [[ ${_bingsu_f[0]} == B1 && ${_bingsu_f[1]} == 7 ]] || return 1
  _bingsu_status_ok "${_bingsu_f[8]}"
}

# nocasematch would make [[ == ]] case-insensitive (F-18): save, clear, restore.
_bingsu_frame() {
  local nm=0 r=0
  if shopt -q nocasematch; then nm=1; shopt -u nocasematch; fi
  _bingsu_frame_core "$1" || r=1
  if (( nm )); then shopt -s nocasematch; fi
  return "$r"
}

# Call only after _bingsu_status_ok passed (inputs are then lowercase, so
# nocasematch cannot change any comparison below).
_bingsu_classify() {
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
