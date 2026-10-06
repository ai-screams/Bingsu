# bingsu hooks for bash 5.1+ (spec section 5). init redefines every
# function on each run; hook registration happens once (F-23).
: "${_bingsu_session:=@SESSION@}"
# Both may come from the environment. Only init's own shapes are kept: a
# 32-digit lowercase hex session and a short decimal counter (the counter
# goes through $(( )), which evaluates subscripts such as a[$(cmd)]).
# nocasematch would let `case` accept uppercase hex (F-18): save, clear,
# restore, as the reader does.
_bingsu_nm=0
if shopt -q nocasematch; then _bingsu_nm=1; shopt -u nocasematch; fi
case $_bingsu_session in
  *[!0-9a-f]*) _bingsu_session=@SESSION@ ;;
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
    ''|*[!0-9]*|0?*|????????????????*) _bingsu_seq=0 ;;
  esac
  _bingsu_seq=$(( _bingsu_seq + 1 ))
  { _bingsu_rec=$(@BIN@ prompt --ctx 1 --record @RECORD@ "$@" --session "$_bingsu_session" --seq "$_bingsu_seq" @RUNTIME_ROOT@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@; printf .); } 2>/dev/null
  _bingsu_rec=${_bingsu_rec%.}
}
