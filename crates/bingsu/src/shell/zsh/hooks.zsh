# bingsu hooks for zsh (spec section 5). init redefines every function on
# each run; hook registration happens once (F-23). @…@ markers are literal
# shell words embedded by init.
: ${_bingsu_session:=@SESSION@}
# Both may come from the environment. Only init's own shapes are kept: a
# 32-digit lowercase hex session and a short decimal counter (a value with
# a subscript would be evaluated as arithmetic).
case $_bingsu_session in
  (*[^0-9a-f]*) _bingsu_session=@SESSION@ ;;
esac
(( ${#_bingsu_session} == 32 )) || _bingsu_session=@SESSION@
case ${_bingsu_seq-} in
  (''|*[^0-9]*|0?*|????????????????*) _bingsu_seq=0 ;;
esac
typeset -gi _bingsu_seq
typeset -g _bingsu_rec=

# Runs the pinned binary once; the raw record goes to _bingsu_rec.
_bingsu_call() {
  emulate -L zsh
  (( ++_bingsu_seq ))
  _bingsu_rec=$(@BIN@ prompt --ctx 1 --record @RECORD@ "$@" --session "$_bingsu_session" --seq "$_bingsu_seq" @RUNTIME_ROOT@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@; print -n .)
  _bingsu_rec=${_bingsu_rec%.}
}
