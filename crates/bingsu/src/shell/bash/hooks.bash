# bingsu hooks for bash 5.1+ (spec section 5). init redefines every
# function on each run; hook registration happens once (F-23).
: "${_bingsu_session:=@SESSION@}"
: "${_bingsu_seq:=0}"
_bingsu_rec=

# Runs the pinned binary once; the raw record goes to _bingsu_rec. The group
# redirect keeps bash's own "ignored null byte" warning off the terminal.
_bingsu_call() {
  _bingsu_seq=$(( _bingsu_seq + 1 ))
  { _bingsu_rec=$(@BIN@ prompt --ctx 1 --record @RECORD@ "$@" --session "$_bingsu_session" --seq "$_bingsu_seq" @RUNTIME_ROOT@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@; printf .); } 2>/dev/null
  _bingsu_rec=${_bingsu_rec%.}
}
