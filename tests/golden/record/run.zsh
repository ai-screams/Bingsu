# Applies the user options under test at top level, then sources the reader.
for _o in ${(s:,:)BINGSU_TEST_OPTS}; do setopt $_o; done
source "$1"
# The reader must run under the user's options, not under the runner's own
# `emulate -L zsh` (zsh options are dynamically scoped, so a caller's emulate
# would hide a reader that forgot its own).
_in_user_opts() {
  emulate -L zsh
  local o
  for o in ${(s:,:)BINGSU_TEST_OPTS}; do setopt $o; done
  "$@"
}
_report() {
  emulate -L zsh
  local v=$1 name=${1:t:r} rec
  rec=$(cat -- "$v"; print -n .); rec=${rec%.}
  if _in_user_opts _bingsu_frame "$rec"; then
    _in_user_opts _bingsu_classify "$_bingsu_f[9]"
    print -r -- "R	$name	accept	$_bingsu_disp	${_bingsu_note:--}"
  else
    print -r -- "R	$name	reject	-	-"
  fi
}
_trans() {
  emulate -L zsh
  local old=$1 new=$2 key due=no
  if [[ $new == @no-record ]]; then key=no-record; else _in_user_opts _bingsu_classify "$new"; key=$_bingsu_key; fi
  _in_user_opts _bingsu_notice_due "$old" "$key" && due=yes
  print -r -- "T	$old	$new	$due	$key"
}
for _v in "$2"/*.bin; do _report "$_v"; done
while IFS='|' read -r _old _new _rest; do
  [[ $_old == \#* ]] && continue
  _trans "$_old" "$_new"
done < "$3"
