for _o in ${BINGSU_TEST_SHOPT//,/ }; do shopt -s "$_o"; done
source "$1"
# F line: element count and hex of each element (bytes, via od).
_emit_f() {
  local name=$1 e hex joined= i=0
  for e in "${_bingsu_f[@]}"; do
    hex=$(printf %s "$e" | od -An -v -tx1 | tr -d ' \n')
    if (( i++ )); then joined+=,$hex; else joined=$hex; fi
  done
  printf 'F\t%s\t%s\t%s\n' "$name" "${#_bingsu_f[@]}" "$joined"
}
_report() {
  local v=$1 name rec nm_before=off nm_after=off
  name=${v##*/}; name=${name%.bin}
  { rec=$(cat -- "$v"; printf .); } 2>/dev/null
  rec=${rec%.}
  if shopt -q nocasematch; then nm_before=on; fi
  if _bingsu_frame "$rec"; then
    if shopt -q nocasematch; then nm_after=on; fi
    _bingsu_classify "${_bingsu_f[8]}"
    printf 'R\t%s\taccept\t%s\t%s\n' "$name" "$_bingsu_disp" "${_bingsu_note:--}"
  else
    if shopt -q nocasematch; then nm_after=on; fi
    printf 'R\t%s\treject\t-\t-\n' "$name"
  fi
  printf 'S\t%s\t%s\t%s\n' "$name" "$nm_before" "$nm_after"
  _emit_f "$name"
}
_trans() {
  local old=$1 new=$2 key due=no
  if [[ $new == @no-record ]]; then key=no-record; else _bingsu_classify "$new"; key=$_bingsu_key; fi
  if _bingsu_notice_due "$old" "$key"; then due=yes; fi
  printf 'T\t%s\t%s\t%s\t%s\n' "$old" "$new" "$due" "$key"
}
for _v in "$2"/*.bin; do _report "$_v"; done
# _bingsu_status_ok called on its own must also ignore nocasematch (R5).
if _bingsu_status_ok OK:NONE; then printf 'U\tstatus_ok_upper\taccept\n'; else printf 'U\tstatus_ok_upper\treject\n'; fi
while IFS='|' read -r _old _new _rest; do
  [[ $_old == \#* ]] && continue
  _trans "$_old" "$_new"
done < "$3"
