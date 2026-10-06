source $argv[1]
# F line: element count and hex of each element (bytes, via od).
function _emit_f --argument-names name
    set -l hs
    for e in $_bingsu_f
        set -a hs "$(printf %s "$e" | od -An -v -tx1 | tr -d ' \n')"
    end
    printf 'F\t%s\t%s\t%s\n' $name (count $_bingsu_f) "$(string join , -- $hs)"
end
function _report --argument-names v
    set -l name (string replace -r '\.bin$' '' -- (basename -- $v))
    set -l rec (cat -- $v | string collect -N)
    if _bingsu_frame "$rec"
        _bingsu_classify "$_bingsu_f[9]"
        set -l note $_bingsu_note
        test -n "$note"; or set note -
        printf 'R\t%s\taccept\t%s\t%s\n' $name $_bingsu_disp $note
    else
        printf 'R\t%s\treject\t-\t-\n' $name
    end
    _emit_f $name
end
function _trans --argument-names old new
    set -l key
    if test "$new" = @no-record
        set key no-record
    else
        _bingsu_classify "$new"
        set key $_bingsu_key
    end
    set -l due no
    _bingsu_notice_due "$old" "$key"; and set due yes
    printf 'T\t%s\t%s\t%s\t%s\n' "$old" "$new" $due "$key"
end
for v in $argv[2]/*.bin
    _report $v
end
# _bingsu_status_ok called on its own must anchor at the true end of string.
if _bingsu_status_ok (printf 'ok:none\n' | string collect -N)
    printf 'U\tstatus_ok_lf\taccept\n'
else
    printf 'U\tstatus_ok_lf\treject\n'
end
while read -l -d '|' old new rest
    string match -q '#*' -- "$old"; and continue
    _trans "$old" "$new"
end < $argv[3]
