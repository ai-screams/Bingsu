# bingsu record reader (spec section 3) and status receive semantics
# (spec section 5). Embedded by `bingsu init fish`; @KNOWN_CODES@ is
# replaced with the known non-ok status strings as quoted words.
set -g _bingsu_f
set -g _bingsu_disp ''
set -g _bingsu_note ''
set -g _bingsu_key ''

function _bingsu_status_ok --argument-names s
    string match -q -r '^[abcdefghijklmnopqrstuvwxyz]+:[abcdefghijklmnopqrstuvwxyz-]+\z' -- "$s"
end

function _bingsu_frame --argument-names rec
    set -g _bingsu_f
    test (string length -- "$rec") -le 65536; or return 1
    # \z, not $: $ also matches before a final newline. Double defence with the
    # count check; a black-box golden cannot tell either layer apart alone.
    string match -q -r '^[^\x1e\n]*\x1e\z' -- "$rec"; or return 1
    set -l f (string split \x1f -- (string replace -r '\x1e\z' '' -- "$rec"))
    test (count $f) -eq 9; or return 1
    test "$f[1]" = B1; and test "$f[2]" = 7; or return 1
    _bingsu_status_ok "$f[9]"; or return 1
    # Contract: on failure _bingsu_f is empty; it is set only after every check.
    set -g _bingsu_f $f
end

# Call only after _bingsu_status_ok passed. Exact comparisons only.
function _bingsu_classify --argument-names st
    set -g _bingsu_note ''
    set -l parts (string split -m 1 : -- "$st")
    if test "$parts[1]" = ok
        set -g _bingsu_disp ok
        set -g _bingsu_key ''
        return 0
    end
    if test "$parts[1]" = notice
        set -g _bingsu_disp notice
    else if test "$parts[1]" = degraded
        set -g _bingsu_disp degraded
    else if test "$parts[1]" = error
        set -g _bingsu_disp error
    else
        set -g _bingsu_disp degraded
    end
    set -g _bingsu_key "$st"
    set -g _bingsu_note generic
    for k in @KNOWN_CODES@
        if test "$st" = "$k"
            set -g _bingsu_note $k
            break
        end
    end
end

function _bingsu_notice_due --argument-names old new
    test -n "$new"; and test "$new" != "$old"
end
