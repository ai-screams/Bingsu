# bingsu prompt for fish 3.6+ (spec section 5). init redefines every
# function on each run.
set -q _bingsu_session; or set -g _bingsu_session @SESSION@
set -q _bingsu_seq; or set -g _bingsu_seq 0
# Both may come from the environment. Only init's own shapes are kept: a
# 32-digit lowercase hex session and a short decimal counter.
string match -qr '^[0-9a-f]{32}\z' -- "$_bingsu_session"; or set -g _bingsu_session @SESSION@
set -g _bingsu_rec ''

# Runs the pinned binary once; the raw record goes to _bingsu_rec.
function _bingsu_call
    string match -qr '^(0|[1-9][0-9]{0,14})\z' -- "$_bingsu_seq"; or set -g _bingsu_seq 0
    set -g _bingsu_seq (math $_bingsu_seq + 1)
    set -g _bingsu_rec (@BIN@ prompt --ctx 1 --record @RECORD@ $argv --session $_bingsu_session --seq $_bingsu_seq @RUNTIME_ROOT@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@ | string collect -N)
end
set -g _bingsu_rps1 ''

# fish draws through this function, so capture and install are one place.
# $status and $pipestatus are read by a single command so neither is reset
# before the other is saved. An empty variable expands to no word in fish,
# so each value that may be empty gets a default: a missing word would make
# the flag before it take the next flag as its value.
function fish_prompt
    set -l sp $status $pipestatus
    set -l s $sp[1]
    set -l pst (string join , -- $sp[2..-1])
    set -l w $COLUMNS
    test -n "$w"; or set w 0
    set -l km $fish_bind_mode
    test -n "$km"; or set km default
    set -l ctx --width $w --status $s --pipestatus $pst --jobs (count (jobs -p 2>/dev/null)) --keymap $km
    if test -n "$CMD_DURATION"
        set -a ctx --duration-ms $CMD_DURATION
    end
    _bingsu_call $ctx
    # fish prints the function's output as is; '%s' keeps % and \ in the
    # data from being read as a format.
    if _bingsu_frame "$_bingsu_rec"
        set -g _bingsu_rps1 $_bingsu_f[4]
        printf '%s' $_bingsu_f[3]
    else
        set -g _bingsu_rps1 ''
        printf '%s ❯ ' (prompt_pwd)
    end
end

# Never runs bingsu: prints the value saved by fish_prompt, which fish runs
# first in each draw.
function fish_right_prompt
    printf '%s' $_bingsu_rps1
end

# Last, after every assignment above: a name that came from the environment
# is an exported global, and set -g keeps that flag, so the raw record and
# the hook state would reach the environment of every child. set -gu needs
# the value repeated: without one it empties the variable.
set -gu _bingsu_session $_bingsu_session
set -gu _bingsu_seq $_bingsu_seq
set -gu _bingsu_rec $_bingsu_rec
set -gu _bingsu_rps1 $_bingsu_rps1
set -gu _bingsu_f $_bingsu_f
set -gu _bingsu_disp $_bingsu_disp
set -gu _bingsu_note $_bingsu_note
set -gu _bingsu_key $_bingsu_key
