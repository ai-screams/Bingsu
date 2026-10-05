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
# $status_generation, $status and $pipestatus are read by a single command so
# none is reset before the others are saved. An empty variable expands to no
# word in fish, so a value that may be empty gets a default or leaves its
# flag out: a missing word would make the flag before it take the next flag
# as its value.
function fish_prompt
    set -l sp $status_generation $status $pipestatus
    set -l g $sp[1]
    set -l s $sp[2]
    set -l pst (string join , -- $sp[3..-1])
    # Shapes as zsh and bash pass them: a user may set either variable to
    # anything. The core checks every value again.
    set -l w $COLUMNS
    string match -qr '^[0123456789]{1,6}\z' -- "$w"; or set w 0
    set -l ctx --width $w --status $s --pipestatus $pst --jobs (count (jobs -p 2>/dev/null))
    # The envelope takes a keymap of 1 to 16 bytes from [a-z_] and refuses the
    # whole call otherwise. A bind mode may be any name (My-Mode, mode2): such
    # a mode, or none, leaves the flag out instead of guessing one. The set is
    # spelled out, as in the reader.
    if string match -qr '^[abcdefghijklmnopqrstuvwxyz_]{1,16}\z' -- "$fish_bind_mode"
        set -a ctx --keymap $fish_bind_mode
    end
    # fish leaves CMD_DURATION at the last command's value when the line runs
    # nothing (empty, blanks, a comment, a lone `;`): only a new status
    # generation says a command ran since the last prompt. A command that
    # sets no status (`set x 1`, `begin; end`) sends no duration, never an
    # old one. A redraw of the same prompt (Ctrl-L) sends none either: fish
    # gives no signal that tells it from an empty line.
    if test "$g" != "$_bingsu_gen"; and string match -qr '^[0123456789]{1,9}\z' -- "$CMD_DURATION"
        set -a ctx --duration-ms $CMD_DURATION
    end
    set -g _bingsu_gen $g
    _bingsu_call $ctx
    # fish prints the function's output as is; '%s' keeps % and \ in the
    # data from being read as a format.
    if _bingsu_frame "$_bingsu_rec"
        set -g _bingsu_rps1 $_bingsu_f[4]
        printf '%s' $_bingsu_f[3]
    else
        # A constant, never the directory: fish 3.6 and 4.0 print control
        # characters of a folder name as they are (prompt_pwd). The renderer
        # cleans the directory before it goes into a record.
        set -g _bingsu_rps1 ''
        printf '❯ '
    end
end

# Never runs bingsu: prints the value saved by fish_prompt, which fish runs
# first in each draw.
function fish_right_prompt
    printf '%s' $_bingsu_rps1
end

# The generation at init, never an inherited one: a value from the
# environment would make the first prompt send the last command's duration.
set -g _bingsu_gen $status_generation

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
set -gu _bingsu_gen $_bingsu_gen
