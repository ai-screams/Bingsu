# bingsu prompt for fish 3.6+ (spec section 5). init redefines every
# function on each run.
set -q _bingsu_session; or set -g _bingsu_session @SESSION@
set -q _bingsu_seq; or set -g _bingsu_seq 0
# Both may come from the environment. Only init's own shapes are kept: a
# 32-digit lowercase hex session and a short decimal counter.
string match -qr '^[0-9a-f]{32}\z' -- "$_bingsu_session"; or set -g _bingsu_session @SESSION@
set -g _bingsu_rec ''

# Byte length of $argv[1]: string length counts characters; the URL escape
# writes every byte it changes as %XX, so the bytes are its length minus two
# per %.
function _bingsu_bytes
    set -l e (string escape --style=url -- "$argv[1]")
    math (string length -- "$e") - 2 \* (string replace -ar '[^%]' '' -- "$e" | string length)
end

# Runs the pinned binary once; the raw record goes to _bingsu_rec. A call
# that a signal ended (status 128 or more: a crash, or on Linux the seccomp
# filter) is not repeated until the next command: a dead call sets
# _bingsu_dead and fish_postexec clears it (the status generation does not
# move for a command that sets no status, such as `set x 1`). Without this
# fish 3.6 reports the signal, redraws, calls again and loops (same rule as
# hooks.zsh).
function _bingsu_call
    if test -n "$_bingsu_dead"
        set -g _bingsu_rec ''
        return 0
    end
    string match -qr '^(0|[1-9][0-9]{0,14})\z' -- "$_bingsu_seq"; or set -g _bingsu_seq 0
    set -g _bingsu_seq (math $_bingsu_seq + 1)
    # Over 64 KiB (bytes): passed empty (see hooks.zsh). fish's $PWD can be
    # that long when fish starts in a deep folder (test_fish_long_cwd).
    set -l _bingsu_pwd $PWD
    if test (_bingsu_bytes $PWD) -gt 65536
        # An empty list: the quotes below make it one empty word.
        set _bingsu_pwd
    end
    set -l _bingsu_log off
    switch "$BINGSU_LOG"
        case error info debug
            set _bingsu_log "$BINGSU_LOG"
    end
    set -l _bingsu_host "$hostname"
    set -l _bingsu_venv "$VIRTUAL_ENV"
    set -l _bingsu_colorfgbg "$COLORFGBG"
    if test (_bingsu_bytes "$_bingsu_colorfgbg") -gt 65536
        set _bingsu_colorfgbg
    end
    if test (_bingsu_bytes "$_bingsu_host") -gt 65536
        set _bingsu_host
    end
    if test (_bingsu_bytes "$_bingsu_venv") -gt 65536
        set _bingsu_venv
    end
    set -l _bingsu_ssh 0
    if test -n "$SSH_CONNECTION"; or test -n "$SSH_TTY"
        set _bingsu_ssh 1
    end
    set -g _bingsu_rec (@BIN@ prompt --ctx 1 --record @RECORD@ $argv --shell fish --pwd "$_bingsu_pwd" --colorterm "$COLORTERM" --colorfgbg "$_bingsu_colorfgbg" "--log-level=$_bingsu_log" --host "$_bingsu_host" --venv "$_bingsu_venv" "--ssh=$_bingsu_ssh" --session $_bingsu_session --seq $_bingsu_seq @RUNTIME_ROOT@ @RUNTIME_GROUPS@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@ @HOME@ @COLLECTOR_EXE@ | string collect -N)
    if test $pipestatus[1] -ge 128
        set -g _bingsu_dead 1
    end
end

function _bingsu_postexec --on-event fish_postexec
    set -g _bingsu_dead ''
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
    # A user may set either variable to anything. Stricter than the zsh and
    # bash hooks, which pass ${COLUMNS:-0} unchecked; the core checks every
    # value again.
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
        # The prompt ran without its system call filter (decision P18): said
        # once per session, with a constant from init.
        if test "$_bingsu_f[10]" = @STATUS_SANDBOX@; and not set -q _bingsu_warned_sandbox[1]
            set -g _bingsu_warned_sandbox 1
            printf '%s\n' @MSG_NO_SANDBOX@ >&2
        end
        # Upper line (record change plan 12, R-04): a newline only when it is not empty.
        if test -n "$_bingsu_f[9]"
            printf '%s\n%s' "$_bingsu_f[9]" "$_bingsu_f[3]"
        else
            printf '%s' "$_bingsu_f[3]"
        end
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
set -g _bingsu_dead ''
# An exported value came from the environment: it would silence the notice.
set -qx _bingsu_warned_sandbox; and set -e _bingsu_warned_sandbox

# Last, after every assignment above: a name that came from the environment
# is an exported global, and set -g keeps that flag, so the raw record and
# the hook state would reach the environment of every child. set -gu needs
# the value repeated: without one it empties the variable. The reader
# unexports its own globals as well (_bingsu_f, _bingsu_disp, _bingsu_note,
# _bingsu_key), since the golden runner sources it alone; they stay here too.
set -gu _bingsu_session $_bingsu_session
set -gu _bingsu_seq $_bingsu_seq
set -gu _bingsu_rec $_bingsu_rec
set -gu _bingsu_rps1 $_bingsu_rps1
set -gu _bingsu_f $_bingsu_f
set -gu _bingsu_disp $_bingsu_disp
set -gu _bingsu_note $_bingsu_note
set -gu _bingsu_key $_bingsu_key
set -gu _bingsu_gen $_bingsu_gen
set -gu _bingsu_dead $_bingsu_dead
