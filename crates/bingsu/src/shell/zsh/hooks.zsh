# bingsu hooks for zsh (spec section 5). init redefines every function on
# each run; hook registration happens once (F-23). @…@ markers are literal
# shell words embedded by init.
# typeset keeps attributes set earlier in this shell (an integer would evaluate
# the prompt text as arithmetic), so every owned name starts over; the three
# that outlive a re-init keep their value.
() {
  emulate -L zsh
  local session=${_bingsu_session-} seq=${_bingsu_seq-} warned=${_bingsu_warned_last-}
  unset _bingsu_session _bingsu_seq _bingsu_warned_last _bingsu_rec _bingsu_s _bingsu_p \
    _bingsu_t0 _bingsu_t1 _bingsu_ps1 _bingsu_rps1 _bingsu_dead _bingsu_key_prev _bingsu_nested
  typeset -g _bingsu_session=$session _bingsu_seq=$seq _bingsu_warned_last=$warned
}
: "${_bingsu_session:=@SESSION@}"
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

# Runs the pinned binary once; the raw record goes to _bingsu_rec. A call
# that a signal ended (status 128 or more: a crash, or on Linux the seccomp
# filter) is not repeated until the next command runs (_bingsu_preexec
# clears _bingsu_dead): the prompt is the fallback until then. Same rule in
# every hook; fish 3.6 would otherwise redraw and call again forever. The
# assignment runs before ||, a context that also covers the substitution's
# subshell: a failed call keeps its status but fires no ZERR trap of the user.
_bingsu_call() {
  emulate -L zsh
  if [[ -n $_bingsu_dead ]]; then
    _bingsu_rec=
    return 0
  fi
  (( ++_bingsu_seq ))
  # A $PWD over 64 KiB (bytes) is drawn as unknown anyway (envelope rule);
  # passing it would put it in argv a second time next to the environment
  # and can hit ARG_MAX. no_multibyte (local, emulate -L) makes ${#} count
  # bytes. An exported PWD over MAX_ARG_STRLEN (32 pages, about 128 KiB with
  # 4 KiB pages) cannot reach any exec on Linux, whatever this hook passes.
  # zsh parses $(…) when it runs, under emulate's aliases, not with this body.
  local _bingsu_pwd=$PWD _bingsu_st=0
  setopt no_multibyte no_aliases
  (( ${#_bingsu_pwd} <= 65536 )) || _bingsu_pwd=
  local _bingsu_log=off _bingsu_host=${HOST-} _bingsu_venv=${VIRTUAL_ENV-} _bingsu_ssh=0 _bingsu_colorfgbg=${COLORFGBG-}
  case ${BINGSU_LOG-} in error|info|debug) _bingsu_log=$BINGSU_LOG ;; esac
  (( ${#_bingsu_host} <= 65536 )) || _bingsu_host=
  (( ${#_bingsu_venv} <= 65536 )) || _bingsu_venv=
  (( ${#_bingsu_colorfgbg} <= 65536 )) || _bingsu_colorfgbg=
  [[ -n ${SSH_CONNECTION-} || -n ${SSH_TTY-} ]] && _bingsu_ssh=1
  _bingsu_rec=$(@BIN@ prompt --ctx 1 --record @RECORD@ "$@" --shell zsh --pwd "$_bingsu_pwd" --colorterm "${COLORTERM-}" --colorfgbg "$_bingsu_colorfgbg" "--log-level=$_bingsu_log" --host "$_bingsu_host" --venv "$_bingsu_venv" "--ssh=$_bingsu_ssh" --session "$_bingsu_session" --seq "$_bingsu_seq" @RUNTIME_ROOT@ @RUNTIME_GROUPS@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@ @HOME@ @GIT_GLOBAL_HOME@ @GIT_GLOBAL_XDG@ @COLLECTOR_EXE@; _bingsu_r=$?; print -n .; exit $_bingsu_r) || _bingsu_st=$?
  (( _bingsu_st < 128 )) || _bingsu_dead=1
  _bingsu_rec=${_bingsu_rec%.}
}

# A missing module must not stop init under ERR_EXIT or ERR_RETURN; the
# duration is then reported as unknown.
zmodload zsh/datetime 2>/dev/null || :
# Reset, never inherited: an environment value for _bingsu_t0 would make
# the first duration negative or huge. _bingsu_warned_last is reset on
# first registration only (below): a re-init keeps the late-hook warning
# quiet once it has been shown (spec section 5, same order stays silent).
typeset -g _bingsu_s=0 _bingsu_t0= _bingsu_t1= _bingsu_ps1= _bingsu_rps1= _bingsu_dead= _bingsu_key_prev= _bingsu_nested=
typeset -g _bingsu_warned_last
typeset -ga _bingsu_p
# Under ALL_EXPORT a new name is exported; without +x the rendered prompt
# and the timings would reach the environment of every child process.
typeset -g +x _bingsu_session _bingsu_seq _bingsu_rec _bingsu_s _bingsu_p _bingsu_t0 _bingsu_t1 _bingsu_ps1 _bingsu_rps1 _bingsu_warned_last _bingsu_dead _bingsu_key_prev _bingsu_nested

# Capture hook, first in precmd_functions. Nothing may run before these
# assignments, or $? and $pipestatus are lost (emulate itself sets $? to
# 0). The end time is read here too, so hooks running between this one and
# the install hook do not count as command time (spec section 5).
_bingsu_save() {
  _bingsu_s=$? _bingsu_p=("${pipestatus[@]}")
  emulate -L zsh
  typeset -g +x _bingsu_s  # the assignment above ran under the user's ALL_EXPORT
  _bingsu_t1=${EPOCHREALTIME-}
  return $_bingsu_s
}

_bingsu_preexec() {
  emulate -L zsh
  _bingsu_t0=${EPOCHREALTIME-} _bingsu_dead=
}

# Status notices (spec section 5): one fixed line when the key changes to a
# non-empty value. A failed frame is the key no-record, which no status can
# equal (a status has a colon). The status is read as the last field, and
# selects a line only by exact comparison with init's constants. init resets
# the key, so running it again tells a lasting problem once more. Only a
# prompt of the interactive shell itself counts: a subshell's key is lost, and
# its stderr may be someone's capture.
_bingsu_notify() {
  emulate -L zsh
  [[ -o interactive ]] && (( ! ZSH_SUBSHELL )) || return 0
  if (( $1 )); then
    _bingsu_classify "$_bingsu_f[-1]"
  else
    _bingsu_key=no-record _bingsu_note=no-record
  fi
  if _bingsu_notice_due "$_bingsu_key_prev" "$_bingsu_key"; then
    if [[ $_bingsu_note == no-record ]]; then print -u2 -r -- @MSG_NO_RECORD@
    elif [[ $_bingsu_note == @STATUS_RUNTIME_ROOT@ ]]; then print -u2 -r -- @MSG_NOTICE_RUNTIME_ROOT@
    elif [[ $_bingsu_note == @STATUS_BAD_ARGS@ ]]; then print -u2 -r -- @MSG_NOTICE_BAD_ARGS@
    elif [[ $_bingsu_note == @STATUS_INTERNAL@ ]]; then print -u2 -r -- @MSG_NOTICE_INTERNAL@
    elif [[ $_bingsu_note == @STATUS_OVERSIZE@ ]]; then print -u2 -r -- @MSG_NOTICE_OVERSIZE@
    elif [[ $_bingsu_note == @STATUS_TRUST_UNVERIFIED@ ]]; then print -u2 -r -- @MSG_NOTICE_TRUST_UNVERIFIED@
    elif [[ $_bingsu_note == @STATUS_TRUST_EXPIRED@ ]]; then print -u2 -r -- @MSG_NOTICE_TRUST_EXPIRED@
    elif [[ $_bingsu_note == @STATUS_TRUST_INVALID@ ]]; then print -u2 -r -- @MSG_NOTICE_TRUST_INVALID@
    elif [[ $_bingsu_note == @STATUS_TRUST_MISMATCH@ ]]; then print -u2 -r -- @MSG_NOTICE_TRUST_MISMATCH@
    elif [[ $_bingsu_note == @STATUS_TRUST_CLOCK@ ]]; then print -u2 -r -- @MSG_NOTICE_TRUST_CLOCK@
    elif [[ $_bingsu_note == @STATUS_SANDBOX@ ]]; then print -u2 -r -- @MSG_NOTICE_SANDBOX@
    elif [[ $_bingsu_note == @STATUS_CONFIG_LAST_GOOD@ ]]; then print -u2 -r -- @MSG_NOTICE_CONFIG_LAST_GOOD@
    elif [[ $_bingsu_note == @STATUS_CONFIG_DEFAULT@ ]]; then print -u2 -r -- @MSG_NOTICE_CONFIG_DEFAULT@
    else print -u2 -r -- @MSG_NOTICE_GENERIC@
    fi
  fi
  _bingsu_key_prev=$_bingsu_key
}

# Sets PROMPT and RPROMPT from record fields, given by number (0: no upper
# line). The numbers keep callers free of array syntax: this must run before
# any `emulate` in its caller, because prompt options are read here, right
# before installing (spec section 3 option table, F-18). Data never reaches
# PROMPT unescaped: reference when PROMPT_SUBST is on, plain assignment
# otherwise. Without a record, or with NO_PROMPT_PERCENT (the record is
# %-escaped for it; option (b), question Q4), a constant.
_bingsu_paint() {
  local o_subst=0 o_bang=0 o_pct=0
  [[ -o prompt_subst ]] && o_subst=1
  [[ -o prompt_bang ]] && o_bang=1
  [[ -o prompt_percent ]] && o_pct=1
  emulate -L zsh
  local ps1 rps1
  if (( ${#_bingsu_f} && o_pct )); then
    ps1=$_bingsu_f[$2] rps1=$_bingsu_f[$3]
    # Upper line (record change plan 12, R-04): joined by a constant newline, only
    # when it is not empty, before any escaping so the escaping covers it.
    if (( $1 )) && [[ -n $_bingsu_f[$1] ]]; then ps1=$_bingsu_f[$1]$'\n'$ps1; fi
    if (( o_bang )); then ps1=${ps1//!/!!} rps1=${rps1//!/!!}; fi
    if (( o_subst )); then
      _bingsu_ps1=$ps1 _bingsu_rps1=$rps1
      PROMPT='${_bingsu_ps1}' RPROMPT='${_bingsu_rps1}'
    else
      PROMPT=$ps1 RPROMPT=$rps1
    fi
  elif (( o_pct )); then
    PROMPT='%~ ❯ ' RPROMPT=
  else
    PROMPT='❯ ' RPROMPT=
  fi
}

_bingsu_render() {
  emulate -L zsh
  local -a ctx
  local -i ms
  local pst=${(j:,:)_bingsu_p}
  [[ -n $pst ]] || pst=$_bingsu_s
  ctx=(--width "${COLUMNS:-0}" --status "$_bingsu_s" --pipestatus "$pst"
       --jobs "${(%):-%j}" --keymap "${KEYMAP:-main}")
  if [[ -n $_bingsu_t0 && -n $_bingsu_t1 ]]; then
    (( ms = (_bingsu_t1 - _bingsu_t0) * 1000 ))
    # A wall clock can step back; the envelope takes no negative value.
    (( ms < 0 )) || ctx+=(--duration-ms "$ms")
  fi
  _bingsu_t0= _bingsu_t1= _bingsu_nested=
  _bingsu_call "${ctx[@]}"
  # The record is checked whatever the options are, so the status notices
  # see it; only installing it on screen depends on PROMPT_PERCENT.
  _bingsu_frame "$_bingsu_rec" || :
}

_bingsu_tell() {
  emulate -L zsh
  _bingsu_notify ${#_bingsu_f}
  if [[ ${precmd_functions[-1]} != _bingsu_install && -z $_bingsu_warned_last ]]; then
    _bingsu_warned_last=1
    print -u2 -r -- @MSG_LATE_HOOK_ZSH@
  fi
}

# Install hook, last in precmd_functions. No `emulate` here: see _bingsu_paint.
_bingsu_install() {
  _bingsu_render
  _bingsu_paint 9 3 4
  _bingsu_tell
  return $_bingsu_s
}

_bingsu_has_transient() {
  emulate -L zsh
  (( ! ${#_bingsu_f} )) || [[ -n $_bingsu_f[5]$_bingsu_f[6] ]]
}

# Transient prompt: the line just finished keeps only the short form, without
# the upper line (spec section 5). A record without one has nothing to swap in.
# No bingsu call here: the precmd_functions after any of these put the full
# prompt back (after Ctrl-C too; only a `precmd` function is skipped then).
_bingsu_transient() {
  _bingsu_has_transient || return 0
  _bingsu_paint 0 5 6
  zle reset-prompt
}

_bingsu_status() {
  return $1
}

# In a function so the user's ALL_EXPORT does not reach the assignment.
_bingsu_nest() {
  emulate -L zsh
  _bingsu_nested=${1-}
}

# Hooks of the line editor. `zle <saved>` without -w keeps $WIDGET, so a saved
# widget that looks itself up by that name (add-zle-hook-widget) still works.
_bingsu_line_finish() {
  [[ -z $_bingsu_nested ]] || return 0
  _bingsu_nest 1
  (( ! ${+widgets[_bingsu_saved_zle-line-finish]} )) || zle _bingsu_saved_zle-line-finish -- "$@"
  _bingsu_nest
  _bingsu_transient
}

_bingsu_send_break() {
  if [[ -n $_bingsu_nested ]]; then
    zle .send-break -- "$@"
    return
  fi
  _bingsu_transient
  _bingsu_nest 1
  zle _bingsu_saved_send-break -- "$@"
  _bingsu_nest
}

# Takes over widget $1 once per shell (F-23): after a first run the chain may
# hold a plugin that wraps us, and saving that would make it call itself. The
# mark is a widget, so no environment can carry it. add-zle-hook-widget keeps
# its list in a dispatcher that a later add would re-enter through our saved
# copy, so there we join the list. Any other dispatcher that calls us from its
# own saved copy stops at _bingsu_nested, which precmd clears after an abort.
_bingsu_zle_wrap() {
  emulate -L zsh
  (( ! ${+widgets[_bingsu_wrapped_$1]} )) || return 0
  zle -N _bingsu_wrapped_$1 $2
  if [[ ${widgets[$1]-} == user:azhw:$1 ]]; then
    add-zle-hook-widget ${1#zle-} _bingsu_wrapped_$1
    return
  fi
  if (( ${+widgets[$1]} )); then zle -A $1 _bingsu_saved_$1; fi
  zle -N $1 $2
}

# Register once (F-23). Function bodies above are redefined on every init.
# Registration is decided by the arrays themselves, not by a flag: a flag
# can arrive from the environment and silently switch bingsu off.
() {
  emulate -L zsh
  if (( ! ${precmd_functions[(Ie)_bingsu_install]:-0} )); then
    # First registration: an inherited value would silence the warning.
    _bingsu_warned_last=
    precmd_functions=(_bingsu_save ${precmd_functions:#_bingsu_save} _bingsu_install)
  fi
  if (( ! ${preexec_functions[(Ie)_bingsu_preexec]:-0} )); then
    preexec_functions+=(_bingsu_preexec)
  fi
}

# The widgets need the line editor and its parameters. zsh runs a TRAPINT
# function in place of the default: a value above 0 goes on as an interrupt, so
# without a user trap this returns what the signal itself would. A saved user
# trap decides by its own return value. A string trap cannot sit beside the
# function (defining one removes the other), so it stays and Ctrl-C keeps the
# long form; `trap |` sees it, a substitution would not. Outside `emulate`,
# whose local traps would remove the function again.
if [[ -o interactive && -o zle ]] && zmodload zsh/zleparameter 2>/dev/null; then
  _bingsu_zle_wrap zle-line-finish _bingsu_line_finish
  _bingsu_zle_wrap send-break _bingsu_send_break
  if [[ ${functions[TRAPINT]-} != *_bingsu_transient* ]]; then
    _bingsu_int=0
    if (( ${+functions[TRAPINT]} )); then
      functions -c TRAPINT _bingsu_saved_TRAPINT
    else
      unset -f _bingsu_saved_TRAPINT 2>/dev/null
      trap | while IFS= read -r _bingsu_line; do
        [[ $_bingsu_line != *' INT' ]] || _bingsu_int=1
      done
    fi
    if (( ! _bingsu_int )); then
      TRAPINT() {
        local _bingsu_entry=$?
        ! zle || _bingsu_transient
        if (( ${+functions[_bingsu_saved_TRAPINT]} )); then
          # The user's trap sees the status it would have seen without us.
          if _bingsu_status $_bingsu_entry; then
            _bingsu_saved_TRAPINT "$@"
          else
            _bingsu_saved_TRAPINT "$@"
          fi
          return $?
        fi
        return $(( 128 + $1 ))
      }
    fi
    unset _bingsu_int _bingsu_line
  fi
fi
