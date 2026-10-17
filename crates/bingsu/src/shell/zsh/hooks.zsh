# bingsu hooks for zsh (spec section 5). init redefines every function on
# each run; hook registration happens once (F-23). @…@ markers are literal
# shell words embedded by init.
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
  local _bingsu_pwd=$PWD _bingsu_st=0
  setopt no_multibyte
  (( ${#_bingsu_pwd} <= 65536 )) || _bingsu_pwd=
  local _bingsu_log=off _bingsu_host=${HOST-} _bingsu_venv=${VIRTUAL_ENV-} _bingsu_ssh=0
  case ${BINGSU_LOG-} in error|info|debug) _bingsu_log=$BINGSU_LOG ;; esac
  (( ${#_bingsu_host} <= 65536 )) || _bingsu_host=
  (( ${#_bingsu_venv} <= 65536 )) || _bingsu_venv=
  [[ -n ${SSH_CONNECTION-} || -n ${SSH_TTY-} ]] && _bingsu_ssh=1
  _bingsu_rec=$(@BIN@ prompt --ctx 1 --record @RECORD@ "$@" --shell zsh --pwd "$_bingsu_pwd" --colorterm "${COLORTERM-}" "--log-level=$_bingsu_log" --host "$_bingsu_host" --venv "$_bingsu_venv" "--ssh=$_bingsu_ssh" --session "$_bingsu_session" --seq "$_bingsu_seq" @RUNTIME_ROOT@ @RUNTIME_GROUPS@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@ @HOME@; _bingsu_r=$?; print -n .; exit $_bingsu_r) || _bingsu_st=$?
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
typeset -g _bingsu_s=0 _bingsu_t0= _bingsu_t1= _bingsu_ps1= _bingsu_rps1= _bingsu_dead=
typeset -g _bingsu_warned_last _bingsu_warned_sandbox
typeset -ga _bingsu_p
# typeset keeps an inherited export flag; without +x the rendered prompt
# and the timings would reach the environment of every child process.
typeset -g +x _bingsu_session _bingsu_seq _bingsu_rec _bingsu_s _bingsu_p _bingsu_t0 _bingsu_t1 _bingsu_ps1 _bingsu_rps1 _bingsu_warned_last _bingsu_dead _bingsu_warned_sandbox

# Capture hook, first in precmd_functions. Nothing may run before these
# assignments, or $? and $pipestatus are lost (emulate itself sets $? to
# 0). The end time is read here too, so hooks running between this one and
# the install hook do not count as command time (spec section 5).
_bingsu_save() {
  _bingsu_s=$? _bingsu_p=("${pipestatus[@]}")
  emulate -L zsh
  _bingsu_t1=${EPOCHREALTIME-}
  return $_bingsu_s
}

_bingsu_preexec() {
  emulate -L zsh
  _bingsu_t0=${EPOCHREALTIME-} _bingsu_dead=
}

# Install hook, last in precmd_functions. Prompt options are read here,
# right before installing, and before `emulate` makes them local
# (spec section 3 option table, F-18). Data never reaches PROMPT unescaped:
# reference when PROMPT_SUBST is on, plain assignment otherwise.
_bingsu_install() {
  local o_subst=0 o_bang=0 o_pct=0
  [[ -o prompt_subst ]] && o_subst=1
  [[ -o prompt_bang ]] && o_bang=1
  [[ -o prompt_percent ]] && o_pct=1
  emulate -L zsh
  local -a ctx
  local -i ms
  local pst=${(j:,:)_bingsu_p} ps1 rps1
  [[ -n $pst ]] || pst=$_bingsu_s
  ctx=(--width "${COLUMNS:-0}" --status "$_bingsu_s" --pipestatus "$pst"
       --jobs "${(%):-%j}" --keymap "${KEYMAP:-main}")
  if [[ -n $_bingsu_t0 && -n $_bingsu_t1 ]]; then
    (( ms = (_bingsu_t1 - _bingsu_t0) * 1000 ))
    ctx+=(--duration-ms "$ms")
  fi
  _bingsu_t0= _bingsu_t1=
  _bingsu_call "${ctx[@]}"
  # The record is checked whatever the options are, so the status notices
  # below see it; only installing it on screen depends on PROMPT_PERCENT.
  local framed=0
  _bingsu_frame "$_bingsu_rec" && framed=1
  if (( framed && o_pct )); then
    ps1=$_bingsu_f[3] rps1=$_bingsu_f[4]
    # Upper line (record change plan 12, R-04): joined by a constant newline, only
    # when it is not empty, before any escaping so the escaping covers it.
    if [[ -n $_bingsu_f[9] ]]; then ps1=$_bingsu_f[9]$'\n'$ps1; fi
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
    # NO_PROMPT_PERCENT: the record is %-escaped for PROMPT_PERCENT, so draw
    # a constant instead (option (b), question Q4).
    PROMPT='❯ ' RPROMPT=
  fi
  # The prompt ran without its system call filter (decision P18): said once
  # per session, with a constant from init.
  if [[ ${_bingsu_f[10]-} == @STATUS_SANDBOX@ && -z $_bingsu_warned_sandbox ]]; then
    _bingsu_warned_sandbox=1
    print -u2 -r -- @MSG_NO_SANDBOX@
  fi
  if [[ ${precmd_functions[-1]} != _bingsu_install && -z $_bingsu_warned_last ]]; then
    _bingsu_warned_last=1
    print -u2 -r -- @MSG_LATE_HOOK_ZSH@
  fi
  return $_bingsu_s
}

# Register once (F-23). Function bodies above are redefined on every init.
# Registration is decided by the arrays themselves, not by a flag: a flag
# can arrive from the environment and silently switch bingsu off.
() {
  emulate -L zsh
  if (( ! ${precmd_functions[(Ie)_bingsu_install]:-0} )); then
    # First registration: an inherited value would silence the warning.
    _bingsu_warned_last= _bingsu_warned_sandbox=
    precmd_functions=(_bingsu_save ${precmd_functions:#_bingsu_save} _bingsu_install)
  fi
  if (( ! ${preexec_functions[(Ie)_bingsu_preexec]:-0} )); then
    preexec_functions+=(_bingsu_preexec)
  fi
}
