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

# Runs the pinned binary once; the raw record goes to _bingsu_rec.
_bingsu_call() {
  emulate -L zsh
  (( ++_bingsu_seq ))
  _bingsu_rec=$(@BIN@ prompt --ctx 1 --record @RECORD@ "$@" --session "$_bingsu_session" --seq "$_bingsu_seq" @RUNTIME_ROOT@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@; print -n .)
  _bingsu_rec=${_bingsu_rec%.}
}

zmodload zsh/datetime 2>/dev/null
typeset -g _bingsu_s=0 _bingsu_t0= _bingsu_ps1= _bingsu_rps1=
typeset -ga _bingsu_p
typeset -g _bingsu_warned_last="${_bingsu_warned_last-}"

# Capture hook, first in precmd_functions. Nothing may run before these
# assignments, or $? and $pipestatus are lost.
_bingsu_save() {
  _bingsu_s=$? _bingsu_p=("${pipestatus[@]}")
  return $_bingsu_s
}

_bingsu_preexec() {
  _bingsu_t0=$EPOCHREALTIME
}

# Install hook, last in precmd_functions. Prompt options are read here,
# right before installing, and before `emulate` makes them local
# (spec section 3 option table, F-18). Data never reaches PROMPT unescaped:
# reference when PROMPT_SUBST is on, plain assignment otherwise.
# A hook running after this one may still change the options, so when
# this hook is not last the prompt is installed by reference whatever the
# options say (a reference is expanded once and its value is never
# expanded again; with PROMPT_SUBST off it shows as literal text, which is
# ugly but runs nothing), and the hook moves itself back to the end. zsh
# walks a copy of precmd_functions, so the move takes effect from the next
# prompt and nothing in the current walk is skipped or run twice.
_bingsu_install() {
  local o_subst=0 o_bang=0 o_pct=0 last=1
  [[ -o prompt_subst ]] && o_subst=1
  [[ -o prompt_bang ]] && o_bang=1
  [[ -o prompt_percent ]] && o_pct=1
  emulate -L zsh
  [[ ${precmd_functions[-1]} == _bingsu_install ]] || last=0
  local -a ctx
  local -i ms
  local pst=${(j:,:)_bingsu_p} ps1 rps1
  [[ -n $pst ]] || pst=$_bingsu_s
  ctx=(--width "${COLUMNS:-0}" --status "$_bingsu_s" --pipestatus "$pst"
       --jobs "${(%):-%j}" --keymap "${KEYMAP:-main}")
  if [[ -n $_bingsu_t0 && -n $EPOCHREALTIME ]]; then
    (( ms = (EPOCHREALTIME - _bingsu_t0) * 1000 ))
    ctx+=(--duration-ms "$ms")
  fi
  _bingsu_t0=
  _bingsu_call "${ctx[@]}"
  if (( o_pct )) && _bingsu_frame "$_bingsu_rec"; then
    ps1=$_bingsu_f[3] rps1=$_bingsu_f[4]
    if (( o_bang )); then ps1=${ps1//!/!!} rps1=${rps1//!/!!}; fi
    if (( o_subst || ! last )); then
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
  if (( ! last )); then
    precmd_functions=(${precmd_functions:#_bingsu_install} _bingsu_install)
    if [[ -z $_bingsu_warned_last ]]; then
      _bingsu_warned_last=1
      print -u2 -r -- @MSG_LATE_HOOK_ZSH@
    fi
  fi
  return $_bingsu_s
}

# Register once (F-23). Function bodies above are redefined on every init.
# Registration is decided by the arrays themselves, not by a flag: a flag
# can arrive from the environment and silently switch bingsu off.
() {
  emulate -L zsh
  if (( ! ${precmd_functions[(Ie)_bingsu_install]:-0} )); then
    precmd_functions=(_bingsu_save ${precmd_functions:#_bingsu_save} _bingsu_install)
  fi
  if (( ! ${preexec_functions[(Ie)_bingsu_preexec]:-0} )); then
    preexec_functions+=(_bingsu_preexec)
  fi
}
