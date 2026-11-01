# The shape oh-my-zsh leaves before bingsu init: hooks already in both arrays,
# the preexec one chained by plain append. Logs to $BINGSU_T_LOG.
_omz_like_precmd() { print -r -- "omz-precmd $?" >>"$BINGSU_T_LOG" }
_omz_like_preexec() { print -r -- "omz-preexec" >>"$BINGSU_T_LOG" }
precmd_functions+=(_omz_like_precmd)
preexec_functions+=(_omz_like_preexec)
