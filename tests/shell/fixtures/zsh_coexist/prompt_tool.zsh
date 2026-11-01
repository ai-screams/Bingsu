# The shape of another prompt tool: it writes PROMPT when loaded, before bingsu
# init, and attaches its hook later, after init (_tool_attach).
PROMPT='tool> '
_tool_precmd() { print -r -- "tool-precmd $?" >>"$BINGSU_T_LOG" }
_tool_attach() { precmd_functions+=(_tool_precmd) }
