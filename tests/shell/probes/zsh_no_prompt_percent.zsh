# What does zsh print for a %-escaped record field under NO_PROMPT_PERCENT?
# Prints the prompt expansion of the same value with the option on and off.
emulate -R zsh
v=$'%{\e[31m%}D:%%F{red}!%{\e[0m%}> '
setopt prompt_percent;   print -r -- "on:  ${(q+)${(%)v}}"
unsetopt prompt_percent; print -r -- "off: ${(q+)${(%)v}}"
