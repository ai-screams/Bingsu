# bingsu prompt for fish 3.6+ (spec section 5). init redefines every
# function on each run.
set -q _bingsu_session; or set -g _bingsu_session @SESSION@
set -q _bingsu_seq; or set -g _bingsu_seq 0
set -g _bingsu_rec ''

# Runs the pinned binary once; the raw record goes to _bingsu_rec.
function _bingsu_call
    set -g _bingsu_seq (math $_bingsu_seq + 1)
    set -g _bingsu_rec (@BIN@ prompt --ctx 1 --record @RECORD@ $argv --session $_bingsu_session --seq $_bingsu_seq @RUNTIME_ROOT@ @CONFIG_ROOT@ @STATE_ROOT@ @LOG_ROOT@ | string collect -N)
end
