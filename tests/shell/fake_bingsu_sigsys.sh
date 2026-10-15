#!/bin/sh
# Test double for a prompt process a signal ended (a crash, or on Linux the
# seccomp filter of `bingsu prompt`): logs one line per call next to the
# installed link, then dies by SIGSYS before writing anything.
printf 'call\n' >> "${0%/*}/calls.log"
kill -s SYS $$
