#!/bin/sh
# Test double for `bingsu prompt`: each call takes the next line of
# statuses.txt next to the installed link and prints a minimal record with
# that status. The last line repeats. `no-record` prints nothing, so the hook
# gets no record.
here=${0%/*}
printf 'END\0' >> "$here/argv.log"
n=$(tr -cd '\0' < "$here/argv.log" | wc -c)
total=$(wc -l < "$here/statuses.txt")
[ "$n" -le "$total" ] || n=$total
status=$(sed -n "${n}p" "$here/statuses.txt")
[ "$status" = no-record ] && exit 0
printf 'B1\03712\037> \037\037\037\037\037\037\037\037\037\037\037%s\036' "$status"
