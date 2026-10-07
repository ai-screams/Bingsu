#!/usr/bin/env bash
# X-05 boot identity probe. Append one line per run:
#   before-logout, after-login, after-reboot
# Usage: x05-boot-id.sh LABEL >> x05.log
# Columns (tab-separated): UTC time, label, boot identity (macOS
# kern.bootsessionuuid, Linux boot_id), boot time in Unix seconds (macOS
# kern.boottime sec, Linux /proc/stat btime).
set -euo pipefail
[[ $# -eq 1 ]] || { echo "usage: x05-boot-id.sh LABEL" >&2; exit 2; }
label=$1
# The label is a TSV column: letters, digits, dot, underscore, dash only.
[[ $label =~ ^[A-Za-z0-9._-]+$ ]] || { echo "bad label: $label" >&2; exit 2; }
case "$(uname -s)" in
  Darwin)
    id=$(sysctl -n kern.bootsessionuuid)
    raw=$(sysctl -n kern.boottime)   # "{ sec = 1791259131, usec = 749645 } Tue Oct ..."
    boot=$(printf '%s\n' "$raw" | sed -n 's/^{ sec = \([0-9][0-9]*\),.*/\1/p') ;;
  Linux)
    id=$(cat /proc/sys/kernel/random/boot_id)
    boot=$(awk '$1 == "btime" { print $2 }' /proc/stat) ;;
  *) echo "unsupported" >&2; exit 2 ;;
esac
[[ -n $id ]] || { echo "empty boot identity" >&2; exit 1; }
[[ $boot =~ ^[0-9]+$ ]] || { echo "boot time not read: $boot" >&2; exit 1; }
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
printf '%s\t%s\t%s\t%s\n' "$now" "$label" "$id" "$boot"
