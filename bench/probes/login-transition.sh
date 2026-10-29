#!/usr/bin/env bash
# Login-transition probe (B7). Run by hand; the first-shell logger cannot tell a
# logout and login from a boot, so this probe says it explicitly: one line per run.
#   login-transition.sh --label before-logout|after-login|before-reboot|after-reboot --out <tsv>
# Pairs: before-logout/after-login and before-reboot/after-reboot. A pair with a
# missing line is BLOCKED in bench/summarize.py. This script never logs out,
# reboots or uses sudo; it only reads the boot identity (x05-boot-id.sh) and appends.
# Columns (tab-separated): UTC time, label, boot identity, boot time in Unix seconds.
set -euo pipefail
usage() { echo "usage: login-transition.sh --label before-logout|after-login|before-reboot|after-reboot --out <tsv>" >&2; exit 2; }
label='' out=''
while [[ $# -gt 0 ]]; do
  case $1 in
    --label) [[ $# -ge 2 ]] || usage; label=$2; shift 2 ;;
    --out) [[ $# -ge 2 ]] || usage; out=$2; shift 2 ;;
    *) usage ;;
  esac
done
case $label in
  before-logout | after-login | before-reboot | after-reboot) ;;
  *) usage ;;
esac
[[ -n $out ]] || usage
line=$("$(dirname "${BASH_SOURCE[0]}")/x05-boot-id.sh" "$label")
printf '%s\n' "$line" >> "$out"
