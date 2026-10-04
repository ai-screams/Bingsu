#!/usr/bin/env bash
# Every FROM line must pin a digest (CLAUDE.md: pin what CI downloads).
set -euo pipefail
cd "$(dirname "$0")"
bad=$(grep -H '^FROM ' ./*.Dockerfile | grep -v '@sha256:[0-9a-f]\{64\}' || true)
if [ -n "$bad" ]; then printf 'unpinned base image:\n%s\n' "$bad" >&2; exit 1; fi
echo "all base images pinned"
