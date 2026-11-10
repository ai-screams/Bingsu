#!/usr/bin/env bash
# Every FROM line must pin a digest (CLAUDE.md: pin what CI downloads), and
# every image that runs apt-get retries archive downloads.
set -euo pipefail
cd "$(dirname "$0")"
bad=$(grep -H '^FROM ' ./*.Dockerfile | grep -v '@sha256:[0-9a-f]\{64\}' || true)
if [ -n "$bad" ]; then printf 'unpinned base image:\n%s\n' "$bad" >&2; exit 1; fi
echo "all base images pinned"
# Every image that runs apt-get sets the archive retries first, so a refused
# connection retries with backoff instead of failing the build.
# 이것을 실패시키는 것: Dockerfile 하나에서 retry 줄을 지우거나 첫 apt-get 뒤로 옮기는 것.
retry="RUN echo 'Acquire::Retries \"5\";' > /etc/apt/apt.conf.d/80-retries"
for file in ./*.Dockerfile; do
  if ! awk -v retry="$retry" '$0 == retry { ok = 1 } /apt-get/ && !ok { exit 1 }' "$file"; then
    printf 'apt-get without archive retries first: %s\n' "$file" >&2
    exit 1
  fi
done
echo "all apt images retry"
