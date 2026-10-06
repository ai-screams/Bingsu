#!/usr/bin/env bash
# Print the multi-arch index digest of a Docker Hub library image tag.
# Usage: resolve-digest.sh ubuntu 22.04
set -euo pipefail
repo=$1 tag=$2
token=$(curl -fsS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/${repo}:pull" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -fsSI -H "Authorization: Bearer ${token}" \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
  "https://registry-1.docker.io/v2/library/${repo}/manifests/${tag}" |
  tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}'
