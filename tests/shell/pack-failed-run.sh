#!/bin/sh
# Packs the pytest folders of a failed CI run into one archive to upload:
# every regular file up to 1 MiB (the helper's refresh.log, state, stores and
# fixture files; the binary copies the tests install are larger). Sockets
# and FIFOs are left out. When the archive passes 200 MiB it is packed again
# with the logs alone, and the job log says so.
# Usage: pack-failed-run.sh ARCHIVE FOLDER...   (missing folders are skipped)
set -eu
out=$1
shift
list=$(mktemp)
archive() {
  # A helper may still be writing: tar then warns that a file changed while
  # it was read, and what it packed is still worth reading.
  tar -czf "$out" --null -T "$list" 2>/dev/null || true
}
for dir in "$@"; do
  find "$dir" -type f ! -size +1024k -print0
done > "$list" 2>/dev/null || true
archive
size=$(wc -c < "$out")
if [ "$size" -gt $((200 * 1024 * 1024)) ]; then
  echo "::warning::test folders packed to $size bytes; keeping the logs alone"
  for dir in "$@"; do
    find "$dir" -type f -name '*.log' ! -size +1024k -print0
  done > "$list" 2>/dev/null || true
  archive
fi
echo "packed $(wc -c < "$out") bytes from $(tr -cd '\0' < "$list" | wc -c) files"
rm -f "$list"
