#!/bin/bash
# config/unpack-output.sh - safely move a tar archive of run results into ./output
# Usage: unpack-output.sh <archive.tar> <destination-dir>
# Keeps only regular files and directories; drops symlinks, devices, absolute paths and "..".
set -u

ARCHIVE="$1"
DEST="$2"
MAX_BYTES=$((51 * 1024 * 1024))

if [ ! -f "$ARCHIVE" ]; then
  echo "[output] No archive received. Nothing saved."
  exit 1
fi

SIZE=$(stat -c %s "$ARCHIVE")
if [ "$SIZE" -gt "$MAX_BYTES" ]; then
  echo "[output] Archive is $SIZE bytes (limit $MAX_BYTES). Nothing saved."
  exit 1
fi

# Reject any entry with an absolute path or ".." before extracting anything
if tar -tf "$ARCHIVE" 2>/dev/null | grep -E -q '(^/|(^|/)\.\.(/|$))'; then
  echo "[output] Archive contains unsafe paths. Nothing saved."
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# --no-same-owner / --no-same-permissions: ignore ownership and modes from the archive
if ! tar -xf "$ARCHIVE" -C "$STAGE" --no-same-owner --no-same-permissions 2>/dev/null; then
  echo "[output] Archive could not be unpacked. Nothing saved."
  exit 1
fi

# Copy only regular files (never symlinks or devices), preserving relative paths
COUNT=0
while IFS= read -r -d '' f; do
  rel="${f#"$STAGE"/}"
  mkdir -p "$DEST/$(dirname "$rel")"
  cp --no-preserve=mode,ownership "$f" "$DEST/$rel"
  COUNT=$((COUNT + 1))
done < <(find "$STAGE" -type f -print0)

SKIPPED=$(find "$STAGE" -mindepth 1 ! -type f ! -type d | wc -l)
echo "[output] Saved $COUNT file(s) to output/. Skipped $SKIPPED non-regular item(s)."
