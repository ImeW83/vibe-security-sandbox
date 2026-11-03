#!/bin/bash
# config/safe-run.sh - snapshot ./sandbox, scan the snapshot, run the same snapshot in the container
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

if [ "$#" -eq 0 ]; then
  echo "Usage: ./config/safe-run.sh <command> [args]"
  echo "Example: ./config/safe-run.sh python hello.py"
  exit 64
fi

# Step 0: refuse oversized input before copying anything (limit: 20 MB)
MAX_INPUT_BYTES=$((20 * 1024 * 1024))
INPUT_BYTES=$(du -sb "$ROOT_DIR/sandbox" | cut -f1)
if [ "$INPUT_BYTES" -gt "$MAX_INPUT_BYTES" ]; then
  echo "[BLOCKED] sandbox/ is $INPUT_BYTES bytes (limit $MAX_INPUT_BYTES). Nothing was copied or executed."
  exit 5
fi

# Step 1: private snapshot (mktemp -d creates it with mode 700)
SNAPSHOT="$(mktemp -d)"
trap 'rm -rf "$SNAPSHOT"' EXIT

cp -a "$ROOT_DIR/sandbox/." "$SNAPSHOT/"
# Container uid 1000 must be able to read and write the snapshot
chmod 755 "$SNAPSHOT"

# Step 2: scan the snapshot, not the live folder
"$SCRIPT_DIR/scan.sh" "$SNAPSHOT"
SCAN_RESULT=$?

if [ "$SCAN_RESULT" -ne 0 ]; then
  echo "[BLOCKED] Scan did not pass. Nothing was executed."
  exit "$SCAN_RESULT"
fi

# Step 3: run the same snapshot in the locked-down container
echo "[RUN] Scan passed. Executing the scanned snapshot inside the sandbox..."
ARCHIVE="$(mktemp)"
trap 'rm -rf "$SNAPSHOT" "$ARCHIVE"' EXIT

RUN_NAME="vibe-run-$$"
RUN_TIMEOUT="${GUARD_TIMEOUT:-60}"
TIMEOUT_FLAG="$(mktemp)"
rm -f "$TIMEOUT_FLAG"

# Watcher: after RUN_TIMEOUT seconds, force-remove the container itself (killing the client is not enough)
( sleep "$RUN_TIMEOUT" && touch "$TIMEOUT_FLAG" && docker rm -f "$RUN_NAME" > /dev/null 2>&1 ) &
WATCHER=$!

SANDBOX_SRC="$SNAPSHOT" RUN_UID="$(id -u)" RUN_GID="$(id -g)" docker compose -f "$ROOT_DIR/docker-compose.yml" run --rm -T --user "$(id -u):$(id -g)" --name "$RUN_NAME" sandbox "$@" > "$ARCHIVE"
RUN_RC=$?

kill "$WATCHER" 2> /dev/null
wait "$WATCHER" 2> /dev/null

if [ -e "$TIMEOUT_FLAG" ]; then
  rm -f "$TIMEOUT_FLAG"
  echo "[TIMEOUT] Run exceeded ${RUN_TIMEOUT}s and was killed."
  exit 124
fi

# Save run results (if any) through the safe unpacker
"$SCRIPT_DIR/unpack-output.sh" "$ARCHIVE" "$ROOT_DIR/output"

exit "$RUN_RC"
