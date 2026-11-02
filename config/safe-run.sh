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
SANDBOX_SRC="$SNAPSHOT" docker compose -f "$ROOT_DIR/docker-compose.yml" run --rm sandbox "$@"
