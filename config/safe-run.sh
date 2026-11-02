#!/bin/bash
# config/safe-run.sh - scan ./sandbox first; run the command in the sandbox only if the scan passes
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."

if [ "$#" -eq 0 ]; then
  echo "Usage: ./config/safe-run.sh <command> [args]"
  echo "Example: ./config/safe-run.sh python hello.py"
  exit 64
fi

# Step 1: Guardian scan
"$SCRIPT_DIR/scan.sh"
SCAN_RESULT=$?

if [ "$SCAN_RESULT" -ne 0 ]; then
  echo "[BLOCKED] Scan did not pass. Nothing was executed."
  exit "$SCAN_RESULT"
fi

# Step 2: Run inside the locked-down container
echo "[RUN] Scan passed. Executing inside the sandbox..."
docker compose -f "$ROOT_DIR/docker-compose.yml" run --rm sandbox "$@"
