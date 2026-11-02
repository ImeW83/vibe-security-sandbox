#!/bin/bash
# config/scan.sh - SAST guardrail: scans ./sandbox with Semgrep before execution
set -u

# Resolve the project root from this script's location, not the caller's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$SCRIPT_DIR/../sandbox"

# Pinned by digest so the scanner can't change underneath you
SEMGREP_IMAGE="semgrep/semgrep@sha256:451b3d875c00dac7ed5db5293e584a07de11449a409c10b3c2d2652f429630b6"

echo "========================================="
echo "[*] Starting Guardian Scan (Semgrep OSS)"
echo "========================================="

# Fail closed: an empty sandbox is a block condition, not a pass
FILE_COUNT=$(find "$SANDBOX_DIR" -type f ! -name ".gitkeep" | wc -l)
if [ "$FILE_COUNT" -eq 0 ]; then
    echo "-----------------------------------------"
    echo "[FAIL] No files found in sandbox/. Nothing to scan, so nothing to run."
    exit 3
fi

# :ro = scanner can't modify the code, :z = SELinux label for Fedora
docker run --rm \
  -v "$SANDBOX_DIR:/src:ro,z" \
  "$SEMGREP_IMAGE" \
  semgrep scan --config auto --severity ERROR --error /src

SCAN_EXIT_CODE=$?

echo "-----------------------------------------"
if [ "$SCAN_EXIT_CODE" -eq 0 ]; then
    echo "[PASS] No high-severity findings."
    exit 0
elif [ "$SCAN_EXIT_CODE" -eq 1 ]; then
    echo "[FAIL] High-severity findings. Execution blocked."
    echo "[!] Send the findings above back to the AI agent to fix."
    exit 1
else
    echo "[ERROR] Scan did not complete (exit code $SCAN_EXIT_CODE). Treating as a failure."
    exit 2
fi
