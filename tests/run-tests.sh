#!/bin/bash
# tests/run-tests.sh - regression tests for the guardrail pipeline
# Backs up anything in sandbox/, runs each check through safe-run.sh, then restores it.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
SANDBOX="$ROOT_DIR/sandbox"
SAFE_RUN="$ROOT_DIR/config/safe-run.sh"

BACKUP="$(mktemp -d)"
LOG="$(mktemp)"
PASS=0
FAIL=0

clear_sandbox() {
  find "$SANDBOX" -mindepth 1 ! -name '.gitkeep' -delete
}

cleanup() {
  clear_sandbox
  find "$BACKUP" -mindepth 1 -maxdepth 1 -exec mv {} "$SANDBOX"/ \;
  rm -rf "$BACKUP" "$LOG"
}
trap cleanup EXIT

# Back up whatever is in sandbox/ (except the placeholder)
find "$SANDBOX" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec mv {} "$BACKUP"/ \;

# check NAME EXPECTED_EXIT EXPECTED_TEXT CANARY_CHECK(yes/no) COMMAND...
check() {
  local name="$1" want="$2" text="$3" canary="$4"
  shift 4
  "$SAFE_RUN" "$@" > "$LOG" 2>&1
  local got=$?
  local ok=1
  [ "$got" -eq "$want" ] || ok=0
  if [ -n "$text" ] && ! grep -q -- "$text" "$LOG"; then ok=0; fi
  if [ "$canary" = "yes" ] && grep -q "CANARY_RAN" "$LOG"; then ok=0; fi
  if [ "$ok" -eq 1 ]; then
    echo "PASS  $name (exit $got)"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $name (expected exit $want, got $got)"
    FAIL=$((FAIL + 1))
  fi
}

echo "Running guardrail tests (this takes a minute or two)..."

# 1. Clean Python runs
clear_sandbox
echo 'print("clean python ok")' > "$SANDBOX/t1.py"
check "clean Python runs" 0 "clean python ok" no python t1.py

# 2. Clean JavaScript runs
clear_sandbox
echo 'console.log("clean js ok");' > "$SANDBOX/t2.js"
check "clean JavaScript runs" 0 "clean js ok" no node t2.js

# 3. SQL injection is blocked
clear_sandbox
cat > "$SANDBOX/t3.py" << 'T3'
import sqlite3

def get_user(name):
    conn = sqlite3.connect("app.db")
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'").fetchall()

print("CANARY" + "_RAN")
T3
check "SQL injection blocked" 1 "[BLOCKED]" yes python t3.py

# 4. eval is blocked (custom rule)
clear_sandbox
cat > "$SANDBOX/t4.py" << 'T4'
def calc(expr):
    return eval(expr)

print("CANARY" + "_RAN")
T4
check "eval blocked" 1 "[BLOCKED]" yes python t4.py

# 5. Empty sandbox is blocked
clear_sandbox
check "empty sandbox blocked" 3 "No files found" no python anything.py

# 6. Hardcoded secret is blocked
clear_sandbox
cat > "$SANDBOX/t6.py" << 'T6'
GITHUB_TOKEN = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5"
print("CANARY" + "_RAN")
T6
check "hardcoded secret blocked" 4 "Secret filter found" yes python t6.py

# 7. Pre-installed dependency (requests) imports and the network stays blocked
clear_sandbox
cat > "$SANDBOX/t7.py" << 'T7'
import requests
try:
    requests.get("http://example.com", timeout=5)
    print("NETWORK" + "_REACHABLE")
except Exception:
    print("deps ok, network blocked")
T7
check "pinned dependency imports, network blocked" 0 "deps ok, network blocked" no python t7.py

echo "-----------------------------------------"
echo "Passed: $PASS   Failed: $FAIL"
[ "$FAIL" -eq 0 ]
