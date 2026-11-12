#!/bin/bash
# tests/run-tests.sh - regression tests for the guardrail pipeline
# Backs up anything in sandbox/, runs each check through safe-run.sh, then restores it.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$SCRIPT_DIR/.."
SANDBOX="$ROOT_DIR/sandbox"
SAFE_RUN="$ROOT_DIR/config/safe-run.sh"
OUTPUT="$ROOT_DIR/output"
OUT_BACKUP="$(mktemp -d)"

BACKUP="$(mktemp -d)"
LOG="$(mktemp)"
PAYLOAD_OUT="$(mktemp)"
PAYLOAD_ERR="$(mktemp)"
PASS=0
FAIL=0

clear_sandbox() {
  find "$SANDBOX" -mindepth 1 ! -name '.gitkeep' -delete
}

cleanup() {
  clear_sandbox
  find "$OUTPUT" -mindepth 1 ! -name '.gitkeep' -delete
  find "$OUT_BACKUP" -mindepth 1 -maxdepth 1 -exec mv {} "$OUTPUT"/ \;
  rm -rf "$OUT_BACKUP"
  find "$BACKUP" -mindepth 1 -maxdepth 1 -exec mv {} "$SANDBOX"/ \;
  rm -rf "$BACKUP" "$LOG" "$PAYLOAD_OUT" "$PAYLOAD_ERR"
}
trap cleanup EXIT

# Back up whatever is in output/ (except the placeholder)
find "$OUTPUT" -mindepth 1 -maxdepth 1 ! -name '.gitkeep' -exec mv {} "$OUT_BACKUP"/ \;

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

# heal_prompt_problem PROMPT KIND KEY VALUE FILE LINE
# Parses the prompt with python3. Prints "OK" if the JSON is valid, has the expected "kind",
# and holds a finding with KEY == VALUE, the given file and line. Otherwise prints why not.
# Callers must treat anything other than exactly "OK" as a failure (so a missing python3 fails closed).
heal_prompt_problem() {
  python3 -I - "$@" << 'PY'
import json, sys
path, kind, key, value, fname, line = sys.argv[1:7]
try:
    with open(path) as f:
        data = json.load(f)
except Exception as e:
    print("prompt is missing or not valid JSON (%s)" % type(e).__name__)
    sys.exit(0)
if data.get("kind") != kind:
    print("kind is %r, expected %r" % (data.get("kind"), kind))
    sys.exit(0)
for fnd in data.get("findings", []):
    if fnd.get(key) == value and fnd.get("file") == fname and fnd.get("line") == int(line):
        print("OK")
        sys.exit(0)
print("no finding with %s=%s, file=%s, line=%s" % (key, value, fname, line))
PY
}

# run_payload: run heal.py --build-payload; stdout -> $PAYLOAD_OUT, stderr -> $PAYLOAD_ERR, exit -> $HEAL_RC
run_payload() {
  PROMPT="$OUTPUT/heal-prompt.json"
  rm -f "$PROMPT"
  "$ROOT_DIR/config/heal.py" --build-payload > "$PAYLOAD_OUT" 2> "$PAYLOAD_ERR"
  HEAL_RC=$?
}

# payload_problem FILE KIND PATH MUST_CONTAIN MUST_NOT_CONTAIN
# Parses the payload JSON with python3. Prints "OK" if it has the kind, a file at PATH that contains
# MUST_CONTAIN (skipped if empty), and nowhere contains MUST_NOT_CONTAIN (skipped if empty).
# Otherwise prints why not. Callers treat anything other than exactly "OK" as a failure.
payload_problem() {
  python3 -I - "$@" << 'PY'
import json, sys
pfile, kind, path, want, banned = sys.argv[1:6]
try:
    with open(pfile) as f:
        data = json.load(f)
except Exception as e:
    print("payload is missing or not valid JSON (%s)" % type(e).__name__)
    sys.exit(0)
if data.get("kind") != kind:
    print("kind is %r, expected %r" % (data.get("kind"), kind))
    sys.exit(0)
files = {f.get("path"): f.get("content", "") for f in data.get("files", [])}
if path not in files:
    print("payload has no file %s" % path)
    sys.exit(0)
if want and want not in files[path]:
    print("file content is missing the expected text")
    sys.exit(0)
if banned and banned in json.dumps(data):
    print("payload contains text that must not be sent")
    sys.exit(0)
print("OK")
PY
}

# count_in_files PATTERN FILE...: total occurrences of PATTERN. Prints nothing if a file is unreadable.
count_in_files() {
  python3 -I -c 'import sys; pat = sys.argv[1]; print(sum(open(p, errors="replace").read().count(pat) for p in sys.argv[2:]))' "$@" 2>/dev/null
}

# heal_unit MODE: import heal.py and call build_payload directly. Prints "OK" or why not.
#   symlink: a flagged file that is a symlink to a file outside the folder must be refused
#   gate:    a payload that still holds a token must be stopped by the pre-send secret gate
heal_unit() {
  python3 -I -B - "$ROOT_DIR/config/heal.py" "$1" << 'PY'
import importlib.machinery, importlib.util, os, sys, tempfile
sys.dont_write_bytecode = True
loader = importlib.machinery.SourceFileLoader("heal_mod", sys.argv[1])
spec = importlib.util.spec_from_loader("heal_mod", loader)
h = importlib.util.module_from_spec(spec)
loader.exec_module(h)
mode = sys.argv[2]
with tempfile.TemporaryDirectory() as tmp:
    box = os.path.join(tmp, "box")
    os.makedirs(box)
    if mode == "symlink":
        outside = os.path.join(tmp, "outside.txt")
        with open(outside, "w") as f:
            f.write("SYMLINK-SENTINEL")
        os.symlink(outside, os.path.join(box, "link.py"))
        name, want = "link.py", ("refusing a path outside", "not a regular file")
    else:
        with open(os.path.join(box, "leak.py"), "w") as f:
            f.write('TOKEN = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5"\n')
        name, want = "leak.py", ("pre-send secret gate",)
    prompt = {"kind": "semgrep", "instruction": "x", "findings": [{"rule": "r", "file": name, "line": 1}]}
    try:
        h.build_payload(prompt, box)
    except h.HealError as e:
        msg = str(e)
        print("OK" if any(w in msg for w in want) and "SYMLINK-SENTINEL" not in msg else "wrong error: " + msg)
    else:
        print("no error was raised; the payload was built")
PY
}

# finish_check REPORTED PASS_MESSAGE: count one PASS if nothing was reported, else one FAIL
finish_check() {
  if [ "$1" -eq 0 ]; then
    echo "PASS  $2"
    PASS=$((PASS + 1))
  else
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

# 8. File written to /output is saved; file written next to the code is lost
clear_sandbox
find "$OUTPUT" -mindepth 1 ! -name '.gitkeep' -delete
cat > "$SANDBOX/t8.py" << 'T8'
open("/output/kept.txt", "w").write("kept\n")
open("/sandbox/lost.txt", "w").write("lost\n")
print("wrote both files")
T8
check "output run completes" 0 "wrote both files" no python t8.py
if [ -f "$OUTPUT/kept.txt" ] && [ ! -f "$SANDBOX/lost.txt" ]; then
  echo "PASS  /output file saved, snapshot file discarded"
  PASS=$((PASS + 1))
else
  echo "FAIL  /output file saved, snapshot file discarded"
  FAIL=$((FAIL + 1))
fi

# 9. An 80 MB write is stopped at the 50 MB cap
clear_sandbox
find "$OUTPUT" -mindepth 1 ! -name '.gitkeep' -delete
cat > "$SANDBOX/t9.py" << 'T9'
import os
try:
    with open("/output/big.bin", "wb") as f:
        for _ in range(80):
            f.write(os.urandom(1024 * 1024))
    print("CANARY" + "_RAN")
except OSError:
    print("write stopped")
T9
check "oversized write stopped" 0 "write stopped" yes python t9.py
BIG_SIZE=$(stat -c %s "$OUTPUT/big.bin" 2>/dev/null || echo 0)
if [ "$BIG_SIZE" -gt 0 ] && [ "$BIG_SIZE" -le 52428800 ]; then
  echo "PASS  saved output is within the 50 MB cap ($BIG_SIZE bytes)"
  PASS=$((PASS + 1))
else
  echo "FAIL  saved output is within the 50 MB cap ($BIG_SIZE bytes)"
  FAIL=$((FAIL + 1))
fi

# 10. Oversized input (over 20 MB) is blocked before anything is copied or scanned
clear_sandbox
head -c 26214400 /dev/zero > "$SANDBOX/big.bin"
check "oversized sandbox blocked" 5 "Nothing was copied or executed" no python anything.py

# 11. An infinite loop is killed by the run timeout
clear_sandbox
cat > "$SANDBOX/t11.py" << 'T11'
import time
while True:
    time.sleep(1)
T11
export GUARD_TIMEOUT=10
check "infinite loop killed by timeout" 124 "TIMEOUT" no python t11.py
unset GUARD_TIMEOUT

# 12. Pre-installed Node package (lodash) loads and the network stays blocked
clear_sandbox
cat > "$SANDBOX/t12.js" << 'T12'
const _ = require("lodash");
require("http").get("http://example.com", () => {
  console.log("NETWORK" + "_REACHABLE");
}).on("error", () => {
  console.log("node deps ok, network blocked: " + _.chunk([1, 2, 3, 4], 2).length);
});
T12
check "pinned Node dependency loads, network blocked" 0 "node deps ok, network blocked: 2" no node t12.js

# 13. heal.py removes a stale prompt itself (empty sandbox -> unfixable exit 3, no new prompt)
clear_sandbox
find "$OUTPUT" -mindepth 1 ! -name '.gitkeep' -delete
STALE="$OUTPUT/heal-prompt.json"
echo '{"stale": true}' > "$STALE"
if [ ! -f "$STALE" ]; then
  echo "FAIL  heal.py removes stale prompt (could not create the stale file)"
  FAIL=$((FAIL + 1))
else
  "$ROOT_DIR/config/heal.py" > "$LOG" 2>&1
  HEAL_RC=$?
  if [ "$HEAL_RC" -eq 3 ] && [ ! -e "$STALE" ]; then
    echo "PASS  heal.py removes stale prompt, empty sandbox (exit $HEAL_RC)"
    PASS=$((PASS + 1))
  else
    REPORTED=0
    if [ "$HEAL_RC" -ne 3 ]; then
      echo "FAIL  heal.py removes stale prompt: wrong exit code (expected 3, got $HEAL_RC)"
      REPORTED=1
    fi
    if [ -e "$STALE" ]; then
      echo "FAIL  heal.py removes stale prompt: stale file was left behind"
      REPORTED=1
    fi
    if [ "$REPORTED" -eq 0 ]; then
      echo "FAIL  heal.py removes stale prompt (unexpected state, exit $HEAL_RC)"
    fi
    FAIL=$((FAIL + 1))
  fi
fi

# 14. heal.py, fixable Semgrep finding (exit 1): prompt names the rule, file and line
clear_sandbox
PROMPT="$OUTPUT/heal-prompt.json"
rm -f "$PROMPT"
cat > "$SANDBOX/t14.py" << 'T14'
import subprocess

def run(cmd):
    subprocess.call(cmd, shell=True)
T14
"$ROOT_DIR/config/heal.py" > "$LOG" 2>&1
HEAL_RC=$?
REPORTED=0
if [ "$HEAL_RC" -ne 1 ]; then
  echo "FAIL  heal.py fixable Semgrep case: wrong exit code (expected 1, got $HEAL_RC)"
  REPORTED=1
fi
PROBLEM="$(heal_prompt_problem "$PROMPT" semgrep rule subprocess-shell-true t14.py 4)"
if [ "$PROBLEM" != "OK" ]; then
  echo "FAIL  heal.py fixable Semgrep case: ${PROBLEM:-prompt check did not run}"
  REPORTED=1
fi
if [ "$REPORTED" -eq 0 ]; then
  echo "PASS  heal.py fixable Semgrep case writes a correct prompt (exit $HEAL_RC)"
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
fi

# 15. heal.py, fixable secret (exit 4): prompt names the detector, file and line, and never holds the token
clear_sandbox
rm -f "$PROMPT"
cat > "$SANDBOX/t15.py" << 'T15'
TOKEN = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5"
print("hello")
T15
if ! grep -qF 'ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5' "$SANDBOX/t15.py"; then
  echo "FAIL  heal.py fixable secret case: fixture does not contain the token (zero-leak check would be vacuous)"
  FAIL=$((FAIL + 1))
else
  "$ROOT_DIR/config/heal.py" > "$LOG" 2>&1
  HEAL_RC=$?
  REPORTED=0
  if [ "$HEAL_RC" -ne 4 ]; then
    echo "FAIL  heal.py fixable secret case: wrong exit code (expected 4, got $HEAL_RC)"
    REPORTED=1
  fi
  PROBLEM="$(heal_prompt_problem "$PROMPT" secret detector Github t15.py 1)"
  if [ "$PROBLEM" != "OK" ]; then
    echo "FAIL  heal.py fixable secret case: ${PROBLEM:-prompt check did not run}"
    REPORTED=1
  fi
  LEAKS="$(python3 -I -c 'import sys; print(open(sys.argv[1]).read().count("ghp_"))' "$PROMPT" 2>/dev/null)"
  if [ "$LEAKS" != "0" ]; then
    echo "FAIL  heal.py fixable secret case: leak check failed (count of ghp_ in prompt: ${LEAKS:-prompt unreadable})"
    REPORTED=1
  fi
  if [ "$REPORTED" -eq 0 ]; then
    echo "PASS  heal.py fixable secret case writes a correct prompt, 0 token leaks (exit $HEAL_RC)"
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
fi

# 16. --build-payload, secret case: the flagged line is removed and the token appears nowhere
clear_sandbox
cat > "$SANDBOX/t16.py" << 'T16'
TOKEN = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5"
print("hello")
T16
if ! grep -qF 'ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5' "$SANDBOX/t16.py"; then
  echo "FAIL  payload secret case: fixture does not contain the token (zero-leak check would be vacuous)"
  FAIL=$((FAIL + 1))
else
  run_payload
  REPORTED=0
  if [ "$HEAL_RC" -ne 4 ]; then
    echo "FAIL  payload secret case: wrong exit code (expected 4, got $HEAL_RC)"
    REPORTED=1
  fi
  PROBLEM="$(payload_problem "$PAYLOAD_OUT" secret t16.py '<line removed: hardcoded Github credential>' 'ghp_')"
  if [ "$PROBLEM" != "OK" ]; then
    echo "FAIL  payload secret case: ${PROBLEM:-payload check did not run}"
    REPORTED=1
  fi
  LEAKS="$(count_in_files ghp_ "$PAYLOAD_OUT" "$PAYLOAD_ERR" "$PROMPT")"
  if [ "$LEAKS" != "0" ]; then
    echo "FAIL  payload secret case: ghp_ count across payload, stderr and prompt is ${LEAKS:-unreadable}"
    REPORTED=1
  fi
  finish_check "$REPORTED" "payload secret case: line removed, 0 token leaks (exit $HEAL_RC)"
fi

# 17. --build-payload, Semgrep case: the flagged file is sent as written
clear_sandbox
cat > "$SANDBOX/t17.py" << 'T17'
import subprocess

def run(cmd):
    subprocess.call(cmd, shell=True)
T17
run_payload
REPORTED=0
if [ "$HEAL_RC" -ne 1 ]; then
  echo "FAIL  payload Semgrep case: wrong exit code (expected 1, got $HEAL_RC)"
  REPORTED=1
fi
PROBLEM="$(payload_problem "$PAYLOAD_OUT" semgrep t17.py 'subprocess.call(cmd, shell=True)' '')"
if [ "$PROBLEM" != "OK" ]; then
  echo "FAIL  payload Semgrep case: ${PROBLEM:-payload check did not run}"
  REPORTED=1
fi
finish_check "$REPORTED" "payload Semgrep case: file sent as written (exit $HEAL_RC)"

# 18. A flagged line that may start a multi-line secret is refused, and nothing is printed
clear_sandbox
printf 'TOKEN = """ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5\n"""\nprint("hello")\n' > "$SANDBOX/t18.py"
run_payload
REPORTED=0
if [ "$HEAL_RC" -ne 2 ]; then
  echo "FAIL  multi-line secret refused: wrong exit code (expected 2, got $HEAL_RC)"
  REPORTED=1
fi
if ! grep -q 'multi-line secret' "$PAYLOAD_ERR"; then
  echo "FAIL  multi-line secret refused: the refusal message is missing"
  REPORTED=1
fi
if [ -s "$PAYLOAD_OUT" ]; then
  echo "FAIL  multi-line secret refused: a payload was printed anyway"
  REPORTED=1
fi
LEAKS="$(count_in_files ghp_ "$PAYLOAD_OUT" "$PAYLOAD_ERR" "$PROMPT")"
if [ "$LEAKS" != "0" ]; then
  echo "FAIL  multi-line secret refused: ghp_ count is ${LEAKS:-unreadable}"
  REPORTED=1
fi
finish_check "$REPORTED" "multi-line secret refused, nothing printed (exit $HEAL_RC)"

# 19. A flagged file that is a symlink to a file outside the folder is refused (no Docker needed)
RESULT="$(heal_unit symlink)"
REPORTED=0
if [ "$RESULT" != "OK" ]; then
  echo "FAIL  symlink refused: ${RESULT:-check did not run}"
  REPORTED=1
fi
finish_check "$REPORTED" "symlink to an outside file refused"

# 20. The pre-send secret gate stops a payload that still holds a token
RESULT="$(heal_unit gate)"
REPORTED=0
if [ "$RESULT" != "OK" ]; then
  echo "FAIL  pre-send gate: ${RESULT:-check did not run}"
  REPORTED=1
fi
finish_check "$REPORTED" "pre-send gate blocks a payload holding a token"

echo "-----------------------------------------"
echo "Passed: $PASS   Failed: $FAIL"
[ "$FAIL" -eq 0 ]
