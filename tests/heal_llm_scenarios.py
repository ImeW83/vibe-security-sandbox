"""tests/heal_llm_scenarios.py - scenario tests for heal.py --llm, run by tests/run-tests.sh.

A fake model stands in for the API (no key, no network); the scans are the real ones.
Prints one PASS or FAIL line per scenario. Between scenarios it deletes everything in sandbox/
and output/, so it refuses to run unless run-tests.sh has backed those folders up first.
Usage: heal_llm_scenarios.py PROJECT_ROOT
"""
import contextlib
import glob
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile

if os.environ.get("VIBE_TESTS_BACKED_UP") != "1":
    print("refusing to run: this deletes the contents of sandbox/ and output/. Run tests/run-tests.sh instead.")
    sys.exit(2)

ROOT = os.path.abspath(sys.argv[1])
sys.dont_write_bytecode = True
_loader = importlib.machinery.SourceFileLoader("heal_mod", os.path.join(ROOT, "config", "heal.py"))
h = importlib.util.module_from_spec(importlib.util.spec_from_loader("heal_mod", _loader))
_loader.exec_module(h)
REAL_MAKE_CLIENT = h.make_client

SANDBOX = os.path.join(ROOT, "sandbox")
OUTPUT = os.path.join(ROOT, "output")
HEALED = os.path.join(OUTPUT, "healed")
FAKE_KEY = "sk-ant-FAKEKEY-DO-NOT-LEAK-0123456789"
TOKEN = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3gH5"
BAD = "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"
GOOD = "import shlex\nimport subprocess\n\ndef run(cmd):\n    subprocess.call(shlex.split(cmd))\n"
FIRST_TRY = "import subprocess\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)  # first attempt\n"
SECRET_SRC = f'TOKEN = "{TOKEN}"\nprint("hello")\n'
SECRET_FIXED = 'import os\nTOKEN = os.environ["GITHUB_TOKEN"]\nprint("hello")\n'

passed = failed = 0
TMP_BEFORE = set(glob.glob(os.path.join(tempfile.gettempdir(), "heal-*")))


class Scenario:
    def __init__(self, name):
        self.name, self.problems = name, []

    def expect(self, cond, what):
        if not cond:
            self.problems.append(what)


@contextlib.contextmanager
def scenario(name):
    global passed, failed
    s = Scenario(name)
    try:
        yield s
    except Exception as e:  # a crash fails this scenario only
        s.problems.append(f"crashed: {type(e).__name__}: {str(e)[:120]}")
    if s.problems:
        failed += 1
        print(f"FAIL  {name}: " + "; ".join(s.problems))
    else:
        passed += 1
        print(f"PASS  {name}")


def reset(files=None):
    for p in glob.glob(os.path.join(SANDBOX, "*")) + glob.glob(os.path.join(OUTPUT, "*")):
        if os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p)
        else:
            os.remove(p)
    for name, text in (files or {}).items():
        with open(os.path.join(SANDBOX, name), "w", encoding="utf-8") as f:
            f.write(text)


def run(argv, replies=None, files=None, key=True, forbid_call=False, pre=None):
    """Run heal.main(argv) with a fake model returning `replies` in order (a reply may be an Exception).
    Returns (exit_code, stdout, stderr, requests_seen)."""
    reset(files)
    if pre:
        pre()
    seen = []

    def fake_call(client, payload):
        if forbid_call:
            raise AssertionError("the model must not be called here")
        seen.append(json.loads(json.dumps(payload)))
        r = replies[min(len(seen) - 1, len(replies) - 1)]
        if isinstance(r, Exception):
            raise r
        return r, {"request_id": "req_FAKE", "input_tokens": 1, "output_tokens": 1}

    h.call_model = fake_call
    if key:
        os.environ["ANTHROPIC_API_KEY"] = FAKE_KEY
        h.make_client = lambda: object()
    else:
        os.environ.pop("ANTHROPIC_API_KEY", None)
        h.make_client = REAL_MAKE_CLIENT
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = h.main(argv)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue(), seen


def reply(path, content):
    return {"files": [{"path": path, "content": content}]}


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def output_text():
    text = ""
    for dirpath, _dirs, names in os.walk(OUTPUT):
        for n in names:
            text += read(os.path.join(dirpath, n))
    return text


# --- end-to-end scenarios (real scans) ---------------------------------------------------------

with scenario("llm: a Semgrep finding is fixed in one attempt, sandbox untouched, output private") as s:
    rc, o, e, c = run(["--llm"], [reply("t.py", GOOD)], files={"t.py": BAD})
    s.expect(rc == 0, f"exit {rc}, expected 0")
    s.expect(len(c) == 1, f"{len(c)} model calls, expected 1")
    s.expect(c and c[0]["files"][0]["content"] == BAD, "the request did not hold the original code")
    s.expect(os.path.exists(os.path.join(HEALED, "t.py")) and read(os.path.join(HEALED, "t.py")) == GOOD, "healed file missing or wrong")
    s.expect(os.path.exists(os.path.join(HEALED, "README.txt")), "healed README.txt missing")
    s.expect(read(os.path.join(SANDBOX, "t.py")) == BAD, "sandbox/ was modified")
    s.expect(oct(os.stat(os.path.join(HEALED, "t.py")).st_mode & 0o777) == "0o600", "healed file is not mode 600")

with scenario("llm: a rewrite that never passes stops at 3 attempts and saves nothing") as s:
    rc, o, e, c = run(["--llm"], [reply("t.py", BAD)], files={"t.py": BAD})
    s.expect(rc == 1, f"exit {rc}, expected 1 (still blocked)")
    s.expect(len(c) == 3, f"{len(c)} model calls, expected exactly 3")  # a literal: the code's own constant could be wrong
    s.expect(not os.path.exists(HEALED), "output/healed/ was created")

stale = {}


def make_stale():
    os.makedirs(HEALED)
    with open(os.path.join(HEALED, "old.py"), "w") as f:
        f.write("old")
    stale["made"] = True


with scenario("llm: a refusal stops at once with no retry, and old healed output is cleared") as s:
    rc, o, e, c = run(["--llm"], [h.HealError("the model refused the request (request req_X)")],
                      files={"t.py": BAD}, pre=make_stale)
    s.expect(stale.get("made"), "setup did not create the stale healed folder")
    s.expect(rc == 2, f"exit {rc}, expected 2")
    s.expect(len(c) == 1, f"{len(c)} model calls, expected exactly 1")
    s.expect(not os.path.exists(HEALED), "stale or new healed output is present")
    s.expect("refused" in o, "the refusal was not reported")

with scenario("llm: a reply naming a file that was not sent is rejected") as s:
    rc, o, e, c = run(["--llm"], [reply("other.py", GOOD)], files={"t.py": BAD})
    s.expect(rc == 2, f"exit {rc}, expected 2")
    s.expect(not os.path.exists(HEALED), "output/healed/ was created")
    s.expect("not sent" in o, "the reason was not reported")

with scenario("llm: secret case sends no token, leaks no key, and the fix reads the environment") as s:
    rc, o, e, c = run(["--llm"], [reply("s.py", SECRET_FIXED)], files={"s.py": SECRET_SRC})
    seen_text = json.dumps(c)
    s.expect(rc == 0, f"exit {rc}, expected 0")
    s.expect(c and "ghp_" not in seen_text, "the request held a token")
    s.expect(c and h.PLACEHOLDER_MARK in c[0]["files"][0]["content"], "the request did not hold the removal placeholder")
    s.expect(FAKE_KEY not in seen_text, "the API key reached the request")
    s.expect(FAKE_KEY not in o + e + output_text(), "the API key reached stdout, stderr or an output file")
    s.expect("ghp_" not in o + e + output_text(), "a token reached stdout, stderr or an output file")
    s.expect(os.path.exists(os.path.join(HEALED, "s.py")) and read(os.path.join(HEALED, "s.py")) == SECRET_FIXED, "healed file wrong")
    s.expect(read(os.path.join(SANDBOX, "s.py")) == SECRET_SRC, "sandbox/ was modified")

with scenario("llm: a reply that keeps the removal placeholder is rejected") as s:
    rc, o, e, c = run(["--llm"], [reply("s.py", h.PLACEHOLDER_MARK + " hardcoded Github credential>\nprint(1)\n")],
                      files={"s.py": SECRET_SRC})
    s.expect(rc == 2, f"exit {rc}, expected 2")
    s.expect(not os.path.exists(HEALED), "output/healed/ was created")

with scenario("llm: an empty sandbox exits 3 and never calls the model") as s:
    rc, o, e, c = run(["--llm"], files={}, forbid_call=True)
    s.expect(rc == 3, f"exit {rc}, expected 3")

with scenario("llm: a missing API key stops (exit 2) before any scan") as s:
    scans = []
    real_run_scan = h.run_scan
    h.run_scan = lambda *a, **k: scans.append(1) or real_run_scan(*a, **k)
    try:
        rc, o, e, c = run(["--llm"], files={"t.py": BAD}, key=False, forbid_call=True)
    finally:
        h.run_scan = real_run_scan
    s.expect(rc == 2, f"exit {rc}, expected 2")
    s.expect(not scans, "a scan ran")
    s.expect("ANTHROPIC_API_KEY" in e, "the message does not name the variable")

with scenario("llm: a retry sends the first rewrite, and the second rewrite is what is saved") as s:
    rc, o, e, c = run(["--llm"], [reply("t.py", FIRST_TRY), reply("t.py", GOOD)], files={"t.py": BAD})
    s.expect(rc == 0 and len(c) == 2, f"exit {rc} after {len(c)} calls, expected 0 after 2")
    s.expect(len(c) == 2 and c[1]["files"][0]["content"] == FIRST_TRY, "the second request did not hold the first rewrite")
    s.expect(os.path.exists(os.path.join(HEALED, "t.py")) and read(os.path.join(HEALED, "t.py")) == GOOD, "healed file is not the second rewrite")

with scenario("llm: --llm together with --build-payload is an argument error") as s:
    rc, o, e, c = run(["--llm", "--build-payload"], files={"t.py": BAD}, forbid_call=True)
    s.expect(rc == 2, f"exit {rc}, expected 2")

# --- unit checks (no scans) ---------------------------------------------------------------------

with scenario("llm: malformed or unsafe replies are rejected by validate_reply") as s:
    sent = {"t.py"}
    cases = {
        "not an object": ["x"],
        "extra top-level key": {"files": [{"path": "t.py", "content": "x"}], "more": 1},
        "empty file list": {"files": []},
        "extra file key": {"files": [{"path": "t.py", "content": "x", "mode": 1}]},
        "duplicate path": {"files": [{"path": "t.py", "content": "x"}] * 2},
        "non-string content": {"files": [{"path": "t.py", "content": 5}]},
        "oversized file": reply("t.py", "x" * (h.MAX_REPLY_FILE_BYTES + 1)),
        "unsent path": reply("other.py", "x"),
        "parent-directory path": reply("../escape.py", "x"),
        "absolute path": reply("/etc/passwd", "x"),
        "dot-dot inside path": reply("sub/../t.py", "x"),
        "placeholder left in": reply("t.py", h.PLACEHOLDER_MARK + " x>"),
    }
    for label, r in cases.items():
        try:
            h.validate_reply(r, sent)
            s.problems.append(f"{label} was accepted")
        except h.HealError:
            pass

with scenario("llm: validate_reply accepts a correct reply") as s:
    s.expect(h.validate_reply(reply("t.py", GOOD), {"t.py"}) == {"t.py": GOOD}, "a correct reply was not returned as given")

with scenario("llm: ANTHROPIC_* variables are removed from child-process environments") as s:
    os.environ["ANTHROPIC_API_KEY"], os.environ["ANTHROPIC_AUTH_TOKEN"], os.environ["KEEP_ME"] = FAKE_KEY, "t", "1"
    env = h.clean_env()
    s.expect(not any(k.startswith("ANTHROPIC_") for k in env), "an ANTHROPIC_ variable was kept")
    s.expect(env.get("KEEP_ME") == "1", "an unrelated variable was removed")

reset()
with scenario("llm: no heal temp folders are left behind") as s:
    left = set(glob.glob(os.path.join(tempfile.gettempdir(), "heal-*"))) - TMP_BEFORE
    s.expect(not left, "left behind: " + ", ".join(sorted(left)))

print(f"\n{passed} scenarios passed, {failed} failed")
sys.exit(1 if failed else 0)
