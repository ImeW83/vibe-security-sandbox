#!/usr/bin/env python3
"""config/heal.py - self-healing helper (dry run).

Runs scan.sh on ./sandbox, and on a fixable failure (exit 1 Semgrep, exit 4 secret)
writes a sanitised remediation prompt to output/heal-prompt.json.
With --build-payload it also prints the exact request payload a future LLM call would
send: the flagged files, with secret lines removed and checked by a TruffleHog gate.
No LLM call is made. The prompt holds only rule ids, detector names, files and line numbers.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCAN = os.path.join(HERE, "scan.sh")
PROMPT_FILE = os.path.join(ROOT, "output", "heal-prompt.json")

FIXABLE = {1: "semgrep", 4: "secret"}
UNFIXABLE = {
    2: "a scanner crashed or did not finish",
    3: "nothing to scan",
    5: "sandbox/ is over the size limit",
    124: "the run timed out",
}

MAX_FILES = 5
MAX_PAYLOAD_BYTES = 100 * 1024
MAX_SANDBOX_BYTES = 20 * 1024 * 1024

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


class HealError(Exception):
    """A payload step failed. The caller stops and sends nothing (fail closed)."""


def clean_env():
    """Environment for child processes: API credentials never reach a scanner."""
    return {k: v for k, v in os.environ.items() if not k.startswith("ANTHROPIC_")}


def clean_path(p):
    p = p.strip()
    for prefix in ("/src/", "/scan/"):
        if p.startswith(prefix):
            return p[len(prefix):]
    return p


def parse_semgrep(text):
    findings, cur_file, cur_rule = [], None, None
    for raw in text.splitlines():
        line = ANSI.sub("", raw)
        s = line.strip()
        if s.startswith("/src/"):
            cur_file = clean_path(s)
        elif "❯❯❱" in line:
            cur_rule = line.split("❯❯❱", 1)[1].strip().split(".")[-1]
        else:
            m = re.match(r"^\s*(\d+)┆", line)
            if m and cur_rule and cur_file:
                findings.append({"rule": cur_rule, "file": cur_file, "line": int(m.group(1))})
    return findings


def parse_secrets(text):
    findings, cur = [], {}
    for raw in text.splitlines():
        line = ANSI.sub("", raw).strip()
        if line.startswith("Detector Type:"):
            cur = {"detector": line.split(":", 1)[1].strip()}
        elif line.startswith("File:") and cur is not None:
            cur["file"] = clean_path(line.split(":", 1)[1])
        elif line.startswith("Line:") and "detector" in cur:
            cur["line"] = int(line.split(":", 1)[1].strip())
            if "file" in cur:
                findings.append(cur)
            cur = {}
        # "Raw result:" is deliberately never read or stored.
    return findings


def copy_sandbox():
    """Copy sandbox/ to a private temp folder. Returns (temp_root, copy_path)."""
    src = os.path.join(ROOT, "sandbox")
    total = 0
    for dirpath, _dirs, names in os.walk(src):
        for n in names:
            p = os.path.join(dirpath, n)
            if not os.path.islink(p):
                total += os.path.getsize(p)
    if total > MAX_SANDBOX_BYTES:
        raise HealError("sandbox/ is over the size limit")
    work = tempfile.mkdtemp(prefix="heal-")
    dst = os.path.join(work, "sandbox")
    shutil.copytree(src, dst, symlinks=True)  # symlinks stay links, never followed
    return work, dst


def read_flagged(root, rel):
    """Read one flagged file as UTF-8 text. Refuses paths that leave root, links and non-text."""
    path = os.path.join(root, rel)
    real_root = os.path.realpath(root)
    if os.path.isabs(rel) or not os.path.realpath(path).startswith(real_root + os.sep):
        raise HealError(f"refusing a path outside sandbox/: {rel}")
    if os.path.islink(path) or not os.path.isfile(path):
        raise HealError(f"{rel} is not a regular file")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError:
        raise HealError(f"{rel} is not valid UTF-8 text")


def safe_name(s):
    s = re.sub(r"[^A-Za-z0-9 _.-]", "", s)[:40].strip()
    return s or "secret"


def may_span_lines(line):
    """True if a flagged line could be the start of a multi-line secret or string."""
    return "-----BEGIN" in line or any(line.count(q) % 2 for q in ('"""', "'''", "`"))


def redact_secret_lines(text, hits):
    """Replace each flagged line. hits is a list of (line_number, detector)."""
    lines = text.split("\n")
    for n, detector in hits:
        if not 1 <= n <= len(lines):
            raise HealError("a flagged line number is out of range")
        line = lines[n - 1]
        if may_span_lines(line):
            raise HealError("a flagged line may start a multi-line secret and cannot be redacted safely; fix it by hand")
        indent = line[: len(line) - len(line.lstrip())]
        lines[n - 1] = f"{indent}<line removed: hardcoded {safe_name(detector)} credential>"
    return "\n".join(lines)


def trufflehog_image():
    """The pinned TruffleHog image, read from scan.sh so there is one source of truth."""
    with open(SCAN, encoding="utf-8") as f:
        m = re.search(r'^TRUFFLEHOG_IMAGE="([^"]+@sha256:[0-9a-f]{64})"', f.read(), re.M)
    if not m:
        raise HealError("could not read the pinned TruffleHog image from scan.sh")
    return m.group(1)


def secret_gate(folder):
    """True only if TruffleHog finds nothing in folder. Its output is discarded so no token is printed."""
    r = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{folder}:/scan:ro,z", trufflehog_image(),
         "filesystem", "/scan", "--no-verification", "--no-update", "--fail", "--fail-on-scan-errors"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=clean_env())
    return r.returncode == 0


def build_payload(prompt, work_dir):
    """The request body a future LLM call would send. Raises HealError instead of sending anything unsafe."""
    kind, findings = prompt["kind"], prompt["findings"]
    by_file = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    if len(by_file) > MAX_FILES:
        raise HealError(f"{len(by_file)} flagged files; the limit is {MAX_FILES}")

    files = []
    for rel in sorted(by_file):
        text = read_flagged(work_dir, rel)
        if kind == "secret":
            text = redact_secret_lines(text, [(f["line"], f.get("detector", "")) for f in by_file[rel]])
        files.append({"path": rel, "content": text})
    if sum(len(f["content"].encode("utf-8")) for f in files) > MAX_PAYLOAD_BYTES:
        raise HealError("flagged files are over the payload size limit")

    # Final gate: scan exactly what would be sent. Anything detectable stops everything.
    gate_dir = tempfile.mkdtemp(prefix="heal-gate-")
    try:
        for f in files:
            dest = os.path.join(gate_dir, f["path"])
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(f["content"])
        for d, _dirs, names in os.walk(gate_dir):  # readable by the scanner container
            os.chmod(d, 0o755)
            for n in names:
                os.chmod(os.path.join(d, n), 0o644)
        if not secret_gate(gate_dir):
            raise HealError("the pre-send secret gate found something; nothing is sent")
    finally:
        shutil.rmtree(gate_dir, ignore_errors=True)

    return {"kind": kind, "instruction": prompt["instruction"], "findings": findings, "files": files}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Dry-run self-healing helper: scan sandbox/ and write a sanitised prompt.")
    ap.add_argument("--build-payload", action="store_true",
                    help="also print the request payload an LLM call would send (no API call is made)")
    args = ap.parse_args(argv)
    out = sys.stderr if args.build_payload else sys.stdout  # keep stdout clean for the payload JSON

    # Remove any prompt from a previous run so a stale one can never be mistaken for current.
    try:
        os.remove(PROMPT_FILE)
    except FileNotFoundError:
        pass

    proc = subprocess.run([SCAN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=clean_env())
    code, text = proc.returncode, proc.stdout

    if code == 0:
        print("[heal] Scan passed. Nothing to fix.", file=out)
        return 0
    if code in UNFIXABLE:
        print(f"[heal] Exit {code}: {UNFIXABLE[code]}. Rewriting the code will not fix this. Stopping.", file=out)
        return code
    if code not in FIXABLE:
        print(f"[heal] Exit {code}: unknown failure. Stopping.", file=out)
        return code

    kind = FIXABLE[code]
    findings = parse_semgrep(text) if kind == "semgrep" else parse_secrets(text)
    if not findings:
        print(f"[heal] Exit {code} but no findings could be parsed. Stopping (fail closed).", file=out)
        return 2

    instruction = (
        "Your code was blocked by a security scan. Rewrite the flagged code to remove the problem "
        "without changing what the program does. "
    )
    if kind == "secret":
        instruction += "Never hardcode credentials: read them from environment variables instead."
    prompt = {"exit_code": code, "kind": kind, "instruction": instruction, "findings": findings}

    os.makedirs(os.path.dirname(PROMPT_FILE), exist_ok=True)
    with open(PROMPT_FILE, "w") as f:
        json.dump(prompt, f, indent=2)
    os.chmod(PROMPT_FILE, 0o600)

    print(f"[heal] Exit {code} ({kind}): {len(findings)} finding(s). Prompt written to output/heal-prompt.json", file=out)

    if args.build_payload:
        work = None
        try:
            work, sandbox_copy = copy_sandbox()
            payload = build_payload(prompt, sandbox_copy)
        except HealError as e:
            print(f"[heal] Payload not built: {e}. Stopping (fail closed).", file=sys.stderr)
            return 2
        finally:
            if work:
                shutil.rmtree(work, ignore_errors=True)
        print(json.dumps(payload, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
