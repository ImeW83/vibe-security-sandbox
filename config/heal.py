#!/usr/bin/env python3
"""config/heal.py - dry-run self-healing helper.

Runs scan.sh on ./sandbox, and on a fixable failure (exit 1 Semgrep, exit 4 secret)
writes a sanitised remediation prompt to output/heal-prompt.json.
No LLM call, no network, no secrets: only rule ids, detector names, files and line numbers.
"""
import json
import os
import re
import subprocess
import sys

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

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


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


def main():
    # Remove any prompt from a previous run so a stale one can never be mistaken for current.
    try:
        os.remove(PROMPT_FILE)
    except FileNotFoundError:
        pass

    proc = subprocess.run([SCAN], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    code, text = proc.returncode, proc.stdout

    if code == 0:
        print("[heal] Scan passed. Nothing to fix.")
        return 0
    if code in UNFIXABLE:
        print(f"[heal] Exit {code}: {UNFIXABLE[code]}. Rewriting the code will not fix this. Stopping.")
        return code
    if code not in FIXABLE:
        print(f"[heal] Exit {code}: unknown failure. Stopping.")
        return code

    kind = FIXABLE[code]
    findings = parse_semgrep(text) if kind == "semgrep" else parse_secrets(text)
    if not findings:
        print(f"[heal] Exit {code} but no findings could be parsed. Stopping (fail closed).")
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

    print(f"[heal] Exit {code} ({kind}): {len(findings)} finding(s). Prompt written to output/heal-prompt.json")
    return code


if __name__ == "__main__":
    sys.exit(main())
