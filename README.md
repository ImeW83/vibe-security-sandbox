# vibe-security-sandbox

[![guardrail tests](https://github.com/ImeW83/vibe-security-sandbox/actions/workflows/tests.yml/badge.svg)](https://github.com/ImeW83/vibe-security-sandbox/actions/workflows/tests.yml)

A guardrail for running AI-generated code. The code is checked for secrets and security flaws first, then run in a locked-down container with no network.

## How a run works
`./config/safe-run.sh <command>` runs these steps in order. If any step fails, nothing runs.
1. **Size check:** refuse a `sandbox/` over 20 MB (exit 5).
2. **Snapshot:** copy `sandbox/` into a private temp folder. Every later step uses this copy, so files cannot change between the scan and the run.
3. **Empty check:** refuse an empty snapshot (exit 3). A `.gitkeep` alone does not count.
4. **Secret filter:** TruffleHog scans the snapshot for hardcoded credentials (exit 4).
5. **Structural scan:** Semgrep scans the snapshot for high-severity flaws (exit 1, or exit 2 if the scanner crashes).
6. **Run:** the same snapshot is mounted into the hardened container, with a time limit (exit 124 on timeout).
7. **Collect output:** anything written to `/output` is packed by the container and unpacked safely into `output/` on the host.

## The three layers
1. **Layer 1: Sandbox.** A hardened Docker container runs the code.
2. **Layer 2: Guardian scan.** Semgrep audits the code before it executes, using local rules so it works offline.
3. **Layer 3: Secret filter.** TruffleHog looks for hardcoded API keys and tokens, fully offline.

## Layout
- `sandbox/` : put AI-generated code here (contents are git-ignored)
- `output/` : the only place run results survive; git-ignored, treat contents as untrusted
- `config/safe-run.sh` : the entry point (steps 1 to 7 above)
- `config/scan.sh` : secret filter and Semgrep scan (fail-closed)
- `config/unpack-output.sh` : saves run results to `output/` (regular files only, size-checked)
- `config/heal.py` : self-healing helper: a dry run, `--build-payload` (shows what a model would be sent) and `--llm` (asks a model to fix a finding); see "Self-healing helper"
- `config/heal-requirements.in` / `config/heal-requirements.txt` : the one host-side package for `--llm` (`anthropic`, with hashes), installed into the git-ignored `.venv-heal/`
- `config/entrypoint.sh` : runtime checks inside the container, then packs `/output`
- `config/rules/` : local copy of community Semgrep rules (277 files, Python and JavaScript)
- `config/semgrep-rules/` : custom Semgrep rules (3 rules: `eval` in Python and JavaScript/TypeScript, `exec` in Python)
- `config/requirements.in` / `config/requirements.txt` : reviewed Python packages (with hashes) installed into the image at build time
- `config/package.json` / `config/package-lock.json` : reviewed Node packages (with integrity hashes) installed into the image at build time
- `Dockerfile` : Python 3.12 slim plus Node.js 20 (from Debian), non-root user
- `docker-compose.yml` : container limits
- `tests/run-tests.sh` : regression suite (36 checks: the full pipeline, `heal.py`, and `heal.py --llm` with a fake model)
- `tests/heal_llm_scenarios.py` : the 14 `--llm` scenarios, run by `run-tests.sh` (it refuses to run on its own)

## Layer 1 controls (container)
- Non-root user (`sandboxuser`), no login shell
- Read-only root filesystem
- `/tmp` is a 64 MB tmpfs and `/output` is a 50 MB tmpfs, both `noexec,nosuid`
- All capabilities dropped, `no-new-privileges`
- 512 MB memory, 1 CPU, 100 processes max
- No network access
- 60-second run limit (the container itself is force-removed, not just the client)

## Layer 2 and 3 controls (scanners)
- Semgrep and TruffleHog run in separate containers, pinned by image digest
- The scanned code and the rules are mounted read-only
- Semgrep runs with `--metrics off` and `--disable-version-check`; TruffleHog runs with `--no-verification`, so no code or key is sent anywhere
- Rules are local, so scans work with the network off

## Exit codes
| Code | Meaning |
|------|---------|
| 0 | Scans passed and the command ran (or the command's own exit code) |
| 1 | Semgrep found a high-severity flaw |
| 2 | A scanner crashed or did not finish (fails closed) |
| 3 | Nothing to scan (empty `sandbox/`) |
| 4 | TruffleHog found a hardcoded secret |
| 5 | `sandbox/` is over 20 MB |
| 124 | The run exceeded the time limit (default 60 seconds) |

## Usage
```bash
# put code in ./sandbox, then:
./config/safe-run.sh python yourfile.py
./config/safe-run.sh node yourfile.js
```
Run results go in `/output` inside the container and appear in `output/` on the host. Everything else the code writes is discarded when the run ends.

## Self-healing helper
`config/heal.py` turns a blocked scan into a fix request. It has three modes, and only the last one calls a model.

```bash
./config/heal.py                  # dry run: scan and write a prompt; nothing leaves the machine
./config/heal.py --build-payload  # also print exactly what a model would be sent (no API call)
./config/heal.py --llm            # ask a model to fix the finding (needs an API key, see below)
```

**All modes** run `config/scan.sh` and act on the result:
- **Exit 0:** nothing to fix.
- **Exit 1 (Semgrep) or exit 4 (secret):** writes `output/heal-prompt.json` (mode 600) and carries on.
- **Exit 2 (a scanner failed) or 3 (nothing to scan):** rewriting the code will not fix these, so it stops and writes no prompt. Any other exit code also stops without a prompt.
- **Findings cannot be parsed:** fails closed (exit 2).

The prompt holds only `exit_code`, `kind` (`semgrep` or `secret`), a fixed `instruction`, and `findings` (the rule or detector name, the file and the line number). It never holds code text, and never TruffleHog's "Raw result" line, which prints the full secret. Output from an earlier run (the prompt, and `output/healed/` in `--llm` mode) is deleted at the start of every run, so stale output is never mistaken for current. The plain dry run scans `sandbox/` directly; `--build-payload` and `--llm` scan a private copy of it and send that same copy.

### `--build-payload`: see what would be sent
Prints the request payload as JSON on stdout (status lines go to stderr). Nothing is sent anywhere.
- Only the flagged files are included, at most 5 files and 100 KB in total. More than that stops with exit 2.
- For a secret finding, each flagged line is replaced whole by `<line removed: hardcoded <Detector> credential>`, so the token never enters the payload.
- A flagged line that could start a multi-line secret (it contains `-----BEGIN`, or an odd number of `"""`, `'''` or backticks) is refused, because the scanner reports only the first line. Fix those by hand.
- Absolute paths, `..`, symlinks and files that are not UTF-8 text are refused.
- Last check: the exact files that would be sent are scanned with the pinned TruffleHog image. If it finds anything, nothing is sent (exit 2). Its output is discarded so no token is printed.

### `--llm`: ask a model to fix it
**Experimental: not yet verified against the live API** (see Known limitations).

One-time setup. The SDK is installed on the host in a git-ignored venv, never in the sandbox image:
```bash
python3 -m venv .venv-heal
.venv-heal/bin/pip install --require-hashes -r config/heal-requirements.txt
```
Then, with the key in your shell only:
```bash
read -rsp "Anthropic API key: " ANTHROPIC_API_KEY; echo; export ANTHROPIC_API_KEY
./config/heal.py --llm
```
`heal.py` switches to `.venv-heal` by itself. The key must be in `ANTHROPIC_API_KEY`. Without it, `heal.py` stops (exit 2) before any scan, copy or request. Logins made with `ant auth login` are not used.

What it does, in order:
1. Copies `sandbox/` to a private temp folder and scans that copy.
2. On exit 1 or 4, builds the payload described above and sends it to `claude-sonnet-5-5` (effort `medium`), with an instruction to treat the file contents as data, not instructions.
3. Validates the reply. It must be JSON holding the complete content of files that were sent. An unsent, absolute or `..` path, a duplicate, a file over 100 KB, or a leftover removal placeholder is rejected. A refusal, a cut-off answer, bad JSON, or an API or network error also stops the run.
4. Writes the reply into the copy and re-scans it with the same `scan.sh` (Semgrep and TruffleHog).
5. Retries only on a new exit 1 or 4, up to 3 attempts. Any other scan result stops the loop.
6. On a pass, saves the changed files to `output/healed/` (mode 600, with a `README.txt`).

`sandbox/` is never modified, and `heal.py` never runs the rewritten code. Exit codes: `0` healed (or nothing to fix), `1` or `4` still blocked after 3 attempts (nothing saved), `3` nothing to scan, and `2` for a failure: a missing key, an API or network error, a refusal, an unusable reply, or a scanner crash. If a re-scan returns some other code, that code is returned.

**Treat `output/healed/` like any untrusted output.** A rewrite that passed the scans is not proven to behave the same. Compare it with `sandbox/` (for example with `diff`) before copying anything over.

**The key and your code.** The key is read from the environment only. It is passed to the SDK, removed from the environment of every child process (the scanners never see it), and never printed, logged or written to a file. Error messages show only the status code, the error class and the request id. The flagged files do leave your machine: they go to the Anthropic API. That is a change from the rest of this tool, where nothing is sent anywhere. Do not use `--llm` on code you cannot send to a third party.

## Testing
```bash
./tests/run-tests.sh
```
Runs 36 checks. Fourteen go through the full pipeline: clean Python and JavaScript run, SQL injection and `eval` are blocked, an empty sandbox is blocked, a hardcoded secret is blocked, pre-installed Python and Node packages load while the network stays blocked, `/output` files are saved while other files are discarded, an 80 MB write is stopped at the 50 MB cap, an oversized `sandbox/` is blocked, and an infinite loop is killed by the timeout. Eight cover `config/heal.py` itself: a stale prompt is deleted on an unfixable run, a fixable Semgrep finding and a fixable secret give correct prompts (the latter with no part of the token), and `--build-payload` removes the secret line, sends a Semgrep file as written, refuses a multi-line secret and a symlink to an outside file, and lets the pre-send gate block a payload that still holds a token. The last fourteen (`tests/heal_llm_scenarios.py`) run `heal.py --llm` against a fake model with the real scans, so they need no API key and no network. They cover a fix in one attempt, the 3-attempt ceiling, a refusal, rejected replies, no token or API key in any request or output, a retry, and a missing key. These tests do not call the real API. The suite moves anything in `sandbox/` and `output/` aside first and restores it afterwards, and exits non-zero if any check fails.

## Adding packages
The sandbox has no network, so packages are installed at image build time from a reviewed list:
1. Add the package to `config/requirements.in`.
2. Regenerate `config/requirements.txt` with `pip-compile --generate-hashes`.
3. Review the diff.
4. Run `docker compose build`.

pip runs with `--require-hashes`, so a tampered download fails the build.

**Node packages** follow the same idea, using a lockfile:
1. Add the package with an exact version (no `^` or `~`) to `config/package.json`.
2. Regenerate `config/package-lock.json` with `npm install --package-lock-only --ignore-scripts` (run it in a throwaway container, not on your host).
3. Review the diff.
4. Run `docker compose build`.

The image runs `npm ci --ignore-scripts`, which installs only what the lockfile lists, checks integrity hashes and refuses to run package install scripts. Packages live in `/opt/app/node_modules` and are found through `NODE_PATH`.

**Packages for `heal.py --llm`** are pinned the same way, but they live on the host, not in the image. `config/heal-requirements.in` lists `anthropic`, and `config/heal-requirements.txt` is made with `pip-compile --generate-hashes` in a throwaway container that uses the same Python version as your host (it was compiled under Python 3.14, so regenerate it if yours differs). Install it into `.venv-heal` with `pip install --require-hashes`.

## Continuous integration
`.github/workflows/tests.yml` runs `./tests/run-tests.sh` on every push to `main` and on every pull request. The workflow builds the image and runs all 36 checks on a GitHub-hosted runner. The `actions/checkout` step is pinned to a full commit SHA, the workflow token is read-only (`contents: read`), and a run is cancelled after 30 minutes. `config/safe-run.sh` runs the container as the host user's uid and gid, so it works on runners where that is not 1000.

## Known limitations
**Scanning**
- Pattern matching misses indirect or obfuscated code (for example a call to `eval` built at runtime).
- `--severity ERROR` ignores WARNING-level findings.
- Coverage is only what is in `config/rules/` (Python and JavaScript folders), and rules are refreshed by hand. They come from `semgrep/semgrep-rules`, pinned to commit `16b9e6d45f10649f6a531ec4838ed9924372c3bc`.
- Two upstream rules were removed on purpose as false positives: `dangerous-subprocess-use-audit` (blocks any `subprocess` call with a variable argument, even with `shell=False`) and `arbitrary-sleep` (blocks `time.sleep()`). `subprocess-shell-true` still blocks the dangerous `shell=True` case.
- A `shell=True` call with a fixed string literal (for example `subprocess.call("ls -l", shell=True)`) passes the scan. `shell=True` with a variable command is blocked. Review literal `shell=True` calls by hand.
- The secret filter is pattern-based, so unusual or custom secret formats can be missed. With `--no-verification`, findings are reported as unverified, so a revoked or fake key still blocks.

**Self-healing helper**
- **`--llm` is experimental and not verified against the live API.** The request shape, the reply handling and the retry loop are tested only with a fake model, and with the real SDK over a mocked HTTP transport. Whether the live API accepts the request as sent, and how good the rewrites are, is unproven.
- A passing re-scan means the rewrite no longer trips Semgrep or TruffleHog. It does not mean the program still behaves the same. Review `output/healed/` yourself.
- Multi-line secrets are caught by a heuristic, not by proof. The scanner reports only a secret's first line. A line that looks like the start of a multi-line value is refused, but a multi-line secret whose first line has none of those markers could leave its remaining lines in the payload, and the TruffleHog check cannot recognise a fragment.
- A removed line loses everything on it, including the variable name, so the model cannot see what the credential was called.
- Prompt injection cannot be ruled out. The file contents are sent as data, with an instruction to ignore instructions inside them, which a model may not follow. That is why every answer is re-scanned and saved for review, and never applied or run.
- Only the flagged files are sent, up to 5 files and 100 KB. A larger set stops with exit 2.
- The plain dry run scans `sandbox/` directly. `--build-payload` and `--llm` scan a private copy. None of the modes is part of the guarded run in `safe-run.sh`.

**Pinning and updates**
- The Semgrep and TruffleHog images and the sandbox base image (`python:3.12-slim`) are all pinned by digest, so none changes unless you change it.
- Pinned images do not get security updates on their own. To update one: pull the new image, read its digest (`docker image inspect <image> --format '{{index .RepoDigests 0}}'`), change the digest in the `Dockerfile` or `config/scan.sh`, rebuild with `docker compose build`, and re-run `./tests/run-tests.sh` before merging.

**Output and limits**
- `output/` contents are untrusted. The unpacker keeps regular files only (symlinks, devices, absolute paths and `..` are dropped), but review files before opening or running them.
- The time limit can be changed with the `GUARD_TIMEOUT` environment variable. Anyone who can set environment variables for the script can raise it, which is fine for a tool you run yourself but not for a shared pipeline.
