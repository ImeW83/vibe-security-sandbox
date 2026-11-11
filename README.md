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
- `config/heal.py` : dry-run self-healing helper; scans `sandbox/` and, on a fixable failure, writes a sanitised `output/heal-prompt.json` (no LLM call)
- `config/entrypoint.sh` : runtime checks inside the container, then packs `/output`
- `config/rules/` : local copy of community Semgrep rules (277 files, Python and JavaScript)
- `config/semgrep-rules/` : custom Semgrep rules (3 rules: `eval` in Python and JavaScript/TypeScript, `exec` in Python)
- `config/requirements.in` / `config/requirements.txt` : reviewed Python packages (with hashes) installed into the image at build time
- `config/package.json` / `config/package-lock.json` : reviewed Node packages (with integrity hashes) installed into the image at build time
- `Dockerfile` : Python 3.12 slim plus Node.js 20 (from Debian), non-root user
- `docker-compose.yml` : container limits
- `tests/run-tests.sh` : regression suite (17 checks: the full pipeline and `heal.py`)

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

## Self-healing helper (dry run)
```bash
./config/heal.py
```
Runs `config/scan.sh` on `sandbox/`. It takes no arguments, does not run the code and makes no LLM call. What happens depends on the scan result:
- **Exit 0:** nothing to fix.
- **Exit 1 (Semgrep) or exit 4 (secret):** writes `output/heal-prompt.json` (mode 600) and exits with the same code.
- **Exit 2 (a scanner failed) or 3 (nothing to scan):** rewriting the code will not fix these, so it stops and writes no prompt. Any other exit code also stops without a prompt.
- **Findings cannot be parsed:** fails closed (exit 2).

The prompt holds only `exit_code`, `kind` (`semgrep` or `secret`), a fixed `instruction`, and `findings` (the rule or detector name, the file and the line number). It never holds code text, and never TruffleHog's "Raw result" line, which prints the full secret. A prompt left by an earlier run is deleted at the start of every run, so a stale one is never mistaken for a current one.

## Testing
```bash
./tests/run-tests.sh
```
Runs 17 checks. Fourteen go through the full pipeline: clean Python and JavaScript run, SQL injection and `eval` are blocked, an empty sandbox is blocked, a hardcoded secret is blocked, pre-installed Python and Node packages load while the network stays blocked, `/output` files are saved while other files are discarded, an 80 MB write is stopped at the 50 MB cap, an oversized `sandbox/` is blocked, and an infinite loop is killed by the timeout. Three cover `config/heal.py`: a stale prompt is deleted on an unfixable run, a fixable Semgrep finding gives a correct prompt, and a fixable secret gives a correct prompt that contains no part of the token. It moves anything in `sandbox/` and `output/` aside first and restores it afterwards, and exits non-zero if any check fails.

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

## Continuous integration
`.github/workflows/tests.yml` runs `./tests/run-tests.sh` on every push to `main` and on every pull request. The workflow builds the image and runs all 17 checks on a GitHub-hosted runner. The `actions/checkout` step is pinned to a full commit SHA, the workflow token is read-only (`contents: read`), and a run is cancelled after 30 minutes. `config/safe-run.sh` runs the container as the host user's uid and gid, so it works on runners where that is not 1000.

## Known limitations
**Scanning**
- Pattern matching misses indirect or obfuscated code (for example a call to `eval` built at runtime).
- `--severity ERROR` ignores WARNING-level findings.
- Coverage is only what is in `config/rules/` (Python and JavaScript folders), and rules are refreshed by hand. They come from `semgrep/semgrep-rules`, pinned to commit `16b9e6d45f10649f6a531ec4838ed9924372c3bc`.
- Two upstream rules were removed on purpose as false positives: `dangerous-subprocess-use-audit` (blocks any `subprocess` call with a variable argument, even with `shell=False`) and `arbitrary-sleep` (blocks `time.sleep()`). `subprocess-shell-true` still blocks the dangerous `shell=True` case.
- A `shell=True` call with a fixed string literal (for example `subprocess.call("ls -l", shell=True)`) passes the scan. `shell=True` with a variable command is blocked. Review literal `shell=True` calls by hand.
- The secret filter is pattern-based, so unusual or custom secret formats can be missed. With `--no-verification`, findings are reported as unverified, so a revoked or fake key still blocks.

**Self-healing helper**
- `config/heal.py` is a dry run: it only writes `output/heal-prompt.json`. Nothing reads that file yet, and nothing rewrites code or calls an LLM.
- It scans `sandbox/` directly, not the private snapshot that `safe-run.sh` uses, so it is a development aid, not part of the guarded run.
- The prompt names where the problem is, not what the code says, so a rewrite has to be re-checked by the same scans.

**Pinning and updates**
- The Semgrep and TruffleHog images and the sandbox base image (`python:3.12-slim`) are all pinned by digest, so none changes unless you change it.
- Pinned images do not get security updates on their own. To update one: pull the new image, read its digest (`docker image inspect <image> --format '{{index .RepoDigests 0}}'`), change the digest in the `Dockerfile` or `config/scan.sh`, rebuild with `docker compose build`, and re-run `./tests/run-tests.sh` before merging.

**Output and limits**
- `output/` contents are untrusted. The unpacker keeps regular files only (symlinks, devices, absolute paths and `..` are dropped), but review files before opening or running them.
- The time limit can be changed with the `GUARD_TIMEOUT` environment variable. Anyone who can set environment variables for the script can raise it, which is fine for a tool you run yourself but not for a shared pipeline.
