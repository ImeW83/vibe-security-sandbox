# vibe-security-sandbox

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
- `config/entrypoint.sh` : runtime checks inside the container, then packs `/output`
- `config/rules/` : local copy of community Semgrep rules (277 files, Python and JavaScript)
- `config/semgrep-rules/` : custom Semgrep rules (3 rules: `eval` in Python and JavaScript/TypeScript, `exec` in Python)
- `config/requirements.in` / `config/requirements.txt` : reviewed Python packages (with hashes) installed into the image at build time
- `config/package.json` / `config/package-lock.json` : reviewed Node packages (with integrity hashes) installed into the image at build time
- `Dockerfile` : Python 3.12 slim plus Node.js 20 (from Debian), non-root user
- `docker-compose.yml` : container limits
- `tests/run-tests.sh` : regression suite (14 checks through the full pipeline)

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

## Testing
```bash
./tests/run-tests.sh
```
Runs 14 checks through the full pipeline: clean Python and JavaScript run, SQL injection and `eval` are blocked, an empty sandbox is blocked, a hardcoded secret is blocked, pre-installed Python and Node packages load while the network stays blocked, `/output` files are saved while other files are discarded, an 80 MB write is stopped at the 50 MB cap, an oversized `sandbox/` is blocked, and an infinite loop is killed by the timeout. It moves anything in `sandbox/` and `output/` aside first and restores it afterwards, and exits non-zero if any check fails.

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

## Known limitations
**Scanning**
- Pattern matching misses indirect or obfuscated code (for example a call to `eval` built at runtime).
- `--severity ERROR` ignores WARNING-level findings.
- Coverage is only what is in `config/rules/` (Python and JavaScript folders), and rules are refreshed by hand. They come from `semgrep/semgrep-rules`, pinned to commit `16b9e6d45f10649f6a531ec4838ed9924372c3bc`.
- Two upstream rules were removed on purpose as false positives: `dangerous-subprocess-use-audit` (blocks any `subprocess` call with a variable argument, even with `shell=False`) and `arbitrary-sleep` (blocks `time.sleep()`). `subprocess-shell-true` still blocks the dangerous `shell=True` case.
- The secret filter is pattern-based, so unusual or custom secret formats can be missed. With `--no-verification`, findings are reported as unverified, so a revoked or fake key still blocks.

**Pinning and updates**
- The Semgrep and TruffleHog images and the sandbox base image (`python:3.12-slim`) are all pinned by digest, so none changes unless you change it.
- Pinned images do not get security updates on their own. To update one: pull the new image, read its digest (`docker image inspect <image> --format '{{index .RepoDigests 0}}'`), change the digest in the `Dockerfile` or `config/scan.sh`, rebuild with `docker compose build`, and re-run `./tests/run-tests.sh` before merging.

**Output and limits**
- `output/` contents are untrusted. The unpacker keeps regular files only (symlinks, devices, absolute paths and `..` are dropped), but review files before opening or running them.
- The time limit can be changed with the `GUARD_TIMEOUT` environment variable. Anyone who can set environment variables for the script can raise it, which is fine for a tool you run yourself but not for a shared pipeline.
