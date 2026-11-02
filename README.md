# vibe-security-sandbox

A two-layer guardrail for running AI-generated code safely.

## How it works
1. **Layer 1: Sandbox.** A hardened Docker container that runs the code.
2. **Layer 2: Guardian scan.** Semgrep audits the code before anything executes.
3. **Layer 3: Secret filter.** TruffleHog scans for hardcoded credentials (API keys, tokens) before Semgrep runs, fully offline.

`config/safe-run.sh` ties them together: scan first, run only if the scan passes.

## Layout
- `sandbox/` : AI-generated code goes here (contents are git-ignored)
- `config/entrypoint.sh` : runtime checks inside the container
- `config/scan.sh` : Semgrep scan (fail-closed)
- `config/semgrep-rules/` : custom Semgrep rules (`eval`/`exec`), loaded by `scan.sh`
- `config/rules/` : local copy of community Semgrep rules (Python and JavaScript), so scans run offline
- `config/requirements.in` / `config/requirements.txt` : reviewed list of Python packages (with hashes) pre-installed into the image at build time
- `tests/run-tests.sh` : regression suite that runs seven checks through the full pipeline
- `config/safe-run.sh` : scan, then run in the sandbox
- `Dockerfile` : Python 3.12 slim + Node.js, non-root user
- `docker-compose.yml` : container limits

## Layer 1 controls
- Non-root user, no login shell
- Read-only root filesystem
- `/tmp` as tmpfs with `noexec,nosuid`
- All capabilities dropped, `no-new-privileges`
- 512 MB memory, 1 CPU, 100 processes max
- No network access

## Layer 2 controls
- Semgrep image pinned by digest
- Read-only mount of the scanned code
- Fails closed: findings (exit 1), scanner crash (exit 2), an empty sandbox (exit 3) and a detected secret (exit 4) all block execution

## Usage
```bash
# put code in ./sandbox, then:
./config/safe-run.sh python yourfile.py
./config/safe-run.sh node yourfile.js
```

## Testing
```bash
./tests/run-tests.sh
```
Runs seven checks through the full pipeline: clean Python and JavaScript run, SQL injection and `eval` are blocked (exit 1), an empty sandbox is blocked (exit 3), a hardcoded secret is blocked (exit 4), and a pre-installed package (`requests`) imports while the network stays blocked. The script moves anything in `sandbox/` aside first and restores it afterwards. It exits non-zero if any check fails.

## Known limitations
- Community rules are incomplete (an `eval` call was missed in testing). A custom rule in `config/semgrep-rules/` now blocks `eval()` and `exec()` in Python and `eval()` in JavaScript/TypeScript, but indirect or obfuscated calls can still evade pattern matching
- `--severity ERROR` ignores WARNING-level findings
- Scans run fully offline using a local copy of the rules (`--metrics off`, `--disable-version-check`). The trade-off is that coverage is only what is copied into `config/rules/` (Python and JavaScript folders only), so the rules must be refreshed by hand to pick up new upstream rules
- The scan and the run use the same private snapshot of `sandbox/`, so files cannot change between them (TOCTOU closed). Files the code writes at runtime are lost when the run ends
- Python packages come only from the reviewed list in `config/requirements.txt`, installed at image build time with hash checking (`--require-hashes`). The sandbox has no network, so anything not in that list fails at import. To add a package: add it to `config/requirements.in`, regenerate the file with `pip-compile --generate-hashes`, review the diff, then run `docker compose build`. Node packages are not pre-installed yet
- The secret filter is pattern-based (TruffleHog detectors), so unusual or custom secret formats and obfuscated values can be missed
- Secrets are scanned with `--no-verification` to stay offline, so findings are reported as unverified and a revoked or fake key still blocks execution
- The TruffleHog image is pinned by digest (`sha256:0d003fc3...`) and must be updated by hand to get new detectors
- Community rules in `config/rules/` are copied from the official `semgrep/semgrep-rules` repo, pinned to commit `16b9e6d45f10649f6a531ec4838ed9924372c3bc`
- The noisy rule `python.lang.security.audit.dangerous-subprocess-use-audit` was removed on purpose, because it blocks any `subprocess` call with a variable argument even when `shell=False`. `subprocess-shell-true` still blocks the dangerous `shell=True` case
