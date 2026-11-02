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
- `tests/run-tests.sh` : regression suite that runs six checks through the full pipeline
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
Runs six checks through the full pipeline: clean Python and JavaScript run, SQL injection and `eval` are blocked (exit 1), an empty sandbox is blocked (exit 3) and a hardcoded secret is blocked (exit 4). The script moves anything in `sandbox/` aside first and restores it afterwards. It exits non-zero if any check fails.

## Known limitations
- Community rules are incomplete (an `eval` call was missed in testing). A custom rule in `config/semgrep-rules/` now blocks `eval()` and `exec()` in Python and `eval()` in JavaScript/TypeScript, but indirect or obfuscated calls can still evade pattern matching
- `--severity ERROR` ignores WARNING-level findings
- Scans run fully offline using a local copy of the rules (`--metrics off`, `--disable-version-check`). The trade-off is that coverage is only what is copied into `config/rules/` (Python and JavaScript folders only), so the rules must be refreshed by hand to pick up new upstream rules
- The scan and the run use the same private snapshot of `sandbox/`, so files cannot change between them (TOCTOU closed). Files the code writes at runtime are lost when the run ends
- Dependencies must be installed at image build time, since the sandbox has no network
- The secret filter is pattern-based (TruffleHog detectors), so unusual or custom secret formats and obfuscated values can be missed
- Secrets are scanned with `--no-verification` to stay offline, so findings are reported as unverified and a revoked or fake key still blocks execution
- The TruffleHog image is pinned by digest (`sha256:0d003fc3...`) and must be updated by hand to get new detectors
- Community rules in `config/rules/` are copied from the official `semgrep/semgrep-rules` repo, pinned to commit `16b9e6d45f10649f6a531ec4838ed9924372c3bc`
- The noisy rule `python.lang.security.audit.dangerous-subprocess-use-audit` was removed on purpose, because it blocks any `subprocess` call with a variable argument even when `shell=False`. `subprocess-shell-true` still blocks the dangerous `shell=True` case
