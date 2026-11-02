# vibe-security-sandbox

A two-layer guardrail for running AI-generated code safely.

## How it works
1. **Layer 1: Sandbox.** A hardened Docker container that runs the code.
2. **Layer 2: Guardian scan.** Semgrep audits the code before anything executes.

`config/safe-run.sh` ties them together: scan first, run only if the scan passes.

## Layout
- `sandbox/` : AI-generated code goes here (contents are git-ignored)
- `config/entrypoint.sh` : runtime checks inside the container
- `config/scan.sh` : Semgrep scan (fail-closed)
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
- Fails closed: findings (exit 1), scanner crash (exit 2) and an empty sandbox (exit 3) all block execution

## Usage
```bash
# put code in ./sandbox, then:
./config/safe-run.sh python yourfile.py
./config/safe-run.sh node yourfile.js
```

## Known limitations
- Semgrep community rules are incomplete (an `eval` call was missed in testing)
- `--severity ERROR` ignores WARNING-level findings
- `--config auto` needs internet to fetch rules, so scans fail (and block) offline
- The scan and the run use the same private snapshot of `sandbox/`, so files cannot change between them (TOCTOU closed). Files the code writes at runtime are lost when the run ends
- Dependencies must be installed at image build time, since the sandbox has no network
