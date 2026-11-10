# CLI Binary Executable

## Overview
The `cli/bin` directory contains the executable entry point for the BOLTCLONE CLI tool. It handles CLI option parsing, scan lifecycle orchestration, progress reporting, exit code determination, and report file generation.

## Interface
- Executable Entry Point: [`boltclone.js`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/bin/boltclone.js)
  - Invocation: `boltclone <target-url> [options]` or `node cli/bin/boltclone.js <target-url> [options]`
  - Flags: `-c, --concurrency <n>`, `-t, --timeout <ms>`, `--skip <list>`, `--import-session <file>`, `--secondary-auth <token>`, `--allow-mutating-methods`, `--dry-run`, `--rate-limit <rps>`, `--openapi <file>`, `--postman <file>`, `--html <file>`, `--gemini-key <key>`, `--vulndb`, `--auth-test`, `--creds <file>`, `--subdomains`, `--json <file>`, `--csv <file>`, `--no-color`.

## Invariants
- Exit codes strictly adhere to the security scanning gate contract:
  - `0`: Scan completed successfully with zero high/critical severity findings.
  - `1`: Scan execution error or invalid CLI arguments.
  - `2`: One or more high or critical severity vulnerabilities detected (usable as a CI/CD quality gate).
- Zero external runtime dependencies.

## Side Effects
- Reads `process.argv` and environment variables (`GEMINI_API_KEY`).
- Writes progress messages to `stderr` and summary reports to `stdout`.
- Writes output artifacts to paths specified via `--json`, `--csv`, `--html`, `--openapi`, and `--postman`.

## Verification
- Run: `node cli/bin/boltclone.js --help`

