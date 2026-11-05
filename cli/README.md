# BOLTCLONE CLI

Command-line vulnerability assessment tool for web apps and APIs. Zero external
dependencies — built entirely on Node's standard library (native `fetch`, `tls`,
`node:crypto`, `node:util.parseArgs`).

## Install

Already linked globally on this machine via `npm link` — open a new terminal and
run `boltclone` directly. To set up elsewhere:

```bash
cd cli
npm link
```

## Usage

```text
boltclone <target-url> [options]

Options:
  -c, --concurrency <n>   Max concurrent requests (default: 8)
  -t, --timeout <ms>      Per-request timeout in ms (default: 8000)
      --skip <list>       Comma-separated categories to skip:
                            injection,access,tls,deps,cookies,graphql,exposure,bopla
      --import-session <file>
                          Path to JSON traffic session exported from Chrome extension
      --secondary-auth <token>
                          Auth token for User B (e.g. "Bearer eyJ...") to power
                          dual-context BOLA (WSTG-ATHZ-02 / ASTF-ATHZ-01) and
                          BFLA (WSTG-ATHZ-03 / ASTF-ATHZ-02) verification
      --allow-mutating-methods
                          Opt-in to replay and fuzz POST, PUT, PATCH, DELETE
                          endpoints. Default: only GET, HEAD, OPTIONS are mutated.
                          WARNING: may cause state changes on the target system.
      --dry-run           Print all planned mutated requests to stdout without
                          dispatching any network packets
      --rate-limit <rps>  Maximum requests per second dispatched to the target
                          (default: 15, minimum: 1)
      --openapi <file>    Generate and write OpenAPI 3.0 specification JSON to <file>
      --postman <file>    Generate and write Postman Collection v2.1 JSON to <file>
      --html <file>       Generate and write self-contained executive HTML report to <file>
      --gemini-key <key>  Google Gemini API Key for AI threat modeling & fix synthesis
                          (or set GEMINI_API_KEY env var)
      --vulndb            Enable live Vulnerability Database lookup (OSV.dev / NVD)
                          for detected server technologies
      --auth-test         Enable opt-in auth / brute-force checks
                          (only against targets you own or are authorized to test)
      --creds <file>      Path to a JSON file of {username,password} pairs for
                          --auth-test (default: small built-in list)
      --subdomains        Enable opt-in subdomain enumeration via crt.sh
                          (queries a third-party service with the target domain)
      --json <file>       Write full results as JSON to <file>
      --csv <file>        Write findings as CSV to <file>
      --no-color          Disable colored output
  -h, --help              Show this help
```

## OWASP Standards Alignment

BOLTCLONE covers four foundational security frameworks:
1. **OWASP Top 10 Web Application Security Risks (2021)**: Active and passive detection across A01–A10.
2. **OWASP API Security Top 10 (2023)**: Complete coverage across API1–API10 (including dual-context BOLA, BOPLA mass assignment, and BFLA role tampering).
3. **OWASP Web Security Testing Guide (WSTG v4.2)**: Procedural testing methodologies covering Information Gathering, Configuration, Authentication, Authorization, Session Management, Input Validation, and Cryptography.
4. **OWASP API Security Testing Framework (ASTF)**: Systematic API reconnaissance, property-level access checks, parameter fuzzing, and telemetry tracing.

All findings across console summaries, JSON dumps, CSV tables, and interactive HTML dashboards include unified taxonomy tags:
```text
[HIGH] Confirmed BOLA — cross-tenant object access (OWASP API1 | WSTG-ATHZ-02 | ASTF-ATHZ-01)
  category: access  url: https://api.example.com/orders/102
  evidence: User B (secondary token) received HTTP 200 with matching response schema.
```

## Dual-Context Testing & Session Replay

Replay captured authenticated sessions and execute comparative cross-tenant tests:

```bash
# Basic scan with default rate limit (15 QPS)
boltclone https://example.com --vulndb

# Replay Chrome Extension session with User B secondary token for dual-context BOLA/BFLA
boltclone https://example.com --import-session session.json \
  --secondary-auth "Bearer eyJhbGc..." \
  --html report.html

# Safe mutation inspection (dry-run without network dispatch)
boltclone https://example.com --import-session session.json --dry-run

# Explicit opt-in for state-altering verb mutation with custom rate limit
boltclone https://example.com --import-session session.json \
  --allow-mutating-methods \
  --rate-limit 10 \
  --csv findings.csv
```

## AI & Vulnerability Database Features

Perform automated CVE database lookups and generate AI threat synthesis:

```bash
# Enable live Vulnerability Database lookup (OSV.dev / NVD)
boltclone https://example.com --vulndb

# AI Threat Modeling via Gemini API
boltclone https://example.com --gemini-key AIzaSy... --html report.html

# Chrome Extension Session Import + Gemini AI + Vuln DB + Executive Report
boltclone https://example.com --import-session session.json --vulndb --gemini-key AIzaSy... --html report.html
```

## What it checks

- **access**: rate limiting, dual-context IDOR/BOLA, BFLA role escalation, CSRF, CORS misconfiguration, SSRF, missing security headers, TRACE/XST, host header injection, stale API versions
- **bopla**: excessive data exposure (sensitive PII, credential leakage in response bodies) and mass assignment parameter injection
- **injection**: SQLi, reflected XSS, open redirect, directory traversal, SSTI, XXE
- **tls**: certificate validity/expiry, weak protocol versions, weak ciphers
- **deps**: frontend library fingerprinting + live lookup against OSV.dev for known CVEs; server/tech header disclosure
- **cookies**: missing Secure, HttpOnly, and SameSite cookie attributes
- **graphql**: introspection abuse, query batching, and field suggestion enumeration
- **exposure**: sensitive files (.env, .git, dumps, metrics)
- **auth** (opt-in, `--auth-test`): detects login endpoints and tests a small default-credential list; flags accepted weak/default credentials

Exit code is `2` if any high-severity finding was reported, `1` on a scan
error, `0` otherwise — usable as a CI gate.

## Subdirectories & Boundaries
- [CLI Binary Executable](./bin/README.md): Command-line executable entry point, process argument parsing, and exit code handling.
- [CLI Core Engine](./src/README.md): Scanning orchestrator, HTTP networking, session ingestion, mutation engine, endpoint discovery, reports, spec generators, and vulnerability checks.

## Invariants
- Zero external runtime npm dependencies: standard Node.js 20+ runtime only.
- Safe-by-default execution: automated mutations restricted to idempotent verbs (`GET`, `HEAD`, `OPTIONS`) unless `--allow-mutating-methods` is passed.
- Target scope boundary: transactions replayed from imported sessions strictly enforce hostname matching to avoid cross-origin credential leakage.
- Synthetic traffic isolation: all replayed requests carry `X-Bolt-Test-Run` session UUID and `X-Synthetic-Test: true` headers.
- Exit code contract: `0` for clean scans, `1` for execution failures, `2` for high/critical security findings.
- Concurrency and timeouts strictly bounded per invocation.

## Side Effects
- Outbound network requests to target hosts, OSV.dev, crt.sh, and Google Gemini API.
- Filesystem writes for requested report artifacts (`--json`, `--csv`, `--html`, `--openapi`, `--postman`).

## Verification
- Run: `node cli/bin/boltclone.js --help`
- Run: `node cli/test/test-owasp-engine.js`
- Run: `node cli/test/test-new-scanners.js`
