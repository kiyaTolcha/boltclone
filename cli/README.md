# BOLTCLONE CLI

Command-line vulnerability assessment tool for web apps and APIs. Zero external
dependencies — built entirely on Node's standard library (native `fetch`, `tls`,
`node:util.parseArgs`).

## Install

Already linked globally on this machine via `npm link` — open a new terminal and
run `boltclone` directly. To set up elsewhere:

```
cd cli
npm link
```

## Usage

```
boltclone <target-url> [options]

  -c, --concurrency <n>   Max concurrent requests (default: 8)
  -t, --timeout <ms>      Per-request timeout in ms (default: 8000)
      --skip <list>       Comma-separated categories to skip: injection,access,tls,deps
      --import-session <file> Path to JSON session exported from Chrome extension
      --openapi <file>    Write OpenAPI 3.0 specification JSON
      --postman <file>    Write Postman Collection v2.1 JSON
      --html <file>       Write self-contained executive HTML report
      --gemini-key <key>  Google Gemini API Key for AI threat modeling & fix synthesis (or set GEMINI_API_KEY env)
      --vulndb            Enable live Vulnerability Database lookup (OSV.dev / NVD) for detected software
      --auth-test         Opt-in auth/brute-force checks (only against targets you own or are authorized to test)
      --creds <file>      JSON file of {username,password} pairs for --auth-test
      --subdomains        Opt-in subdomain enumeration via crt.sh
      --json <file>       Write full results as JSON
      --csv <file>        Write findings as CSV
      --no-color          Disable colored output
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

- **injection**: SQLi, reflected XSS, open redirect, directory traversal
- **access**: rate limiting, IDOR/BOLA, CSRF, CORS misconfiguration, SSRF, missing security headers
- **tls**: certificate validity/expiry, weak protocol versions, weak ciphers
- **deps**: frontend library fingerprinting + live lookup against OSV.dev for known CVEs; server/tech header disclosure
- **auth** (opt-in, `--auth-test`): detects login endpoints and tests a small default-credential list; flags accepted weak/default credentials

Exit code is `2` if any high-severity finding was reported, `1` on a scan
error, `0` otherwise — usable as a CI gate.
