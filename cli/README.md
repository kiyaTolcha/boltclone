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
      --auth-test         Opt-in auth/brute-force checks (only against targets you own or are authorized to test)
      --creds <file>      JSON file of {username,password} pairs for --auth-test
      --subdomains        Opt-in subdomain enumeration via crt.sh
      --json <file>       Write full results as JSON
      --csv <file>        Write findings as CSV
      --no-color          Disable colored output
```

## What it checks

- **injection**: SQLi, reflected XSS, open redirect, directory traversal
- **access**: rate limiting, IDOR/BOLA, CSRF, CORS misconfiguration, SSRF, missing security headers
- **tls**: certificate validity/expiry, weak protocol versions, weak ciphers
- **deps**: frontend library fingerprinting + live lookup against OSV.dev for known CVEs; server/tech header disclosure
- **auth** (opt-in, `--auth-test`): detects login endpoints and tests a small default-credential list; flags accepted weak/default credentials

Exit code is `2` if any high-severity finding was reported, `1` on a scan
error, `0` otherwise — usable as a CI gate.

## Notes

- Endpoint discovery only tries common/guessable paths plus anything listed in
  `robots.txt`/`sitemap.xml` — it can't discover undocumented app-specific routes
  the way the companion Chrome extension can (which observes real browser traffic).
  The literal target URL you pass is always scanned regardless of what discovery finds.
- `--auth-test` and `--subdomains` are opt-in and off by default since they're
  more invasive (credential testing) or call a third-party service (crt.sh) with
  the target's domain.
