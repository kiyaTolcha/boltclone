# BOLTCLONE Blueprint

## System Overview
BOLTCLONE is an API security assessment, traffic analysis, and specification generation toolkit inspired by APIsec's BOLT technology. The system enables developers and security engineers to discover APIs in real time, analyze passive and active security postures, map attack surfaces, and export standardized OpenAPI 3.0 and Postman collections.

The architecture is partitioned into two cooperating subsystems:
1. **Chrome Extension (Manifest V3)**: Intercepts browser HTTP/HTTPS traffic passively, merges asynchronous webRequest events, identifies surface-level misconfigurations (BOLA path patterns, mass assignment, token leakage, missing security headers), and exports session dumps.
2. **CLI Scanner (`cli/`)**: A zero-dependency Node.js scanner that consumes target URLs or imported Chrome extension sessions, discovers hidden routes, executes active vulnerability checks (injection, access control, cookies, GraphQL, exposure, TLS, brute-force auth), queries live CVE databases via OSV.dev, and generates executive HTML reports with Gemini AI threat modeling.

```
       ┌────────────────────────────────────────────────────────┐
       │               Chrome Browser / Web Traffic             │
       └───────────────────────────┬────────────────────────────┘
                                   │ (chrome.webRequest)
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │       Chrome Extension Subsystem (chrome-extension/)   │
       │  - Service Worker (background.js)                      │
       │  - Rule Engine & BOLA Heuristics (rules.js)            │
       │  - Spec Exporters (openapi.js, postman.js)             │
       │  - UI: DevTools & Popup (panel.html, popup.js)         │
       └───────────────────────────┬────────────────────────────┘
                                   │ Session JSON Export
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                BOLTCLONE CLI Subsystem (cli/)          │
       │  - CLI Executable (bin/boltclone.js)                   │
       │  - Scanner & Discovery Engine (src/scan.js)            │
       │  - HTTP Transport Pool (src/http.js)                   │
       │  - Modular Checkers (src/checks/*)                     │
       │  - Vulnerability DB & AI Synthesis (vulndb.js, gemini) │
       └────────────────────────────────────────────────────────┘
```

## Subdirectories & System Boundaries
- [Chrome Extension Subsystem](./chrome-extension/README.md): Manifest V3 extension providing passive API traffic interception, local rule analysis, spec generation, and DevTools controls.
- [BOLTCLONE CLI](./cli/README.md): Zero-dependency Node.js command-line vulnerability scanner, endpoint crawler, and reporting engine.
  - [CLI Binary Executable](./cli/bin/README.md): Command-line argument parsing and exit code handling.
  - [CLI Core Engine](./cli/src/README.md): Scanner orchestrator, network pooling, OpenAPI/Postman builders, and discovery logic.
  - [Vulnerability Checks Subsystem](./cli/src/checks/README.md): Modular active security checks for injection, access, cookies, exposure, GraphQL, and TLS.

## Global Invariants
- Zero external runtime npm dependencies across the entire CLI subsystem (built exclusively on native Node.js 20+ standard library).
- Manifest V3 compliance across the browser extension (service worker lifecycle, no dynamic script evaluations).
- Non-destructive execution: active security scans default strictly to read-only/idempotent inspection probes.
- Quality gate contract: CLI exits with code `2` on high/critical findings, `1` on execution errors, and `0` when clean.

## Global Side Effects
- Browser network inspection via `chrome.webRequest` and state mutation in `chrome.storage.local`.
- Outbound active security probes dispatched against target APIs and hostnames.
- External API calls to OSV.dev (`https://api.osv.dev/v1/query`), crt.sh Certificate Transparency logs, and Google Gemini API.
- Filesystem writes when saving scan results, session exports, or OpenAPI/Postman specifications.

## System Verification
- Verify Chrome Extension: `node chrome-extension/test/test-chrome-extension.js`
- Verify CLI Suite: `node cli/test/test-new-scanners.js`
- Verify CLI Help Interface: `node cli/bin/boltclone.js --help`

