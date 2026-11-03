# CLI Core Engine

## Overview
The `cli/src` package contains the core orchestration, HTTP transport, endpoint discovery, reporting, specification generation, and AI threat modeling logic for the BOLTCLONE CLI. It coordinates scanner execution across discovery pipelines and modular checks.

## Interface
- `runScan({ target, concurrency, timeout, categories, credsFile, importSession, vulndb, geminiKey, onProgress })`: Primary scanner entry point executing discovery, modular checks, CVE lookups, and reporting ([`scan.js:20`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/scan.js#L20)).
- `normalizeTarget(value)`: Normalizes user-supplied URL inputs to standard HTTPS/HTTP origins without trailing slashes ([`scan.js:15`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/scan.js#L15)).
- `parseCliArgs(argv)`: Parses command-line flags and options using `node:util.parseArgs` ([`args.js:33`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/args.js#L33)).
- `discoverEndpoints(baseUrl, { concurrency, timeout })`: Crawls target HTML, scripts, and sitemaps to enumerate API routes ([`discovery.js:10`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/discovery.js#L10)).
- `enumerateSubdomains(hostname, { timeout })`: Queries crt.sh Certificate Transparency logs for target subdomains ([`discovery.js:57`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/discovery.js#L57)).
- `pool(items, limit, worker)`: Bounded-concurrency promise pool runner ([`http.js:17`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L17)).
- `safeFetch(url, opts, timeoutMs)`: Non-throwing HTTP fetch wrapper with AbortController timeout ([`http.js:8`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L8)).
- `timeoutFetch(url, opts, timeoutMs)`: Timeout-bounded native fetch ([`http.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L1)).
- `analyzeWithGemini(apiKey, findings, trafficMeta)`: Dispatches security findings to Gemini API for threat modeling and remediation guidance ([`gemini.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/gemini.js#L1)).
- `buildCliOpenApi(discoveredUrls, trafficLogs)`: Generates an OpenAPI 3.0 specification from discovered endpoints and traffic traces ([`openapi.js:46`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/openapi.js#L46)).
- `buildCliPostman(discoveredUrls, trafficLogs)`: Generates a Postman Collection v2.1 export ([`postman.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/postman.js#L1)).
- `buildCliHtmlReport(target, findings, meta)`: Renders a standalone executive HTML report ([`htmlReport.js:230`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/htmlReport.js#L230)).
- `printConsoleReport(findings, meta, color)`: Formats and outputs terminal summary reports ([`report.js:17`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/report.js#L17)).
- `writeJsonReport(path, findings, meta)` / `writeCsvReport(path, findings)` / `writeHtmlReport(path, target, findings, meta)`: Serializes scan findings to disk ([`report.js:42-60`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/report.js#L42-L60)).
- `queryOsvDb(packageName, version, ecosystem)`: Queries OSV.dev for package vulnerabilities ([`vulndb.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/vulndb.js#L1)).
- `lookupSoftwareVulns(serverHeader)`: Parses server headers and identifies known vulnerabilities ([`vulndb.js:32`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/vulndb.js#L32)).
- [Checks Subsystem](./checks/README.md): Modular security checks and vulnerability detection runners.

## Invariants
- Built with zero external runtime dependencies using native Node.js 20+ capabilities (`node:util`, `node:fs/promises`, `node:crypto`, `node:tls`, native `fetch`).
- Concurrency bounded: all multi-request pipelines must execute via `pool()` respecting caller concurrency settings.
- Non-throwing HTTP fetch: `safeFetch` catches all network aborts and errors, returning `null` to callers.

## Side Effects
- Dispatches outbound HTTP/HTTPS requests to target hosts and third-party APIs (crt.sh, OSV.dev, Google Gemini API).
- Reads imported session JSON files and custom credential files from disk.
- Writes generated reports and specifications (`.json`, `.csv`, `.html`, OpenAPI, Postman) to local filesystem paths when specified.

## Verification
- Run: `node cli/test/test-new-scanners.js`

