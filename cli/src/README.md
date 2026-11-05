# CLI Core Engine

## Overview
The `cli/src` package contains the core orchestration, HTTP transport, session ingestion, mutation generation, endpoint discovery, reporting, specification generation, and AI threat modeling logic for the BOLTCLONE CLI. It coordinates scanner execution across discovery pipelines, imported session traffic, and modular checks.

## Interface
- `runScan({ target, concurrency, timeout, categories, credsFile, importSession, vulndb, geminiKey, onProgress, secondaryAuth, allowMutatingMethods, dryRun, rateLimit })`: Primary scanner entry point executing discovery, session normalizer, modular checks, CVE lookups, dual-context authorization testing, and reporting ([`scan.js:105`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/scan.js#L105)).
- `normalizeTarget(value)`: Normalizes user-supplied URL inputs to standard HTTPS/HTTP origins without trailing slashes ([`scan.js:18`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/scan.js#L18)).
- `parseCliArgs(argv)`: Parses command-line flags and options using `node:util.parseArgs` ([`args.js:56`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/args.js#L56)).
- `groupById(logEntries)`: Merges split `chrome.webRequest` lifecycle events sharing an ID ([`ingestion.js:58`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/ingestion.js#L58)).
- `decodeRequestBody(requestBody, contentType)`: Unpacks Chrome `{ raw: [{ text }] }` and `{ formData }` request body envelopes ([`ingestion.js:80`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/ingestion.js#L80)).
- `sanitizeHeaders(headersArray)`: Converts header arrays to lowercase key-value dictionaries, stripping noise/transport headers ([`ingestion.js:120`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/ingestion.js#L120)).
- `normalizeSession(rawSessionData, targetBaseUrl)`: Ingests raw session dumps, reconciles transactions, decodes bodies, filters off-scope hosts, and yields canonical `TransactionDTO[]` ([`ingestion.js:161`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/ingestion.js#L161)).
- `generateIdorMutations(tx, allowMutating)`: Generator yielding integer path segment (±1), UUID neighbour, and query param ID mutations ([`mutations.js:146`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/mutations.js#L146)).
- `generateBflaMutations(tx, secondaryAuthToken, allowMutating)`: Generator yielding unauthenticated and cross-tenant mutations on privileged endpoints ([`mutations.js:237`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/mutations.js#L237)).
- `generateParamMutations(tx, payloads, allowMutating)`: Injects fuzz vectors across query parameters and JSON object keys ([`mutations.js:316`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/mutations.js#L316)).
- `createRateLimiter(rps)`: Creates a token-bucket rate limiter enforcing maximum requests per second ([`http.js:46`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L46)).
- `setDefaultRateLimit(rps)`: Configures the global default dispatch rate limit ([`http.js:72`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L72)).
- `getSessionRunId()`: Retrieves the unique session execution UUID v4 used for APM telemetry isolation ([`http.js:237`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L237)).
- `pool(items, limit, worker)`: Bounded-concurrency promise pool runner ([`http.js:213`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L213)).
- `safeFetch(url, opts, timeoutMs)`: Non-throwing HTTP fetch wrapper with AbortController timeout, synthetic headers, and transparent decompression ([`http.js:196`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L196)).
- `timeoutFetch(url, opts, timeoutMs)`: Timeout-bounded native fetch injecting `X-Bolt-Test-Run` and `X-Synthetic-Test` ([`http.js:149`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/http.js#L149)).
- `discoverEndpoints(baseUrl, { concurrency, timeout })`: Crawls target HTML, scripts, and sitemaps to enumerate API routes ([`discovery.js:10`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/discovery.js#L10)).
- `enumerateSubdomains(hostname, { timeout })`: Queries crt.sh Certificate Transparency logs for target subdomains ([`discovery.js:57`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/discovery.js#L57)).
- `analyzeWithGemini(apiKey, findings, trafficMeta)`: Dispatches security findings to Gemini API for threat modeling and remediation guidance ([`gemini.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/gemini.js#L1)).
- `buildCliOpenApi(discoveredUrls, trafficLogs)`: Generates an OpenAPI 3.0 specification from discovered endpoints and traffic traces ([`openapi.js:46`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/openapi.js#L46)).
- `buildCliPostman(discoveredUrls, trafficLogs)`: Generates a Postman Collection v2.1 export ([`postman.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/postman.js#L1)).
- `buildCliHtmlReport(target, findings, meta)`: Renders a standalone executive HTML report with interactive OWASP Top 10, WSTG, and ASTF compliance filter cards ([`htmlReport.js:296`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/htmlReport.js#L296)).
- `printConsoleReport(findings, meta, color)`: Formats and outputs terminal summary reports displaying standards tags next to findings ([`report.js:33`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/report.js#L33)).
- `writeJsonReport(path, findings, meta)` / `writeCsvReport(path, findings)` / `writeHtmlReport(path, target, findings, meta)`: Serializes scan findings with standards taxonomy to disk ([`report.js:58-80`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/report.js#L58-L80)).
- `queryOsvDb(packageName, version, ecosystem)`: Queries OSV.dev for package vulnerabilities ([`vulndb.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/vulndb.js#L1)).
- `lookupSoftwareVulns(serverHeader)`: Parses server headers and identifies known vulnerabilities ([`vulndb.js:32`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/vulndb.js#L32)).
- [Checks Subsystem](./checks/README.md): Modular security checks and vulnerability detection runners.

## Invariants
- Built with zero external runtime dependencies using native Node.js 20+ capabilities (`node:util`, `node:fs/promises`, `node:crypto`, `node:tls`, `node:zlib`, native `fetch`).
- Safe-by-default execution: mutation generators (`generateIdorMutations`, `generateBflaMutations`, `generateParamMutations`, `checkMassAssignment`) skip state-altering verbs (`POST`, `PUT`, `PATCH`, `DELETE`) unless `allowMutating` is explicitly true.
- Scope boundary enforcement: replayed transactions are strictly filtered against the target hostname; off-scope domains are dropped.
- Synthetic traffic isolation: all requests sent via `timeoutFetch` include `X-Bolt-Test-Run` session UUID and `X-Synthetic-Test: true` for downstream APM filtering.
- Concurrency bounded: all multi-request pipelines must execute via `pool()` respecting caller concurrency settings.
- Rate limited: dispatch cadence governed by `createRateLimiter` (default 15 QPS).

## Side Effects
- Dispatches outbound HTTP/HTTPS requests to target hosts and third-party APIs (crt.sh, OSV.dev, Google Gemini API).
- Reads imported session JSON files and custom credential files from disk.
- Writes generated reports and specifications (`.json`, `.csv`, `.html`, OpenAPI, Postman) to local filesystem paths when specified.

## Verification
- Run: `node cli/test/test-owasp-engine.js`
- Run: `node cli/test/test-new-scanners.js`
