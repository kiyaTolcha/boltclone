# Vulnerability Checks Subsystem

## Overview
The `cli/src/checks` package implements the active vulnerability analysis engine for the BOLTCLONE CLI. It contains modular security check runners covering injection vulnerabilities, access control flaws, authentication weaknesses, insecure cookie attributes, sensitive endpoint exposure, GraphQL misconfigurations, dependency CVEs via OSV.dev, and TLS/cipher weaknesses.

## Interface
- `runAccessChecks(url, timeout)`: Evaluates access control and header policies across 9 distinct checks ([`access.js:151`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L151)).
- `checkRateLimit(url, timeout)`: Tests for request rate limiting via rapid burst requests ([`access.js:3`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L3)).
- `checkIdorBola(url, timeout)`: Probes adjacent numeric object IDs in path segments for authorization leakage ([`access.js:15`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L15)).
- `checkCsrf(url, timeout)`: Checks CORS preflight allowances for state-changing methods ([`access.js:38`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L38)).
- `checkCors(url, timeout)`: Detects wildcard origins with credentials and reflected arbitrary origins ([`access.js:47`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L47)).
- `checkSsrf(url, timeout)`: Probes internal loopback query parameter reflection ([`access.js:61`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L61)).
- `checkSecurityHeaders(url, timeout)`: Identifies missing HSTS, CSP, and X-Content-Type-Options headers ([`access.js:76`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L76)).
- `checkTraceMethod(url, timeout)`: Checks if the HTTP TRACE method is enabled ([`access.js:93`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L93)).
- `checkHostHeaderInjection(url, timeout)`: Tests host header reflection ([`access.js:109`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L109)).
- `checkApiVersioning(url, timeout)`: Checks accessibility of deprecated API versions (`/v0`, `/v1`) ([`access.js:127`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/access.js#L127)).
- `runAuthChecks(baseUrl, discovered, timeout, credsFile)`: Opt-in credential brute-force testing against identified login routes ([`auth.js:67`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/auth.js#L67)).
- `loadCreds(credsFile)`: Reads and parses custom credential pair JSON files ([`auth.js:19`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/auth.js#L19)).
- `runCookieChecks(url, timeout)`: Audits `Set-Cookie` headers for missing `Secure`, `HttpOnly`, and `SameSite` flags ([`cookies.js:68`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/cookies.js#L68)).
- `runDependencyChecks(baseUrl, timeout)`: Fingerprints server technologies and frontend libraries against OSV.dev ([`deps.js:97`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/deps.js#L97)).
- `runExposureChecks(baseUrl, timeout)`: Probes for exposed `.env`, `.git/HEAD`, Prometheus metrics, and server dumps ([`exposure.js:50`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/exposure.js#L50)).
- `runGraphqlChecks(baseUrl, timeout)`: Detects GraphQL endpoints and probes introspection, batching, and field suggestions ([`graphql.js:103`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/graphql.js#L103)).
- `runInjectionChecks(url, timeout)`: Orchestrates SQLi, XSS, open redirect, directory traversal, SSTI, and XXE checks ([`injection.js:96`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/injection.js#L96)).
- `runTlsChecks(hostname, timeout)`: Validates TLS certificate expiration, deprecated protocols, and weak cipher suites ([`tls.js:23`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/tls.js#L23)).

## Invariants
- `check*` functions return an array of finding objects matching `{ category: string, title: string, severity: 'critical'|'high'|'medium'|'low'|'info', url: string, evidence: string }` or `null` if no finding is detected.
- Functions must be exception-safe: network errors, aborts, and timeout rejections are caught and handled without throwing to the caller.
- All checks adhere to the per-request timeout limit passed by the caller.

## Side Effects
- Dispatches outbound HTTP/HTTPS network requests against the specified target URLs using `safeFetch`/`timeoutFetch`.
- Connects directly to target hosts on port 443 via `node:tls` in `runTlsChecks`.
- `runDependencyChecks` makes external outbound network calls to `https://api.osv.dev/v1/query`.

## Verification
- Run: `node cli/test/test-new-scanners.js`

