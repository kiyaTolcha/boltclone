# Design Document: Unified OWASP Testing Engine (Web Top 10, API Top 10, WSTG & ASTF)

* **Author:** kiyaTolcha
* **Date:** 2026-11-03
* **Status:** Implemented & Verified (Phases 1–4 Complete)

---

## 1. Problem Statement & Overview

### 1.1 The Problem
Security engineers, developers, and QA teams evaluating modern web applications and API architectures must navigate four foundational, intersecting security standards:
1. **OWASP Top 10 Web Application Security Risks (2021)**: Broad application-level security risk categories.
2. **OWASP API Security Top 10 (2023)**: Dedicated API business logic, object-level access (Broken Object Level Authorization / BOLA), Broken Function Level Authorization (BFLA), Broken Object Property Level Authorization (BOPLA), and resource consumption risks.
3. **OWASP Web Security Testing Guide (WSTG v4.2)**: Comprehensive, procedural testing methodologies for web applications (Information Gathering, Configuration, Identity, Authentication, Authorization, Session Management, Input Validation, Error Handling, Cryptography, Business Logic, and Client-Side testing).
4. **OWASP API Security Testing Framework (ASTF)**: Systematic methodology specifically targeting API reconnaissance, authentication mechanics, property-level validation, rate limiting, and shadow/zombie API identification.

Currently, tooling across these four standards is highly fragmented:
* **Authentication and State Blindness**: Traditional crawlers and fuzzers test unauthenticated public routes, failing to reach authenticated workflows where WSTG authorization (WSTG-ATHZ) and ASTF object-level tests (ASTF-ATHZ / Insecure Direct Object Reference [IDOR] / BOLA) reside. BOLTCLONE's Chrome extension captures authenticated browser sessions, but the CLI previously stripped all headers, cookies, tokens, and payloads, preventing authenticated procedural testing.
* **Lack of Procedural Test Rigor**: Without alignment to WSTG and ASTF methodologies, vulnerability scans rely on ad-hoc URL checks rather than systematic procedural verification (e.g., comparing baseline vs cross-tenant responses, testing parameter boundaries, auditing cookie security flags, or verifying cryptographic ciphers).
* **Toolchain Sprawl**: Teams operate multiple separate tools (Burp Suite Pro, OWASP ZAP, Postman, custom scripts) across standards, hindering automated integration into CI/CD pipelines.
* **Destructive Testing Risks**: Automated fuzzers that mutate state-altering verbs (`POST`, `PUT`, `DELETE`) without semantic context risk corrupting live or staging databases, deleting records, or locking test accounts without guardrails.

### 1.2 Overview
This design establishes an end-to-end, zero-dependency testing architecture in BOLTCLONE that directly operationalizes:
- **OWASP Top 10 Web (2021)** (A01–A10)
- **OWASP API Security Top 10 (2023)** (API1–API10)
- **OWASP Web Security Testing Guide (WSTG)** procedural test workflows
- **OWASP API Security Testing Framework (ASTF)** systematic API verification

The unified architecture provides:
1. **Stateful Ingestion & Normalization**: Porting transaction merging (`groupById`) to the CLI to recombine split browser `webRequest` events, decode body envelopes (`raw.text`, `formData`), sanitize transport headers, and enforce strict target host scope.
2. **Dual-Context Authorization Matrix**: Providing `--secondary-auth <token|cookie>` to execute comparative cross-tenant tests, systematically evaluating WSTG-ATHZ-02 (IDOR) and ASTF-ATHZ-01 (BOLA) while significantly minimizing false positives compared to single-token checks.
3. **Procedural Multi-Standard Check Suite**: Coordinating passive in-browser analysis (`chrome-extension/rules.js`) with active CLI modules (`cli/src/checks/*` and `cli/src/mutations.js`), annotating every finding with its exact OWASP Top 10, WSTG, and ASTF identifiers.
4. **Safe-by-Default Execution**: Restricting automated mutation sweeps to read-only/idempotent methods (`GET`, `HEAD`, `OPTIONS`) by default, requiring explicit opt-in (`--allow-mutating-methods`) for state-altering verbs.
5. **Zero External Runtime Dependencies**: Standard Node.js 20+ runtime only (`node:util`, `node:crypto`, `node:tls`, `node:fs`, native `fetch`).

### 1.3 Goals & Non-Goals

#### Goals
* **G-1 (Four-Standard Security Alignment)**: Implement active and passive detection mechanisms mapped across:
  - OWASP Web Top 10 (2021) Categories A01–A10
  - OWASP API Security Top 10 (2023) Categories API1–API10
  - OWASP WSTG Categories (INFO, CONF, IDNT, ATHN, ATHZ, SESS, INPV, ERRH, CRYP, BUSL, CLNT)
  - OWASP ASTF Workflows (DISC, AUTH, ATHZ, INPT, BUSL, CONF)
* **G-2 (Dual-Context Authorization Engine)**: Support comparative multi-tenant evaluation (`--secondary-auth`) to verify resource isolation across Owner, Foreign User, and Unauthenticated contexts (WSTG-ATHZ-02, ASTF-ATHZ-01).
* **G-3 (Canonical Session Ingestion)**: Ingest heterogeneous Chrome extension export formats, merge split request lifecycle events, and unpack JSON and form payloads into mutable structures.
* **G-4 (Target Scope Boundary Enforcement)**: Enforce strict hostname scope matching on all replayed traffic to prevent cross-origin credential exfiltration.
* **G-5 (Safe-by-Default Replay)**: Restrict automated parameter mutation to idempotent HTTP methods by default; gate write-verb mutations behind `--allow-mutating-methods`.
* **G-6 (Unified Compliance Reporting)**: Generate console summaries, JSON deliverables, and executive HTML reports where each vulnerability is mapped to its corresponding Top 10, WSTG, and ASTF taxonomy tags.
* **G-7 (Synthetic Traffic Classification)**: Inject standard distributed tracing headers (`X-Bolt-Test-Run`, `X-Synthetic-Test: true`) so backend APMs isolate scanner traffic from production metrics.
* **G-8 (Zero Runtime Dependencies)**: Keep the entire CLI scanner built strictly on Node.js built-in modules.

#### Non-Goals
* **NG-1 (Automated Destructive Write Fuzzing by Default)**: No automated deletion or modification of backend state without explicit operator consent.
* **NG-2 (Headless Browser Driver Integration)**: Will not embed Chromium or Puppeteer into the CLI; web browsing traffic capture remains the domain of the Chrome extension.
* **NG-3 (Complex Binary Protocol Fuzzing)**: Arbitrary binary and proprietary protocol fuzzing is out of scope and remains delegated to dedicated DAST platforms via `--openapi` and `--postman` exports.

---

## 2. Technical Plan

### 2.1 Architectural Overview & Data Flow
The upgraded architecture bridges captured browser interactions into an automated multi-standard security scanner.

```mermaid
flowchart TD
    subgraph Browser ["Chrome Extension (Manifest V3)"]
        WR["chrome.webRequest Stream"] --> BG["background.js (Split Events)"]
        BG --> EXP["Session Export (JSON)"]
        BG --> PE["Passive Rules Engine (rules.js)"]
    end

    subgraph CLI ["BOLTCLONE CLI Engine"]
        EXP --> ING["Session Ingestion Normalizer (ingestion.js)"]
        ING --> GID["groupById() Event Merging"]
        GID --> DEC["Body Envelope Decoder & Header Sanitizer"]
        DEC --> SCOPE["Scope Boundary Filter (Hostname Match)"]
        SCOPE --> DTO["Canonical TransactionDTO"]

        DTO --> MUT["Mutation Generator Pool (mutations.js)"]
        DTO --> ORACLES["Modular Check Oracles (cli/src/checks/*)"]
        MUT -.->|"Candidate Probe Descriptors"| ORACLES
        
        subgraph Oracles ["Four-Standard Check Oracles"]
            access["access.js (BOLA, BFLA, CORS, SSRF)"]
            bopla["bopla.js (Mass Assign, Prop-Level Auth)"]
            inject["injection.js (SQLi, XSS, Path Traversal)"]
            auth["auth.js (Broken Auth, Brute Force)"]
            cookies["cookies.js (Cookie Security Flags)"]
            graphql["graphql.js (Introspection, Batching)"]
            exposure["exposure.js (Sensitive Files, Dumps)"]
            deps["deps.js & vulndb.js (OSV.dev CVEs)"]
            tls["tls.js (Ciphers, Certificates)"]
        end

        ORACLES --> HTTP["HTTP Client Pool (http.js)"]
        HTTP -->|"Evaluated Responses"| ORACLES
        ORACLES --> SCAN["Scanner Orchestrator (scan.js)"]
        SCAN --> REP["Taxonomy & Multi-Standard Reporter (report.js)"]
        REP --> OUT1["Console Table with WSTG/ASTF Tags"]
        REP --> OUT2["JSON Scan Deliverable (findings.json)"]
        REP --> OUT3["Executive HTML Report (report.html)"]
    end

    HTTP -->|"Rate-Limited Dispatch (RPS Ceiling)"| TARGET["Target API Backend"]
    TARGET -->|"HTTP Responses"| HTTP
```

### 2.2 Four-Standard Procedural Mapping Matrix
The scanner organizes all detection modules across OWASP Web 2021, OWASP API 2023, WSTG v4.2, and ASTF:

| Category / Area | OWASP Web (2021) | OWASP API (2023) | WSTG v4.2 Identifier | ASTF Workflow | Check Implementation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Object Authorization** | A01: Broken Access | API1: BOLA | `WSTG-ATHZ-02` | `ASTF-ATHZ-01` | `checks/access.js` & `mutations.js` |
| **Function Authorization** | A01: Broken Access | API5: BFLA | `WSTG-ATHZ-03` | `ASTF-ATHZ-02` | `checks/access.js` (Role swapping) |
| **Property Authorization** | A01: Broken Access | API3: BOPLA | `WSTG-BUSL-07` | `ASTF-ATHZ-03` | `checks/bopla.js` (Mass assignment & PII) |
| **Authentication Testing** | A07: Identification | API2: Broken Auth | `WSTG-ATHN-01..08` | `ASTF-AUTH-01..04` | `checks/auth.js` (Default creds & token validation) |
| **Session Management** | A07: Identification | API2: Broken Auth | `WSTG-SESS-01..09` | `ASTF-AUTH-05` | `checks/cookies.js` (`Secure`, `HttpOnly`, `SameSite`) |
| **Resource Consumption** | A04: Insecure Design | API4: Resource Abuse | `WSTG-BUSL-05` | `ASTF-BUSL-01` | `checks/access.js` (Rate limit) & `checks/graphql.js` |
| **Injection (SQL, XSS, etc)**| A03: Injection | API8: Misconfig | `WSTG-INPV-01..19` | `ASTF-INPT-01..05` | `checks/injection.js` (SQLi, XSS, Traversal, SSTI, XXE) |
| **SSRF** | A10: SSRF | API7: SSRF | `WSTG-INPV-19` | `ASTF-INPT-06` | `checks/access.js` (Metadata/Loopback reflection) |
| **Security Misconfiguration**| A05: Misconfiguration | API8: Misconfig | `WSTG-CONF-01..11` | `ASTF-CONF-01..03` | `checks/access.js` (CORS, HSTS, CSP, Host Header) |
| **Cryptographic Failures** | A02: Crypto Failures | API8: Misconfig | `WSTG-CRYP-01..04` | `ASTF-CONF-04` | `checks/tls.js` (Certs, protocols, weak ciphers) |
| **Vulnerable Dependencies** | A06: Outdated Comps | API8: Misconfig | `WSTG-CONF-05` | `ASTF-CONF-05` | `checks/deps.js` & `vulndb.js` (OSV.dev query) |
| **Information Disclosure** | A05: Misconfiguration | API8: Misconfig | `WSTG-INFO-01..10` | `ASTF-DISC-01..04` | `checks/exposure.js` & `discovery.js` |
| **Inventory / Stale APIs** | A05: Misconfiguration | API9: Inventory Mgmt | `WSTG-CONF-06` | `ASTF-DISC-05` | `checks/access.js` (Legacy API routes) & `openapi.js` |

### 2.3 Subsystem Breakdown & Module Design

#### 2.3.1 Ingestion & Event Normalizer (`cli/src/ingestion.js`)
* **Transaction Contract (`TransactionDTO`)**:
  ```typescript
  interface TransactionDTO {
    id: string;                              // Shared webRequest ID across split events
    url: string;                             // Canonical target URL
    method: string;                          // Normalized uppercase HTTP verb (GET, POST, etc.)
    headers: Record<string, string>;         // Lowercased, sanitized request headers
    body: object | string | null;            // Decoded payload (parsed JSON, form map, or raw string)
    bodyFormat: 'json' | 'form' | 'raw' | 'empty'; // Payload serialization format
    statusCode: number | null;               // Recorded HTTP response status
    responseHeaders: Record<string, string>; // Lowercased response headers
    responseBody: any | null;                // Response payload if captured or fetched
    isEnriched: boolean;                     // True if headers/payloads captured; false for URL-only
  }
  ```
* **Event Merging**: Recombines split `chrome.webRequest` events (`onBeforeRequest`, `onSendHeaders`, `onHeadersReceived`) sharing a common `id` into unified `TransactionDTO` records.
* **Header Sanitization**: Converts array-based headers (`[ { name, value } ]`) into a lower-cased dictionary. Strips browser transport pseudo-headers (`sec-ch-ua*`, `host`, `content-length`, `connection`, `upgrade-insecure-requests`).
* **Body Envelope Unpacking**: Automatically extracts payload data from Chrome extension wrappers:
  - Form data: `{ formData: { key: ["val"] } }` -> Normalized key-value map.
  - Raw JSON: `{ raw: [ { text: "..." } ] }` -> Decoded JSON object with syntax validation.
* **Scope Boundary Enforcement**: Filters all transactions to ensure `new URL(tx.url).hostname === new URL(baseUrl).hostname` (with wildcard subdomain support when specified). Drops off-target requests to prevent credential exfiltration.

#### 2.3.2 Mutation & Tampering Engine (`cli/src/mutations.js`)
* **Decoupled Architecture**: Isolated from transport (`http.js`) and assertions (`access.js`), functioning as candidate mutation generators:
  - `generateIdorMutations(tx)`: Detects numeric IDs, UUIDs, and slug paths, yielding candidate adjacent ID probes.
  - `generateBflaMutations(tx, secondaryToken)`: Tests role boundary escalation by swapping User A auth tokens with User B tokens, or stripping authorization entirely.
  - `generateParamMutations(tx, payloads)`: Injects fuzz vectors across query parameters and JSON body keys without corrupting overall JSON syntax.
* **Safety Invariant**: Filters candidate generation by HTTP method: `GET`, `HEAD`, and `OPTIONS` execute in safe mode. Non-idempotent methods (`POST`, `PUT`, `PATCH`, `DELETE`) are skipped unless `--allow-mutating-methods` is enabled.

#### 2.3.3 Dual-Context Authorization Oracle (`cli/src/checks/access.js`)
* **Differential Access Matrix**:
  1. **Baseline Request**: Executes request with Owner credentials (`User A`). Expected: HTTP 200 with resource body.
  2. **Tampered Unauth Request**: Executes tampered request with no credentials. Expected: HTTP 401 or 403. If 200 returned on non-public route, flags potential unauthenticated access.
  3. **Tampered Cross-Tenant Request**: Executes tampered request with `--secondary-auth` (`User B` Bearer token or Cookie string). Expected: HTTP 403 or 404.
* **Finding Classification**: If Probe 2 confirmed the route requires authentication (HTTP 401/403) and Probe 3 returns HTTP 200 with matching schema structure (>= 50% key overlap), flags a high-confidence **BOLA (OWASP API1 / WSTG-ATHZ-02 / ASTF-ATHZ-01)** finding.

#### 2.3.4 Transport & Synthetic Telemetry (`cli/src/http.js`)
* **Token-Bucket Rate Limiter**: Configurable dispatch ceiling (default: 15 RPS, minimum: 1 via `--rate-limit <rps>`, max sockets: 8) to protect target infrastructure and avoid WAF bans.
* **Synthetic Traffic Tagging**: Outgoing test probes carry headers:
  - `X-Bolt-Test-Run: <UUID>`
  - `X-Synthetic-Test: true`
  - `X-Bolt-Standard: <WSTG|ASTF|OWASP-API|OWASP-WEB>`
  - `User-Agent: BOLTCLONE-SecurityScanner/<version>`
* **Response Decompression**: Handles transparent stream and buffer decompression before passing response bodies to assertion oracles.
* **Redirect Isolation**: Sets `redirect: 'manual'` to prevent automated transmission of authorization headers across cross-host 3xx redirects.

#### 2.3.5 Multi-Standard Compliance Reporting (`cli/src/report.js` & `htmlReport.js`)
* **Finding Data Structure**:
  ```typescript
  interface FindingDTO {
    category: string;
    title: string;
    severity: 'high' | 'medium' | 'low' | 'info';
    url: string;
    evidence: string;
    standards: {
      owaspWeb?: string;   // e.g. "A01:2021-Broken Access Control"
      owaspApi?: string;   // e.g. "API1:2023-BOLA"
      wstg?: string | null;// e.g. "WSTG-ATHZ-02"
      astf?: string | null;// e.g. "ASTF-ATHZ-01"
    };
  }
  ```
* **Output Deliverables**: Console table grouped by standard, structured JSON export (`--json`), CSV export (`--csv`), and standalone interactive HTML report (`--html`) featuring severity filters and compliance checklists. Sensitive credentials and PII in `evidence` are redacted before output.

---

## 3. Risks, Limitations & Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **WAF / Rate-Limiting Trip** | Automated scanner traffic triggers 429/403 blocks or IP bans. | Built-in token-bucket rate limiter (`createRateLimiter`, default: 15 RPS, configurable via `--rate-limit <rps>`). |
| **Large Session Files (Heap Usage)** | Large Chrome extension session dumps (100MB+) consume Node heap. | Strict target hostname scope matching filters off-origin entries early during ingestion; payload unpacking discards binary media types. File size ceilings can be enforced via `fs.statSync`. |
| **Secondary Token Expiration Mid-Scan** | Expired User B token causes dual-context BOLA/BFLA oracles to misclassify legitimate 401s as passes. | Scanner runs pre-flight baseline connectivity and authentication probes for both primary captured tokens and `--secondary-auth` before initiating active oracles; warns operator on 401/403. |
| **Target State Pollution / Data Corruption** | Mutating requests (`POST`, `PUT`, `DELETE`) alter live databases. | Safe-by-default execution invariant: parameter mutations are restricted to idempotent verbs (`GET`, `HEAD`, `OPTIONS`). Mutating verbs require explicit `--allow-mutating-methods` opt-in and support `--dry-run` inspection. |
| **Cross-Domain Credential Exfiltration** | Follow-redirect behavior forwards Authorization headers to off-target hosts. | Strict hostname scope filtering in `ingestion.js` drops foreign URLs; `timeoutFetch` sets `redirect: 'manual'` to prevent forwarding sensitive credentials across 3xx redirects. |
| **PII / Secret Exposure in Deliverables** | Sensitive data (passwords, tokens, SSNs) printed to scan reports. | Reporter performs mandatory masking in `FindingDTO.evidence` (redacting auth headers, truncating keys, masking SSNs). |

---

## 4. Alternatives Considered

* **Monolithic Check Overload (Embedding Mutation in `access.js` & `http.js`)**:
  * *Description*: Directly adding JSON body parsing, path AST traversal, and parameter mutation loops into existing `cli/src/checks/access.js` and `cli/src/http.js` modules.
  * *Decision & Trade-offs*: Violates the Single Responsibility Principle. Coupling network transport with testing state machines alters established `(url, timeout, [opts])` function signatures and complicates heuristic maintenance.
* **Single-Session ID Incrementation (`ID + 1`) for BOLA**:
  * *Description*: Retaining the legacy approach of testing IDOR by naively incrementing numeric path segments under a single user token.
  * *Decision & Trade-offs*: Insufficient for authenticated OWASP API1 / WSTG-ATHZ-02 verification because it cannot differentiate between public endpoints, data owned by the same user, and actual unauthorized cross-tenant leaks. Retained as an unauthenticated fallback heuristic on plain URLs, but deprecated for authenticated authorization testing where dual-context verification is required.
* **External DAST / Fuzzing Dependencies (Axios, Lodash, Schemathesis)**:
  * *Description*: Importing third-party npm packages to handle HTTP requests, deep cloning, and OpenAPI fuzzing.
  * *Decision & Trade-offs*: Violates BOLTCLONE's core architectural principle of zero external runtime dependencies. Node.js 20+ standard library (`fetch`, `crypto`, `util`, `tls`, `fs`) provides all required primitives with lower supply-chain attack surface and minimal startup overhead.
* **Confining Active Testing Strictly to Browser UI (Manipulator Wizard)**:
  * *Description*: Relying exclusively on the Chrome extension's interactive DevTools panel for all active mutation and IDOR tests.
  * *Decision & Trade-offs*: Prevents headless automation, scheduled security testing, and integration into CI/CD regression pipelines.
* **Bundling Chromium / Puppeteer in the CLI Scanner**:
  * *Description*: Embedding headless browser drivers in the CLI to crawl authenticated Single-Page Applications (SPAs) directly.
  * *Decision & Trade-offs*: Adds over 300MB of binary dependencies, creates platform-specific installation friction, and duplicates the Chrome extension's native role as the browser traffic collector.

---

## 5. Detailed Implementation Plan

The implementation is partitioned into four incremental, independently verifiable phases. Each phase maintains a buildable and testable codebase state.

```
Phase 1: Ingestion Normalizer & Transport Hardening
    │
    ▼
Phase 2: Mutation Engine & Dual-Context Authorization Oracle
    │
    ▼
Phase 3: BOPLA Mass Assignment & Multi-Standard Check Expansion
    │
    ▼
Phase 4: Multi-Standard Taxonomy Reporting & Test Harness
```

### 5.1 Target File Boundary & Scope

| Action | Repository-Relative Path | Rationale |
| :--- | :--- | :--- |
| **Create** | `cli/src/ingestion.js` | Merges split `chrome.webRequest` events, decodes body envelopes, sanitizes transport headers, and enforces target host boundaries. |
| **Create** | `cli/src/mutations.js` | Implements generator pipeline for IDOR, BFLA, and parameter fuzzing candidate mutations. |
| **Create** | `cli/src/checks/bopla.js` | Evaluates property-level authorization and mass assignment vulnerabilities (API3 / WSTG-BUSL-07 / ASTF-ATHZ-03). |
| **Modify** | `cli/bin/boltclone.js` | Forwards `--secondary-auth`, `--allow-mutating-methods`, `--dry-run`, and `--rate-limit` from CLI arguments into `runScan()`. |
| **Modify** | `cli/src/args.js` | Adds `--secondary-auth`, `--allow-mutating-methods`, `--dry-run`, and `--rate-limit` CLI arguments with help documentation. |
| **Modify** | `cli/src/http.js` | Implements token-bucket rate limiting (default 15 RPS via `createRateLimiter` and `setDefaultRateLimit`), synthetic telemetry headers (`X-Bolt-Test-Run`), and manual redirect isolation. |
| **Modify** | `cli/src/checks/access.js` | Integrates dual-context BOLA verification with `--secondary-auth`, adds BFLA role tampering check, and supports polymorphic transaction descriptors. |
| **Modify** | `cli/src/scan.js` | Connects `ingestion.js` and `mutations.js`, executes pre-flight auth and secondary auth validation, orchestrates check pools, and implements `--dry-run` mutation preview. |
| **Modify** | `cli/src/report.js` | Updates console, JSON, and CSV reports to display and filter findings by OWASP Web 2021, OWASP API 2023, WSTG, and ASTF identifiers with sensitive evidence masking. |
| **Modify** | `cli/src/htmlReport.js` | Enhances executive HTML report with dedicated OWASP Top 10, WSTG, and ASTF compliance filter cards. |
| **Create** | `cli/test/test-owasp-engine.js` | Automated verification test suite covering session ingestion, dual-context BOLA detection, BOPLA checks, rate limiting, and scope filtering. |
| **Modify** | `cli/README.md` | Documents new flags, multi-standard testing workflows, and dual-context usage examples. |
| **Modify** | `cli/src/README.md` | Updates package contract to reflect `ingestion.js`, `mutations.js`, and `bopla.js`. |
| **Modify** | `cli/src/checks/README.md` | Updates check subsystem contract to document `bopla.js` and dual-context signatures. |

---

### 5.2 Phase 1: Ingestion Normalizer & Transport Hardening

#### Step 1.1: Create Session Ingestion Normalizer (`cli/src/ingestion.js`)
* **Functions to Implement**:
  - `groupById(logEntries)`: Ingests an array of raw Chrome webRequest event logs. Groups entries by `entry.id`, merging properties across `onBeforeRequest` (URL, method, requestBody), `onSendHeaders` (requestHeaders), and `onHeadersReceived` (statusCode, responseHeaders).
  - `decodeRequestBody(requestBody, contentType)`: Unpacks `{ raw: [{ text }] }` stringified JSON into JavaScript objects; decodes `{ formData: { key: [val] } }` into standard maps; returns `{ decoded: object|string|null, format: 'json'|'form'|'raw'|'empty' }`.
  - `sanitizeHeaders(headersArray)`: Converts `[{ name, value }]` to a lower-cased `Record<string, string>`. Drops `host`, `content-length`, `connection`, `transfer-encoding`, `upgrade-insecure-requests`, and `sec-ch-ua*`.
  - `normalizeSession(rawSessionData, targetBaseUrl)`: Sniffs root envelope (`boltcloneTraffic`, `analysis`, or raw Array). Runs `groupById`, filters transactions by `new URL(tx.url).hostname === new URL(targetBaseUrl).hostname`, decodes bodies, sanitizes headers, and returns canonical `TransactionDTO[]`.
* **Zero-Decision Enforcement**: If an imported file contains only `analysis` objects without headers/body, `normalizeSession` extracts only URLs and returns transactions with `isEnriched: false`.

#### Step 1.2: Harden HTTP Transport & Rate Limiting (`cli/src/http.js`)
* **Functions to Implement / Modify**:
  - `createRateLimiter(rps = 15)`: Implements a token-bucket algorithm ensuring dispatch rates do not exceed `rps` requests per second.
  - `setDefaultRateLimit(rps)`: Configures global rate limiter ceiling for the scanner.
  - Update `timeoutFetch(url, opts, timeoutMs)`:
    - Sets `redirect: 'manual'` to prevent automated transmission of credentials across off-target 3xx redirects.
    - Injects synthetic identification headers on every request:
      - `X-Bolt-Test-Run`: Active session UUID generated via `node:crypto.randomUUID()`.
      - `X-Synthetic-Test: true`
      - `X-Bolt-Standard`: Standard identifier tag passed in `opts`.
      - `User-Agent: BOLTCLONE-SecurityScanner/1.0.0`
    - Supports transparent decompression: if `content-encoding` is `gzip` or `br`, decompresses body bytes via `zlib.gunzipSync()` or `zlib.brotliDecompressSync()`, or lets native `fetch` decompress automatically.
* **Verification Checkpoint**: Run `node cli/bin/boltclone.js --help` to confirm valid compilation and argument flags.

---

### 5.3 Phase 2: Mutation Engine & Dual-Context Authorization Oracle

#### Step 2.1: Create Mutation & Tampering Engine (`cli/src/mutations.js`)
* **Functions to Implement**:
  - `*generateIdorMutations(tx, allowMutating = false)`: Analyzes `tx.url`. If method is not `GET`/`HEAD`/`OPTIONS` and `allowMutating` is false, returns immediately. Detects integer path segments (tests `ID + 1`, `ID - 1`), UUID v4 segments (tests swapped byte / adjacent UUID), and query parameter IDs (`?id=`, `?user_id=`). Yields candidate mutation objects `{ tx, mutatedUrl, mutatedBody, mutatedHeaders, mutationType: 'IDOR' }`.
  - `*generateBflaMutations(tx, secondaryAuthToken, allowMutating = false)`: Targets privileged administrative paths (`/admin`, `/manage`, `/superuser`, etc.), yielding two mutations:
    1. Unauthenticated mutation: strips `Authorization` and cookie headers.
    2. Cross-tenant mutation: replaces `Authorization` with `secondaryAuthToken`.
  - `*generateParamMutations(tx, payloads, allowMutating = false)`: Injects fuzz vectors across query strings and JSON object keys without corrupting overall JSON syntax.

#### Step 2.2: Implement Dual-Context Oracle in `cli/src/checks/access.js`
* **Functions to Modify**:
  - Update `checkIdorBola(target, timeout, options = {})`:
    - Handles polymorphic `target`: string URL or `TransactionDTO`.
    - If `TransactionDTO` has auth headers and `options.secondaryAuth` is set (supports Bearer token or `Cookie:` string):
      1. Dispatches baseline request with original credentials (asserts HTTP 200).
      2. Dispatches unauthenticated probe with stripped credentials (verifies route requires authentication; flags missing auth if 200 returned).
      3. Dispatches cross-tenant probe with `options.secondaryAuth`. If the route required auth (probe 2 returned 401/403) and probe 3 returns 200 with matching JSON body structure (>= 50% key overlap), flags confirmed **BOLA (OWASP API1 / WSTG-ATHZ-02 / ASTF-ATHZ-01)** at `high` severity.
    - If `target` is a plain string URL, falls back to legacy path-increment check.
  - Implement `checkBfla(tx, timeout, secondaryAuth)`: Tests administrative routes (`/admin/`, `/manage/`, `/api/v1/users/delete`) under secondary/unprivileged tokens (WSTG-ATHZ-03 / ASTF-ATHZ-02).
* **Verification Checkpoint**: Unit test `checkIdorBola` and `checkBfla` with mock server instances.

---

### 5.4 Phase 3: BOPLA Mass Assignment & Multi-Standard Check Expansion

#### Step 3.1: Create Property-Level Authorization Check (`cli/src/checks/bopla.js`)
* **Functions to Implement**:
  - `checkExcessiveDataExposure(tx, responseBody)`: Scans response JSON bodies for sensitive PII/secrets (`password_hash`, `ssn`, `private_key`, `secret_token`, `credit_card`). Active scans perform a baseline GET probe to populate `responseBody` if not present in session dump. Flags **OWASP API3 / WSTG-INFO-05**.
  - `checkMassAssignment(tx, timeout, allowMutating = false)`: For JSON endpoints accepting payloads, injects administrative property overrides (`{"isAdmin": true}`, `{"role": "admin"}`, `{"verified": true}`). If server responds with HTTP 200/201 and reflects the injected property in the response, flags **OWASP API3 / WSTG-BUSL-07 / ASTF-ATHZ-03** at `high` severity.
  - `runBoplaChecks(tx, timeout, options)`: Aggregates property exposure and mass assignment tests.

#### Step 3.2: Update CLI Flags & Scanner Integration (`cli/src/args.js`, `cli/bin/boltclone.js`, `cli/src/scan.js`)
* **CLI Arguments to Add (`cli/src/args.js`)**:
  - `--secondary-auth <token|cookie>`: Auth token or cookie for User B to power dual-context BOLA/BFLA verification.
  - `--allow-mutating-methods`: Explicit opt-in enabling parameter fuzzing on `POST`, `PUT`, `DELETE`.
  - `--dry-run`: Prints planned mutated requests without dispatching network packets.
  - `--rate-limit <rps>`: Configures maximum requests per second (default: 15).
* **CLI Executable Forwarding (`cli/bin/boltclone.js`)**:
  - Unpacks `opts.secondaryAuth`, `opts.allowMutatingMethods`, `opts.dryRun`, and `opts.rateLimit` and forwards them into `runScan()`.
* **Orchestrator Wiring (`cli/src/scan.js`)**:
  - Reads session file via `ingestion.normalizeSession()`.
  - Runs pre-flight auth check: validates primary captured credentials and `--secondary-auth` (if provided). If primary returns 401/403, warns user: `"Session token expired or invalid; aborting authenticated tests"`.
  - Wires `mutations.js` into `printDryRun()` to display generated candidate mutations and planned counts.
  - Dispatches `runScan` pool executing `access.js`, `bopla.js`, `injection.js`, `cookies.js`, `graphql.js`, and `exposure.js`.

---

### 5.5 Phase 4: Multi-Standard Reporting, Contract Synchronization & Test Harness

#### Step 5.1: Multi-Standard Reporting Updates (`cli/src/report.js` & `cli/src/htmlReport.js`)
* **Console Reporter (`report.js`)**: Displays four-standard taxonomy tags next to findings:
  `[HIGH] BOLA Detected - /api/orders/102 (OWASP API1 | WSTG-ATHZ-02 | ASTF-ATHZ-01)`
* **HTML Dashboard (`htmlReport.js`)**: Adds interactive filter buttons allowing users to view findings partitioned by:
  - All Findings
  - OWASP Top 10 Web (2021)
  - OWASP API Security Top 10 (2023)
  - OWASP WSTG v4.2
  - OWASP ASTF Workflows

#### Step 5.2: Automated Test Suite (`cli/test/test-owasp-engine.js`)
* **Test Assertions to Implement**:
  1. `ingestion.js`: Merges 3 split webRequest events with matching `id` into 1 unified transaction.
  2. `ingestion.js`: Decodes `{ raw: [{ text: "{\"id\":1}" }] }` into `{ id: 1 }`.
  3. `ingestion.js`: Drops transactions targeting off-scope hosts (`evil.example.com`).
  4. `mutations.js`: Generates IDOR mutations for integer, UUID, and query param targets.
  5. `mutations.js`: Skips `DELETE` and `PUT` endpoints when `allowMutatingMethods` is false.
  6. `access.js`: Flags confirmed BOLA when secondary auth receives HTTP 200 with matching schema.
  7. `bopla.js`: Detects mass assignment when injected `isAdmin` is accepted by mock server.
  8. `http.js`: Injects `X-Bolt-Test-Run` and `X-Synthetic-Test: true` on dispatched requests.
* **Verification Command**:
  - Run: `node cli/test/test-owasp-engine.js`

#### Step 5.3: Contract & Documentation Synchronization
* Update [`README.md`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/README.md), [`cli/README.md`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/README.md), [`cli/src/README.md`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/README.md), and [`cli/src/checks/README.md`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/src/checks/README.md) to document all newly exported modules, function signatures, invariants, and CLI argument flags.
