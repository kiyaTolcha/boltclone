# Comprehensive OWASP Web (2021) & API (2023) Security Scanner

* **Author:** kiyaTolcha
* **Date:** 2026-11-03

## Overview

BOLTCLONE is an API security testing and traffic analysis toolkit comprising a Chrome Extension (passive real-time traffic capture and rule analysis) and a CLI scanner (zero-dependency automated vulnerability scanner).

This specification establishes an end-to-end testing engine that provides full coverage for both **OWASP Top 10 Web Application Security Risks (2021)** and **OWASP API Security Top 10 (2023)**. It unites passive in-browser inspection with active CLI replay and mutation fuzzing, transforming recorded browser sessions into authenticated vulnerability sweeps across all standard risk categories without external runtime dependencies.

---

## Analysis & OWASP Standards Mapping

All six Goldfish review lenses evaluated the architecture against the two OWASP standards to ensure coverage without introducing architectural bloat, false positives, or destructive risks.

### 1. OWASP Top 10 (2021) Web Applications Mapping

| Category | Vulnerability Type | BOLTCLONE Detection Mechanism | Subsystem |
| :--- | :--- | :--- | :--- |
| **A01: Broken Access Control** | IDOR, path traversal, missing authz, CORS misconfig | Dual-context ID tampering, traversal payloads (`../../etc/passwd`), Origin reflection | CLI (`access.js`, `injection.js`) & Ext (`rules.js`) |
| **A02: Cryptographic Failures** | Missing TLS, weak ciphers, cleartext auth, insecure cookies | Socket TLS inspection, HTTP auth detection, `Set-Cookie` audits (`Secure`, `HttpOnly`, `SameSite`) | CLI (`tls.js`, `cookies.js`) & Ext (`rules.js`) |
| **A03: Injection** | SQLi, Reflected XSS, SSTI, XXE, Command Injection | Parameter injection probes (`' OR '1'='1`, `{{7*7}}`, `<script>`) across URL and JSON keys | CLI (`injection.js`) |
| **A04: Insecure Design** | Architectural flaws, missing rate limits, threat modeling | Rapid request bursts, threat modeling synthesis via Google Gemini API | CLI (`access.js`, `gemini.js`) |
| **A05: Security Misconfiguration** | Missing security headers, tech disclosure, exposed debug endpoints | Header presence check (HSTS, CSP), Server/X-Powered-By detection, `.env`/`.git` probing | CLI (`access.js`, `exposure.js`) & Ext (`rules.js`) |
| **A06: Vulnerable & Outdated Components** | Known CVEs in server stack and frontend dependencies | Live CVE lookup against OSV.dev and NVD via package fingerprinting | CLI (`deps.js`, `vulndb.js`) & Ext (`vulndb.js`) |
| **A07: Identification & Auth Failures** | Default credentials, weak passwords, brute-force | Opt-in login endpoint detection and default credential dictionary evaluation | CLI (`auth.js`) |
| **A08: Software & Data Integrity Failures** | Insecure deserialization, untrusted content execution | Schema validation, MIME type enforcement, Content-Type strictness | CLI (`scan.js`, `openapi.js`) |
| **A09: Security Logging & Monitoring** | Missing audit trails, unmonitored test traffic | Synthetic test tagging (`X-Bolt-Test-Run`, `X-Synthetic-Test`) for telemetry triage | CLI (`http.js`, `scan.js`) |
| **A10: Server-Side Request Forgery (SSRF)** | Internal IP/metadata service access | Localhost/metadata endpoint probing (`127.0.0.1`, `169.254.169.254`) | CLI (`access.js`) |

---

### 2. OWASP API Security Top 10 (2023) Mapping

| Category | API Vulnerability Type | BOLTCLONE Detection Mechanism | Subsystem |
| :--- | :--- | :--- | :--- |
| **API1: BOLA (Broken Object Level Auth)** | Object ID tampering across user boundaries | Dual-context matrix (`--secondary-auth`) comparing User A baseline vs User B probe | CLI (`access.js`, `mutations.js`) |
| **API2: Broken Authentication** | Token expiration, weak JWTs, credential stuffing | Pre-flight auth verification, Bearer/Basic token validation, brute-force auth module | CLI (`auth.js`, `scan.js`) & Ext (`rules.js`) |
| **API3: BOPLA (Property-Level Auth)** | Mass assignment, excessive data exposure | Ingestion body property tampering, detection of sensitive response fields (`ssn`, `password_hash`) | Ext (`rules.js`) & CLI (`mutations.js`) |
| **API4: Unrestricted Resource Consumption** | Missing rate limits, GraphQL batching/deep query abuse | 8-burst rate limit checks, GraphQL introspection & multi-query batching probes | CLI (`access.js`, `graphql.js`) |
| **API5: BFLA (Function Level Auth)** | Administrative privilege escalation | Replaying administrative endpoints with non-admin tokens or stripped auth | CLI (`access.js`, `mutations.js`) |
| **API6: Unrestricted Business Flows** | Automation of sensitive business endpoints | Baseline heuristic flagging for repeated high-impact transactions | Ext (`rules.js`) |
| **API7: Server Side Request Forgery (SSRF)** | API webhooks and parameter-based URL fetches | Loopback and cloud metadata query parameter probing | CLI (`access.js`) |
| **API8: Security Misconfiguration** | Verb tampering, CORS with credentials, missing headers | OPTIONS preflight inspection, HTTP method testing (`TRACE`, `OPTIONS`), header linting | CLI (`access.js`) & Ext (`rules.js`) |
| **API9: Improper Inventory Management** | Shadow / Zombie APIs, stale API versions | Stale API version probing (`/v0`, `/v1`), OpenAPI drift detection against runtime traffic | CLI (`access.js`, `openapi.js`) |
| **API10: Unsafe Consumption of APIs** | Blind trust in external APIs, unvalidated payloads | Ingress payload sanitization, Content-Type mismatch checks, response anomaly detection | CLI (`scan.js`, `http.js`) |

---

## Goals vs. Non-Goals

### In-Scope Goals
* **Comprehensive 20-Point OWASP Matrix**: Provide test coverage and reporting for all 10 OWASP Web (2021) and 10 OWASP API (2023) categories.
* **Dual-Context Authorization Engine**: Implement `--secondary-auth` to eliminate false positives in BOLA (API1/A01) and BFLA (API5/A01).
* **Safe-by-Default Replay**: Restrict automated mutation testing to idempotent methods (`GET`, `HEAD`, `OPTIONS`) by default, requiring `--allow-mutating-methods` for state-altering requests.
* **Canonical Session Ingestion**: Recombine Chrome `webRequest` split events (`groupById`) and decode body envelopes (`formData`, `raw.text`) into standard transactions.
* **Zero External Runtime Dependencies**: Standard Node.js 20+ built-ins (`node:util`, `node:crypto`, `node:fs`, `node:tls`, native `fetch`).

### Out-of-Scope Non-Goals
* **Destructive Automatic Modification by Default**: No blind deletion of production data.
* **Headless Browser Crawler Engine**: No dynamic Chromium browser automation inside the CLI; traffic capture is provided by the Chrome extension.

---

## Key Decisions & Staging for Next Steps

1. **Integrated OWASP Reporting Matrix**: Format CLI console, JSON, and HTML reports with explicit tags linking each finding to OWASP Web 2021 and OWASP API 2023 IDs.
2. **Modular Architecture**: Separate transport (`http.js`), evaluation oracles (`checks/*.js`), and payload mutation (`mutations.js`).
3. **Dual-Tenant CLI Flags**: Provide `--secondary-auth <token>` and `--creds <file>` to power authenticated authorization checks.

Staged for formal design drafting in `/egm-draft`.
