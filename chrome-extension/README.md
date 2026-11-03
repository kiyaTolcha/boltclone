# Chrome Extension Subsystem

## Overview
The `chrome-extension` package implements the browser-side passive traffic interceptor, security rule analyzer, and specification generator for BOLTCLONE. Built on Manifest V3, it intercepts HTTP/HTTPS network traffic via `chrome.webRequest`, discovers API endpoints in real-time, flags security misconfigurations, and exports structured OpenAPI, Postman, and HTML security reports.

## Interface
- `background.js`: Background Service Worker managing traffic capture listeners, storage flushing, alarms, and message handling ([`background.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/background.js#L1)).
- `content.js`: Page-level content script injected across `<all_urls>` to monitor DOM API fetch/XHR calls ([`content.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/content.js#L1)).
- `analyzeTraffic(logEntries)`: Analyzes grouped HTTP transactions for BOLA patterns, mass assignment, token leakage in query strings, missing cookie flags, cleartext auth, and tech disclosure ([`rules.js:11`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/rules.js#L11)).
- `analyzeHosts(logEntries)`: Aggregates captured transactions by origin host, classifying authentication strength, rate limiting, HSTS, CORS policies, and exposed PII ([`rules.js:131`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/rules.js#L131)).
- `groupById(logEntries)`: Merges asynchronous `onBeforeRequest`, `onSendHeaders`, and `onHeadersReceived` webRequest events sharing a request ID into consolidated transaction objects ([`rules.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/rules.js#L1)).
- `buildOpenApi(trafficLogs, customOptions)`: Generates an OpenAPI 3.0 specification from captured traffic ([`openapi.js:68`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/openapi.js#L68)).
- `buildPostmanCollection(trafficLogs)`: Generates a Postman Collection v2.1 export ([`postman.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/postman.js#L1)).
- `generateHtmlReport({ target, findings, traffic, discovered })`: Produces a self-contained HTML vulnerability and traffic report ([`htmlReport.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/htmlReport.js#L1)).
- `analyzeWithGemini(apiKey, findings, meta)`: Queries Google Gemini API for threat analysis and priority fix recommendations ([`gemini.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/gemini.js#L1)).
- `lookupSoftwareVulns(serverHeader)`: Queries OSV.dev for known CVEs matching detected server technologies ([`vulndb.js:1`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/chrome-extension/vulndb.js#L1)).
- `popup.js` / `panel.html` / `devtools.html`: User interface components for DevTools integration, active traffic viewing, and the interactive Manipulator Wizard.

## Invariants
- Manifest V3 compliant: avoids dynamic evaluation (`eval`), imports internal modules via `importScripts`, and runs in service worker context.
- Passive traffic capture: does not block or alter in-flight web traffic during standard capture modes.
- Storage isolation: stores captured session logs in `chrome.storage.local` with bounded array caps (`MAX_DISCOVERED = 300`).

## Side Effects
- Registers listeners on `chrome.webRequest` (`onBeforeRequest`, `onSendHeaders`, `onHeadersReceived`) across `<all_urls>`.
- Mutates `chrome.storage.local` keys (`boltcloneTraffic`, `discoveredApis`, `boltcloneCaptureRules`, `boltcloneAnalysis`).
- Triggers browser downloads via data URLs and `chrome.downloads` for exported files.
- Makes outbound network requests to Gemini API and OSV.dev when explicitly triggered.

## Verification
- Run: `node chrome-extension/test/test-chrome-extension.js`

