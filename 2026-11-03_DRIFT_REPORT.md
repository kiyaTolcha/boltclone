# EGM Drift Report (2026-11-03)

Audit of generated repository contract documents against current codebase implementation.

---

## `cli/src/checks/README.md`

No drift detected.
* All 18 exported check functions, signatures, invariants, and side effects match the implementations in `access.js`, `auth.js`, `cookies.js`, `deps.js`, `exposure.js`, `graphql.js`, `injection.js`, and `tls.js`.

---

## `cli/src/README.md`

No drift detected.
* All 17 exported functions across `scan.js`, `args.js`, `discovery.js`, `http.js`, `gemini.js`, `openapi.js`, `postman.js`, `htmlReport.js`, `report.js`, and `vulndb.js` accurately reflect the implementation.
* Relative link `./checks/README.md` resolves to an existing verified contract file.

---

## `cli/bin/README.md`

No drift detected.
* CLI executable options, exit code contract (`0`, `1`, `2`), and progress output streams match [`cli/bin/boltclone.js`](file:///c:/Users/HUAWEI/Documents/Projects/boltclone/cli/bin/boltclone.js).

---

## `cli/README.md`

No drift detected.
* Command usage flags, installation instructions, scan categories, and subdirectories (`./bin/README.md`, `./src/README.md`) match the underlying implementation and file tree.

---

## `chrome-extension/README.md`

No drift detected.
* All modules (`background.js`, `content.js`, `rules.js`, `openapi.js`, `postman.js`, `htmlReport.js`, `gemini.js`, `vulndb.js`) and UI assets match the Manifest V3 specification.
* Test suite verification (`node chrome-extension/test/test-chrome-extension.js`) passes with 89/89 assertions.

---

## `README.md` (Repository Root Blueprint)

No drift detected.
* Architecture diagrams, global invariants (zero external npm runtime dependencies, Manifest V3 compliance, non-destructive execution), global side effects, and all relative contract links accurately reflect the repository structure and verified child contracts.

