import fs from 'node:fs/promises';
import { pool, setDefaultRateLimit } from './http.js';
import { normalizeSession } from './ingestion.js';
import { generateIdorMutations, generateBflaMutations, generateParamMutations } from './mutations.js';
import { discoverEndpoints, enumerateSubdomains } from './discovery.js';
import { runInjectionChecks } from './checks/injection.js';
import { runAccessChecks, checkIdorBola, checkBfla } from './checks/access.js';
import { runBoplaChecks, checkExcessiveDataExposure } from './checks/bopla.js';
import { runTlsChecks } from './checks/tls.js';
import { runDependencyChecks } from './checks/deps.js';
import { runAuthChecks } from './checks/auth.js';
import { runCookieChecks } from './checks/cookies.js';
import { runGraphqlChecks } from './checks/graphql.js';
import { runExposureChecks } from './checks/exposure.js';
import { lookupSoftwareVulns } from './vulndb.js';
import { analyzeWithGemini } from './gemini.js';

export function normalizeTarget(value) {
  const withScheme = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  return new URL(withScheme).toString().replace(/\/$/, '');
}

/**
 * Parameterizes a URL path by replacing dynamic IDs (integers, UUIDs, hex hashes)
 * with placeholder tokens, producing a canonical route template.
 * E.g., "/api/users/123/orders/550e8400-e29b-41d4-a716-446655440000"
 *    -> "/api/users/{id}/orders/{uuid}"
 *
 * @param {string} urlString
 * @returns {string}
 */
export function parameterizeUrlPath(urlString) {
  try {
    const parsed = new URL(urlString);
    const segments = parsed.pathname.split('/').map((seg) => {
      if (/^\d+$/.test(seg)) return '{id}';
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return '{uuid}';
      if (/^[0-9a-f]{24,64}$/i.test(seg)) return '{hash}';
      return seg;
    });
    // Canonicalize query parameter names (sorted keys without values)
    const paramKeys = Array.from(parsed.searchParams.keys()).sort().join('&');
    return `${segments.join('/')}${paramKeys ? `?${paramKeys}` : ''}`;
  } catch {
    return urlString;
  }
}

/**
 * Deduplicates transactions by route template.
 * Retains at most `maxPerRoute` (default: 2) instances per template so that
 * differential BOLA/IDOR checks have at least two distinct objects to compare,
 * while eliminating dozens of redundant requests on the same endpoint.
 *
 * @param {TransactionDTO[]} transactions
 * @param {number} [maxPerRoute=2]
 * @returns {TransactionDTO[]}
 */
export function deduplicateTransactions(transactions, maxPerRoute = 2) {
  const groups = new Map();
  for (const tx of transactions) {
    const template = `${tx.method} ${parameterizeUrlPath(tx.url)}`;
    if (!groups.has(template)) {
      groups.set(template, []);
    }
    const list = groups.get(template);
    if (list.length < maxPerRoute) {
      list.push(tx);
    }
  }
  const result = [];
  for (const list of groups.values()) {
    result.push(...list);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Pre-flight session token validity check
// ---------------------------------------------------------------------------

/**
 * Sends one baseline request using the session's captured credentials to
 * confirm the token is still valid before running authenticated tests.
 *
 * Returns true if credentials appear valid (2xx response), false otherwise.
 *
 * @param {TransactionDTO[]} transactions  Normalized session transactions.
 * @param {number}           timeout
 * @param {Function}         onProgress
 * @returns {Promise<boolean>}
 */
async function validateSessionAuth(transactions, timeout, onProgress, secondaryAuth = null) {
  // Find the first enriched transaction that carries an Authorization header.
  const enrichedTx = transactions.find(
    (tx) => tx.isEnriched && tx.headers?.authorization
  );
  if (!enrichedTx) return true; // No auth headers captured — non-authenticated session, proceed.

  onProgress?.('Pre-flight: validating captured session token ...');

  let resp;
  try {
    resp = await fetch(enrichedTx.url, {
      method:  enrichedTx.method,
      headers: enrichedTx.headers,
      signal:  AbortSignal.timeout(timeout),
    });
  } catch {
    onProgress?.('Pre-flight: could not reach target to validate session token — continuing.');
    return true; // Network unreachable is not a token failure; do not abort.
  }

  if (resp.status === 401 || resp.status === 403) {
    onProgress?.('Warning: Session token expired or invalid; aborting authenticated tests.');
    return false;
  }

  onProgress?.(`Pre-flight: session token valid (HTTP ${resp.status} on ${enrichedTx.url}).`);

  if (secondaryAuth) {
    onProgress?.('Pre-flight: validating secondary auth token/cookie ...');
    const secHeaders = { ...enrichedTx.headers };
    if (secondaryAuth.toLowerCase().startsWith('cookie:')) {
      secHeaders['cookie'] = secondaryAuth.replace(/^cookie:\s*/i, '').trim();
    } else if (secondaryAuth.includes('=')) {
      secHeaders['cookie'] = secondaryAuth.trim();
    } else {
      secHeaders['authorization'] = secondaryAuth.startsWith('Bearer ') ? secondaryAuth : `Bearer ${secondaryAuth}`;
    }
    try {
      const secResp = await fetch(enrichedTx.url, {
        method: enrichedTx.method,
        headers: secHeaders,
        signal: AbortSignal.timeout(timeout),
      });
      onProgress?.(`Pre-flight: secondary auth responded with HTTP ${secResp.status}.`);
    } catch {
      onProgress?.('Pre-flight: could not reach target to validate secondary auth — continuing.');
    }
  }

  return true;
}

// ---------------------------------------------------------------------------
// Dry-run helper
// ---------------------------------------------------------------------------

/**
 * Prints planned mutations to stdout without dispatching any packets.
 * Called when --dry-run is set.
 *
 * @param {TransactionDTO[]} transactions
 * @param {object}           scanOptions
 * @param {Function}         onProgress
 */
function printDryRun(transactions, scanOptions, onProgress) {
  onProgress?.('DRY-RUN mode — no network requests will be dispatched for mutated transactions.\n');
  onProgress?.(`Session transactions: ${transactions.length}`);

  let plannedIdor = 0;
  let plannedBfla = 0;
  let plannedParam = 0;

  for (const tx of transactions) {
    const method = tx.method.padEnd(7);
    const enriched = tx.isEnriched ? '[enriched]' : '[url-only]';
    const auth = tx.headers?.authorization ? `[auth: ${tx.headers.authorization.slice(0, 30)}...]` : '[no-auth]';
    onProgress?.(`  ${method} ${tx.url} ${enriched} ${auth}`);

    for (const _ of generateIdorMutations(tx, scanOptions.allowMutatingMethods)) plannedIdor++;
    if (scanOptions.secondaryAuth) {
      for (const _ of generateBflaMutations(tx, scanOptions.secondaryAuth, scanOptions.allowMutatingMethods)) plannedBfla++;
    }
    for (const _ of generateParamMutations(tx, undefined, scanOptions.allowMutatingMethods)) plannedParam++;
  }

  onProgress?.(`\nPlanned Mutations:`);
  onProgress?.(`  IDOR/BOLA candidate probes:     ${plannedIdor}`);
  onProgress?.(`  BFLA privilege probe mutations: ${plannedBfla}`);
  onProgress?.(`  Parameter fuzz probes:          ${plannedParam}`);

  if (scanOptions.secondaryAuth) {
    onProgress?.(`\nSecondary auth provided — dual-context BOLA/BFLA tests active.`);
  }
  if (scanOptions.allowMutatingMethods) {
    onProgress?.('--allow-mutating-methods active — POST/PUT/PATCH/DELETE will be mutated.');
  } else {
    onProgress?.('Safe mode default — mutating verbs (POST/PUT/PATCH/DELETE) skipped.');
  }
  onProgress?.('\n(DRY-RUN complete — rerun without --dry-run to execute.)');
}

// ---------------------------------------------------------------------------
// Main scan orchestrator
// ---------------------------------------------------------------------------

/**
 * Runs the full BOLTCLONE scan pipeline.
 *
 * New parameters (Phase 3):
 *   secondaryAuth        — Bearer token for dual-context BOLA/BFLA (optional).
 *   allowMutatingMethods — Enables POST/PUT/PATCH/DELETE mutation (default false).
 *   dryRun               — Prints planned mutations without network dispatch.
 *   rateLimit            — Requests per second ceiling (default 15).
 *
 * @param {object} opts
 * @returns {Promise<{ findings, meta }>}
 */
export async function runScan({
  target,
  concurrency,
  timeout,
  categories,
  credsFile,
  importSession,
  vulndb,
  geminiKey,
  onProgress,
  // Phase 3 additions:
  secondaryAuth        = null,
  allowMutatingMethods = false,
  dryRun               = false,
  rateLimit            = 15,
}) {
  const startTime = Date.now();
  const baseUrl   = normalizeTarget(target);
  const hostname  = new URL(baseUrl).hostname;
  const findings  = [];
  let geminiAnalysis = null;
  let vulndbResults  = [];

  // Apply rate limiter configuration from --rate-limit.
  setDefaultRateLimit(rateLimit);

  // ---------------------------------------------------------------------------
  // Session ingestion (Phase 1 normalizer)
  // ---------------------------------------------------------------------------
  let transactions = [];   // Canonical TransactionDTO[]

  if (importSession) {
    try {
      onProgress?.(`Importing session file: ${importSession} ...`);
      const raw    = await fs.readFile(importSession, 'utf8');
      const parsed = JSON.parse(raw);
      transactions = normalizeSession(parsed, baseUrl);
      onProgress?.(`Session normalizer: ${transactions.length} transaction(s) scoped to ${hostname}.`);

      const beforeCount = transactions.length;
      transactions = deduplicateTransactions(transactions, 2);
      if (transactions.length < beforeCount) {
        const savedPct = Math.round((1 - transactions.length / beforeCount) * 100);
        onProgress?.(`Route deduplication: condensed ${beforeCount} transactions to ${transactions.length} unique route templates (-${savedPct}% probe traffic).`);
      }
    } catch (err) {
      onProgress?.(`Warning: Failed to parse session file: ${err.message}`);
    }
  }

  // Legacy: build importedTraffic array for backward-compat callers (report.js).
  const importedTraffic = transactions.map((tx) => ({ url: tx.url, method: tx.method }));

  // ---------------------------------------------------------------------------
  // Dry-run gate
  // ---------------------------------------------------------------------------
  if (dryRun) {
    printDryRun(transactions, { secondaryAuth, allowMutatingMethods }, onProgress);
    return {
      findings: [],
      meta: {
        target: baseUrl,
        endpointCount: 0,
        subdomainCount: 0,
        subdomains: [],
        discovered: [],
        importedTraffic,
        transactions,
        vulndbResults: [],
        geminiAnalysis: null,
        durationMs: Date.now() - startTime,
        dryRun: true,
      },
    };
  }

  // ---------------------------------------------------------------------------
  // Pre-flight session token validation
  // ---------------------------------------------------------------------------
  let sessionValid = true;
  if (transactions.length > 0) {
    sessionValid = await validateSessionAuth(transactions, timeout, onProgress, secondaryAuth);
  }

  // ---------------------------------------------------------------------------
  // Endpoint discovery
  // ---------------------------------------------------------------------------
  onProgress?.(`Discovering endpoints on ${baseUrl} ...`);
  const discovered = await discoverEndpoints(baseUrl, { concurrency, timeout });
  onProgress?.(`Found ${discovered.length} endpoint(s).`);

  let subdomains = [];
  if (categories.subdomains) {
    onProgress?.(`Enumerating subdomains for ${hostname} via crt.sh ...`);
    subdomains = await enumerateSubdomains(hostname, { timeout });
    onProgress?.(`Found ${subdomains.length} subdomain(s).`);
  }

  // Merge discovered URLs with enriched session transaction URLs for scanning.
  const sessionUrls = transactions.map((tx) => tx.url);
  const scanTargets = Array.from(
    new Set([baseUrl, ...discovered.map((d) => d.url), ...sessionUrls])
  );

  // ---------------------------------------------------------------------------
  // Standard URL-based injection / access checks
  // ---------------------------------------------------------------------------
  if (categories.injection || categories.access) {
    onProgress?.(`Running injection/access checks against ${scanTargets.length} endpoint(s) ...`);
    await pool(scanTargets, concurrency, async (url) => {
      if (categories.injection) findings.push(...await runInjectionChecks(url, timeout));
      if (categories.access)    findings.push(...await runAccessChecks(url, timeout));
    });
  }

  // ---------------------------------------------------------------------------
  // Session-based dual-context BOLA / BFLA checks (Phase 2)
  // ---------------------------------------------------------------------------
  if (categories.access && sessionValid && transactions.length > 0) {
    onProgress?.(`Running dual-context BOLA/BFLA checks on ${transactions.length} session transaction(s) ...`);
    await pool(transactions, concurrency, async (tx) => {
      // Dual-context IDOR/BOLA.
      const bolaResult = await checkIdorBola(tx, timeout, { secondaryAuth });
      if (bolaResult) {
        findings.push(...(Array.isArray(bolaResult) ? bolaResult : [bolaResult]));
      }
      // BFLA (function-level auth).
      if (secondaryAuth || tx.headers?.authorization) {
        const bflaResults = await checkBfla(tx, timeout, secondaryAuth);
        findings.push(...bflaResults);
      }
    });
  }

  // ---------------------------------------------------------------------------
  // BOPLA checks — property-level authorization (Phase 3)
  // ---------------------------------------------------------------------------
  if (categories.bopla && sessionValid && transactions.length > 0) {
    onProgress?.(`Running BOPLA checks (mass assignment, excessive data exposure) on ${transactions.length} transaction(s) ...`);
    await pool(transactions, concurrency, async (tx) => {
      const boplaResults = await runBoplaChecks(tx, timeout, {
        allowMutating: allowMutatingMethods,
        responseBody:  null, // Passive check: caller must supply responseBody if available.
      });
      findings.push(...boplaResults);
    });
  }

  // ---------------------------------------------------------------------------
  // Side-channel checks (TLS, deps, cookies, GraphQL, exposure)
  // ---------------------------------------------------------------------------
  const sideTasks = [];

  if (categories.tls) {
    sideTasks.push((async () => {
      onProgress?.('Running TLS/certificate checks ...');
      findings.push(...await runTlsChecks(hostname, timeout));
    })());
  }

  if (categories.deps) {
    sideTasks.push((async () => {
      onProgress?.('Fingerprinting dependencies and checking OSV.dev ...');
      findings.push(...await runDependencyChecks(baseUrl, timeout));
    })());
  }

  if (categories.cookies) {
    sideTasks.push((async () => {
      onProgress?.(`Running cookie security checks against ${scanTargets.length} endpoint(s) ...`);
      await pool(scanTargets, concurrency, async (url) => {
        findings.push(...await runCookieChecks(url, timeout));
      });
    })());
  }

  if (categories.graphql) {
    sideTasks.push((async () => {
      onProgress?.('Probing for GraphQL endpoints ...');
      findings.push(...await runGraphqlChecks(baseUrl, timeout));
    })());
  }

  if (categories.exposure) {
    sideTasks.push((async () => {
      onProgress?.('Probing for sensitive file / endpoint exposure ...');
      findings.push(...await runExposureChecks(baseUrl, timeout));
    })());
  }

  await Promise.all(sideTasks);

  // ---------------------------------------------------------------------------
  // Opt-in auth / brute-force checks
  // ---------------------------------------------------------------------------
  if (categories.auth) {
    onProgress?.('Running opt-in auth checks (only against targets you are authorized to test) ...');
    findings.push(...await runAuthChecks(baseUrl, discovered, timeout, credsFile));
  }

  // ---------------------------------------------------------------------------
  // Vulnerability database lookup
  // ---------------------------------------------------------------------------
  if (vulndb) {
    onProgress?.('Querying Vulnerability Databases (OSV.dev / NVD) for server technologies ...');
    const depFinding = findings.find((f) => f.category === 'deps' && f.evidence?.includes('Server:'));
    if (depFinding) {
      vulndbResults = await lookupSoftwareVulns(depFinding.evidence);
      for (const res of vulndbResults) {
        for (const v of res.vulns) {
          findings.push({
            category: 'vulndb',
            title:    `Vulnerability in ${res.software} ${res.version}: ${v.cve}`,
            severity: 'high',
            url:      baseUrl,
            evidence: `CVE ID: ${v.cve} | Summary: ${v.summary}`,
            standards: { owaspWeb: 'A06', owaspApi: null, wstg: 'WSTG-CONF-01', astf: null },
          });
        }
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Gemini AI synthesis
  // ---------------------------------------------------------------------------
  if (geminiKey) {
    try {
      onProgress?.('Synthesizing threat analysis & remediation guidance via Google Gemini AI ...');
      geminiAnalysis = await analyzeWithGemini(
        geminiKey, findings, { target: baseUrl, endpointCount: scanTargets.length }
      );
    } catch (err) {
      onProgress?.(`Warning: Gemini AI analysis failed: ${err.message}`);
    }
  }

  // ---------------------------------------------------------------------------
  // Result
  // ---------------------------------------------------------------------------
  return {
    findings,
    meta: {
      target:         baseUrl,
      endpointCount:  scanTargets.length,
      subdomainCount: subdomains.length,
      subdomains,
      discovered,
      importedTraffic,
      transactions,
      vulndbResults,
      geminiAnalysis,
      durationMs:     Date.now() - startTime,
      dryRun:         false,
    },
  };
}
