/**
 * access.js - Access Control Check Suite
 *
 * Implements active security checks for:
 *   - BOLA/IDOR (OWASP API1 / WSTG-ATHZ-02 / ASTF-ATHZ-01)
 *   - BFLA (OWASP API5 / WSTG-ATHZ-03 / ASTF-ATHZ-02)
 *   - CORS misconfiguration (OWASP A01 / WSTG-CONF-07)
 *   - CSRF risk (OWASP A01 / WSTG-SESS-05)
 *   - SSRF (OWASP A10 / WSTG-INPV-19)
 *   - Missing security headers (OWASP A05 / WSTG-CONF-11)
 *   - TRACE method / XST (OWASP A05 / WSTG-CONF-06)
 *   - Host header injection (OWASP A03 / WSTG-INPV-17)
 *   - Stale API version (OWASP API9 / ASTF-CONF-02)
 *   - Rate limiting absence (OWASP API4 / WSTG-CONF-01)
 *
 * checkIdorBola() supports two call modes:
 *   1. Legacy (string URL): uses path-increment heuristic — single context.
 *   2. Dual-context (TransactionDTO + options.secondaryAuth): dispatches three
 *      probes (baseline, unauthenticated, cross-tenant) and compares responses.
 */

'use strict';

import { safeFetch, timeoutFetch } from '../http.js';

// ---------------------------------------------------------------------------
// Standard taxonomy tags
// ---------------------------------------------------------------------------
const STANDARDS = {
  BOLA:             { owaspWeb: 'A01', owaspApi: 'API1', wstg: 'WSTG-ATHZ-02', astf: 'ASTF-ATHZ-01' },
  BFLA:             { owaspWeb: 'A01', owaspApi: 'API5', wstg: 'WSTG-ATHZ-03', astf: 'ASTF-ATHZ-02' },
  RATE_LIMIT:       { owaspWeb: 'A04', owaspApi: 'API4', wstg: 'WSTG-CONF-01', astf: 'ASTF-CONF-01' },
  CORS:             { owaspWeb: 'A05', owaspApi: 'API7', wstg: 'WSTG-CONF-07', astf: null },
  CSRF:             { owaspWeb: 'A01', owaspApi: null,   wstg: 'WSTG-SESS-05', astf: null },
  SSRF:             { owaspWeb: 'A10', owaspApi: 'API7', wstg: 'WSTG-INPV-19', astf: null },
  SECURITY_HEADERS: { owaspWeb: 'A05', owaspApi: null,   wstg: 'WSTG-CONF-11', astf: null },
  XST:              { owaspWeb: 'A05', owaspApi: null,   wstg: 'WSTG-CONF-06', astf: null },
  HOST_INJECT:      { owaspWeb: 'A03', owaspApi: null,   wstg: 'WSTG-INPV-17', astf: null },
  STALE_API:        { owaspWeb: 'A09', owaspApi: 'API9', wstg: null,            astf: 'ASTF-CONF-02' },
};

/**
 * Builds a finding object with the four-standard taxonomy attached.
 *
 * @param {object} base   { category, title, severity, url, evidence }
 * @param {string} stdKey Key from STANDARDS map.
 * @returns {object}
 */
function finding(base, stdKey) {
  return { ...base, standards: STANDARDS[stdKey] ?? null };
}

// ---------------------------------------------------------------------------
// Helper: compare response body structure
// ---------------------------------------------------------------------------

/**
 * Fetches a URL, attempts to parse the response as JSON, and returns both the
 * status code and the parsed body (or null on parse failure).
 *
 * @param {string}  url
 * @param {object}  opts   fetch init options.
 * @param {number}  timeout
 * @returns {Promise<{ status: number, body: object|null }|null>}
 */
async function probeJson(url, opts, timeout) {
  const resp = await safeFetch(url, opts, timeout);
  if (!resp) return null;
  let body = null;
  try { body = await resp.json(); } catch { /* ignore */ }
  return { status: resp.status, body };
}

/**
 * Compares the top-level keys of two JSON objects.
 * Returns true if they share at least half their keys — indicative that the
 * cross-tenant response returned data in the same schema as the baseline.
 *
 * @param {object|null} a
 * @param {object|null} b
 * @returns {boolean}
 */
function schemaSimilar(a, b) {
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object') return false;
  const keysA = new Set(Object.keys(a));
  const keysB = Object.keys(b);
  if (keysA.size === 0 || keysB.length === 0) return false;
  const shared = keysB.filter((k) => keysA.has(k)).length;
  return shared / Math.max(keysA.size, keysB.length) >= 0.5;
}

// ---------------------------------------------------------------------------
// Rate limiting check
// ---------------------------------------------------------------------------

export async function checkRateLimit(url, timeout) {
  const attempts = await Promise.all(
    Array.from({ length: 8 }, () => timeoutFetch(url, { method: 'GET' }, timeout).catch((e) => e))
  );
  const statuses = attempts.filter((r) => r instanceof Response).map((r) => r.status);
  if (statuses.length === 0) return null;
  if (!statuses.includes(429) && statuses.filter((s) => s >= 200 && s < 300).length > 5) {
    return finding({
      category: 'access',
      title: 'No rate-limiting detected',
      severity: 'medium',
      url,
      evidence: `8 rapid requests, statuses: ${statuses.join(', ')}`,
    }, 'RATE_LIMIT');
  }
  return null;
}

// ---------------------------------------------------------------------------
// BOLA / IDOR check — polymorphic (string URL or TransactionDTO)
// ---------------------------------------------------------------------------

/**
 * Checks for Broken Object Level Authorization (BOLA / IDOR).
 *
 * When `target` is a plain string URL: falls back to the legacy single-context
 * path-increment heuristic (no auth headers, no comparison).
 *
 * When `target` is a TransactionDTO and `options.secondaryAuth` is provided:
 * executes the dual-context three-probe matrix:
 *   1. Baseline probe — original credentials → must return 2xx to proceed.
 *   2. Unauthenticated probe — stripped auth → 2xx means the resource is public
 *      or auth bypass is present (WSTG-ATHZ-02, medium severity).
 *   3. Cross-tenant probe — secondary auth token → 2xx + schema match means
 *      confirmed BOLA (OWASP API1 / WSTG-ATHZ-02 / ASTF-ATHZ-01, high severity).
 *
 * @param {string|TransactionDTO} target
 * @param {number}                timeout
 * @param {object}                [options={}]
 * @param {string}                [options.secondaryAuth]  Bearer token for User B.
 * @returns {Promise<object|object[]|null>}
 */
export async function checkIdorBola(target, timeout, options = {}) {
  // ── Dual-context path (TransactionDTO with secondaryAuth) ────────────────
  if (target && typeof target === 'object' && target.url) {
    const tx = target;
    const { secondaryAuth } = options;

    // Only proceed with dual-context if the session was enriched with auth
    // headers — otherwise we cannot distinguish "public data" from a real leak.
    if (!tx.isEnriched || !tx.headers?.authorization) {
      // Fall through to legacy heuristic using the URL string.
      return checkIdorBola(tx.url, timeout, options);
    }

    const fetchOpts = {
      method: tx.method,
      headers: tx.headers,
      standard: 'WSTG-ATHZ-02',
    };

    // Probe 1: baseline — original credentials.
    const baseline = await probeJson(tx.url, fetchOpts, timeout);
    if (!baseline || baseline.status < 200 || baseline.status >= 300) return null;

    const findings = [];

    // Probe 2: unauthenticated — strip auth + cookie.
    const unauthHeaders = Object.fromEntries(
      Object.entries(tx.headers).filter(([k]) => k !== 'authorization' && k !== 'cookie')
    );
    const unauthProbe = await probeJson(tx.url, { method: tx.method, headers: unauthHeaders, standard: 'WSTG-ATHZ-02' }, timeout);
    if (unauthProbe && unauthProbe.status >= 200 && unauthProbe.status < 300) {
      findings.push(finding({
        category: 'access',
        title: 'Potential unauthenticated access (BOLA/IDOR)',
        severity: 'medium',
        url: tx.url,
        evidence: `Endpoint returned HTTP ${unauthProbe.status} without Authorization header. Resource may be publicly accessible or auth check is missing. (WSTG-ATHZ-02)`,
      }, 'BOLA'));
    }

    // Probe 3: cross-tenant — secondary auth token.
    if (secondaryAuth) {
      const crossHeaders = {
        ...unauthHeaders,
        authorization: secondaryAuth.startsWith('Bearer ')
          ? secondaryAuth
          : `Bearer ${secondaryAuth}`,
      };
      const crossProbe = await probeJson(tx.url, { method: tx.method, headers: crossHeaders, standard: 'ASTF-ATHZ-01' }, timeout);
      if (crossProbe && crossProbe.status >= 200 && crossProbe.status < 300 && schemaSimilar(baseline.body, crossProbe.body)) {
        findings.push(finding({
          category: 'access',
          title: 'Confirmed BOLA — cross-tenant object access',
          severity: 'high',
          url: tx.url,
          evidence: `User B (secondary token) received HTTP ${crossProbe.status} with matching response schema. Object at ${tx.url} is accessible across tenant boundaries. (OWASP API1 / WSTG-ATHZ-02 / ASTF-ATHZ-01)`,
        }, 'BOLA'));
      }
    }

    return findings.length > 0 ? findings : null;
  }

  // ── Legacy single-context path (plain string URL) ────────────────────────
  let parsed;
  try { parsed = new URL(target); } catch { return null; }

  const segments = parsed.pathname.split('/').filter(Boolean);
  const idx = segments.findIndex((s) => /^\d+$/.test(s));
  if (idx === -1) return null;

  const original = segments[idx];
  const alt = String(Number(original) + 1);
  const trial = new URL(parsed);
  trial.pathname = parsed.pathname.replace(`/${original}`, `/${alt}`);

  const [origResp, altResp] = await Promise.all([
    safeFetch(parsed.toString(), {}, timeout),
    safeFetch(trial.toString(), {}, timeout),
  ]);
  if (!origResp || origResp.status < 200 || origResp.status >= 300) return null;
  if (altResp && altResp.status >= 200 && altResp.status < 300) {
    return finding({
      category: 'access',
      title: 'Potential IDOR/BOLA',
      severity: 'high',
      url: trial.toString(),
      evidence: `Adjacent object id ${alt} accessible without authorization (status ${altResp.status})`,
    }, 'BOLA');
  }
  return null;
}

// ---------------------------------------------------------------------------
// BFLA check (OWASP API5 / WSTG-ATHZ-03 / ASTF-ATHZ-02)
// ---------------------------------------------------------------------------

// Administrative / privileged route patterns.
const PRIVILEGED_PATH_PATTERNS = [
  /\/admin(\/|$)/i,
  /\/manage(\/|$)/i,
  /\/management(\/|$)/i,
  /\/superuser(\/|$)/i,
  /\/staff(\/|$)/i,
  /\/internal(\/|$)/i,
  /\/backoffice(\/|$)/i,
  /\/(api\/v\d+\/)?users\/(delete|ban|promote|demote|update-role)/i,
  /\/(api\/v\d+\/)?settings\/security/i,
  /\/(api\/v\d+\/)?permissions/i,
  /\/(api\/v\d+\/)?roles/i,
];

/**
 * Tests whether an authenticated privileged endpoint is accessible to an
 * unprivileged/secondary credential (Broken Function Level Authorization).
 *
 * Dispatches two probes:
 *   A. Unauthenticated — no auth headers.
 *   B. Cross-tenant — secondary auth token.
 *
 * A 2xx response on either probe for a privileged route signals BFLA.
 *
 * @param {TransactionDTO} tx
 * @param {number}         timeout
 * @param {string|null}    secondaryAuth  Bearer token for User B.
 * @returns {Promise<object[]>}
 */
export async function checkBfla(tx, timeout, secondaryAuth = null) {
  if (!tx || !tx.url) return [];

  const isPrivileged = PRIVILEGED_PATH_PATTERNS.some((re) => re.test(tx.url));
  if (!isPrivileged) return [];

  const findings = [];

  // Base headers without auth/cookie for unauthenticated probe.
  const headersNoAuth = Object.fromEntries(
    Object.entries(tx.headers ?? {}).filter(([k]) => k !== 'authorization' && k !== 'cookie')
  );

  // Probe A: unauthenticated.
  const unauthResp = await safeFetch(
    tx.url,
    { method: tx.method ?? 'GET', headers: headersNoAuth, standard: 'WSTG-ATHZ-03' },
    timeout
  );
  if (unauthResp && unauthResp.status >= 200 && unauthResp.status < 300) {
    findings.push(finding({
      category: 'access',
      title: 'BFLA — Privileged endpoint accessible without authentication',
      severity: 'high',
      url: tx.url,
      evidence: `${tx.method ?? 'GET'} ${tx.url} returned HTTP ${unauthResp.status} with no Authorization header. Administrative function accessible to unauthenticated callers. (OWASP API5 / WSTG-ATHZ-03 / ASTF-ATHZ-02)`,
    }, 'BFLA'));
  }

  // Probe B: cross-tenant / unprivileged secondary token.
  if (secondaryAuth) {
    const crossHeaders = {
      ...headersNoAuth,
      authorization: secondaryAuth.startsWith('Bearer ')
        ? secondaryAuth
        : `Bearer ${secondaryAuth}`,
    };
    const crossResp = await safeFetch(
      tx.url,
      { method: tx.method ?? 'GET', headers: crossHeaders, standard: 'ASTF-ATHZ-02' },
      timeout
    );
    if (crossResp && crossResp.status >= 200 && crossResp.status < 300) {
      findings.push(finding({
        category: 'access',
        title: 'BFLA — Privileged endpoint accessible to unprivileged role',
        severity: 'high',
        url: tx.url,
        evidence: `${tx.method ?? 'GET'} ${tx.url} returned HTTP ${crossResp.status} with secondary (low-privilege) token. Administrative function accessible to unauthorized role. (OWASP API5 / WSTG-ATHZ-03 / ASTF-ATHZ-02)`,
      }, 'BFLA'));
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// CSRF check
// ---------------------------------------------------------------------------

export async function checkCsrf(url, timeout) {
  const resp = await safeFetch(url, { method: 'OPTIONS' }, timeout);
  const allow = resp?.headers.get('access-control-allow-methods') || '';
  if (/put|delete|post/i.test(allow)) {
    return finding({
      category: 'access',
      title: 'Potential CSRF risk',
      severity: 'medium',
      url,
      evidence: `CORS preflight allows state-changing methods: ${allow}`,
    }, 'CSRF');
  }
  return null;
}

// ---------------------------------------------------------------------------
// CORS check
// ---------------------------------------------------------------------------

export async function checkCors(url, timeout) {
  const resp = await safeFetch(url, { method: 'OPTIONS', headers: { Origin: 'https://attacker.example' } }, timeout);
  if (!resp) return null;
  const allowOrigin = resp.headers.get('access-control-allow-origin') || '';
  const allowCreds  = resp.headers.get('access-control-allow-credentials') || '';
  if (allowOrigin === '*' && allowCreds === 'true') {
    return finding({
      category: 'access',
      title: 'CORS misconfiguration',
      severity: 'high',
      url,
      evidence: `allow-origin: ${allowOrigin}, allow-credentials: ${allowCreds}`,
    }, 'CORS');
  }
  if (allowOrigin === 'https://attacker.example') {
    return finding({
      category: 'access',
      title: 'CORS reflects arbitrary Origin',
      severity: 'medium',
      url,
      evidence: `Server reflected an untrusted Origin back: ${allowOrigin}`,
    }, 'CORS');
  }
  return null;
}

// ---------------------------------------------------------------------------
// SSRF check
// ---------------------------------------------------------------------------

export async function checkSsrf(url, timeout) {
  let trial;
  try {
    trial = new URL(url);
    trial.searchParams.set('url', 'http://169.254.169.254/latest/meta-data/');
  } catch { return null; }
  const resp = await safeFetch(trial.toString(), {}, timeout);
  if (!resp || resp.status < 200 || resp.status >= 300) return null;
  const text = await resp.text().catch(() => '');
  if (text.toLowerCase().includes('meta-data') || text.toLowerCase().includes('ami-id')) {
    return finding({
      category: 'access',
      title: 'Potential SSRF vector',
      severity: 'high',
      url: trial.toString(),
      evidence: 'Endpoint fetched and returned cloud metadata content.',
    }, 'SSRF');
  }
  return null;
}

// ---------------------------------------------------------------------------
// Security headers check
// ---------------------------------------------------------------------------

export async function checkSecurityHeaders(url, timeout) {
  const resp = await safeFetch(url, {}, timeout);
  if (!resp) return null;
  const checks = {
    'Content-Security-Policy': 'content-security-policy',
    'Strict-Transport-Security': 'strict-transport-security',
    'X-Frame-Options': 'x-frame-options',
    'X-Content-Type-Options': 'x-content-type-options',
    'Referrer-Policy': 'referrer-policy',
  };
  const missing = Object.entries(checks).filter(([, h]) => !resp.headers.get(h)).map(([name]) => name);
  if (missing.length) {
    return finding({
      category: 'access',
      title: 'Missing security headers',
      severity: 'low',
      url,
      evidence: `Missing: ${missing.join(', ')}`,
    }, 'SECURITY_HEADERS');
  }
  return null;
}

// ---------------------------------------------------------------------------
// TRACE method / Cross-Site Tracing check
// ---------------------------------------------------------------------------

export async function checkTraceMethod(url, timeout) {
  const resp = await safeFetch(url, { method: 'TRACE' }, timeout);
  if (!resp || resp.status !== 200) return null;
  const text = await resp.text().catch(() => '');
  if (text.toUpperCase().includes('TRACE')) {
    return finding({
      category: 'access',
      title: 'TRACE method enabled (Cross-Site Tracing risk)',
      severity: 'medium',
      url,
      evidence: 'Server responded 200 to a TRACE request and echoed the request back. Disable TRACE to prevent XST attacks.',
    }, 'XST');
  }
  return null;
}

// ---------------------------------------------------------------------------
// Host header injection check
// ---------------------------------------------------------------------------

export async function checkHostHeaderInjection(url, timeout) {
  const resp = await safeFetch(url, {
    headers: { Host: 'evil.boltclone-probe.internal' },
  }, timeout);
  if (!resp) return null;
  const text = await resp.text().catch(() => '');
  if (text.includes('evil.boltclone-probe.internal')) {
    return finding({
      category: 'access',
      title: 'Host header injection vulnerability',
      severity: 'high',
      url,
      evidence: 'Response body reflected the injected Host header. Exploitable for password-reset poisoning and cache poisoning.',
    }, 'HOST_INJECT');
  }
  return null;
}

// ---------------------------------------------------------------------------
// Stale API version check
// ---------------------------------------------------------------------------

export async function checkApiVersioning(url, timeout) {
  let base;
  try { base = new URL(url); } catch { return null; }
  const oldVersions = ['v0', 'v1', 'v2'].filter(
    (v) => !base.pathname.startsWith(`/${v}`) && !base.pathname.includes(`/${v}/`)
  );
  for (const ver of oldVersions.slice(0, 2)) {
    const trial = new URL(base);
    trial.pathname = `/${ver}${base.pathname}`;
    const resp = await safeFetch(trial.toString(), {}, timeout);
    if (resp && resp.status >= 200 && resp.status < 300) {
      return finding({
        category: 'access',
        title: 'Stale API version accessible',
        severity: 'medium',
        url: trial.toString(),
        evidence: `Older API version /${ver}/ responded with HTTP ${resp.status}. Legacy versions may lack current security patches.`,
      }, 'STALE_API');
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Aggregated runner
// ---------------------------------------------------------------------------

/**
 * Runs all access-control checks against a plain URL string.
 * For session-based dual-context checks use checkIdorBola(tx, timeout, opts)
 * and checkBfla(tx, timeout, secondaryAuth) directly from scan.js.
 *
 * @param {string} url
 * @param {number} timeout
 * @returns {Promise<object[]>}
 */
export async function runAccessChecks(url, timeout) {
  const results = await Promise.all([
    checkRateLimit(url, timeout),
    checkIdorBola(url, timeout),
    checkCsrf(url, timeout),
    checkCors(url, timeout),
    checkSsrf(url, timeout),
    checkSecurityHeaders(url, timeout),
    checkTraceMethod(url, timeout),
    checkHostHeaderInjection(url, timeout),
    checkApiVersioning(url, timeout),
  ]);
  // checkIdorBola can return an array (dual-context) or a single finding.
  return results.filter(Boolean).flat();
}
