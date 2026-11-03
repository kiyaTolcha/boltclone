/**
 * bopla.js - BOPLA (Broken Object Property Level Authorization) Check Suite
 *
 * Implements property-level authorization security checks covering:
 *
 *   checkExcessiveDataExposure(tx, responseBody)
 *     Scans response JSON bodies for sensitive PII / secret fields that
 *     should never leave the server boundary.
 *     → OWASP API3 (Broken Object Property Level Auth) / WSTG-INFO-05
 *
 *   checkMassAssignment(tx, timeout, allowMutating)
 *     Injects administrative property overrides into JSON request bodies and
 *     checks whether the server reflects them back in the response.
 *     → OWASP API3 / WSTG-BUSL-07 / ASTF-ATHZ-03
 *
 *   runBoplaChecks(tx, timeout, options)
 *     Aggregates both checks into a single call for use by scan.js.
 *
 * Standards taxonomy:
 *   owaspWeb: A03 (Injection via property abuse)
 *   owaspApi: API3 (Broken Object Property Level Authorization)
 *   wstg:     WSTG-INFO-05 (exposure) / WSTG-BUSL-07 (mass assignment)
 *   astf:     ASTF-ATHZ-03
 */

'use strict';

import { safeFetch } from '../http.js';

// ---------------------------------------------------------------------------
// Standard taxonomy tags
// ---------------------------------------------------------------------------

const STANDARDS = {
  EXCESSIVE_EXPOSURE: {
    owaspWeb: 'A03',
    owaspApi: 'API3',
    wstg:     'WSTG-INFO-05',
    astf:     'ASTF-ATHZ-03',
  },
  MASS_ASSIGNMENT: {
    owaspWeb: 'A03',
    owaspApi: 'API3',
    wstg:     'WSTG-BUSL-07',
    astf:     'ASTF-ATHZ-03',
  },
};

function finding(base, stdKey) {
  return { ...base, standards: STANDARDS[stdKey] };
}

// ---------------------------------------------------------------------------
// Sensitive field registry
// ---------------------------------------------------------------------------

// Exact key names (case-insensitive) that should never appear in a response body
// exposed to the client. Any match is flagged as an over-exposure finding.
const SENSITIVE_KEYS = new Set([
  // Credential / auth secrets
  'password',
  'password_hash',
  'passwd',
  'hashed_password',
  'secret',
  'secret_key',
  'secret_token',
  'api_key',
  'apikey',
  'api_secret',
  'access_token',
  'refresh_token',
  'private_key',
  'signing_key',
  'encryption_key',
  'token_secret',
  // Personal identifiers
  'ssn',
  'social_security_number',
  'national_id',
  'passport_number',
  'drivers_license',
  'tax_id',
  // Financial data
  'credit_card',
  'card_number',
  'cvv',
  'ccv',
  'card_cvv',
  'account_number',
  'bank_account',
  'routing_number',
  'iban',
  // Health / legal
  'medical_record',
  'diagnosis',
  'health_insurance_id',
  // Internal infra
  'database_password',
  'db_password',
  'db_pass',
  'smtp_password',
  'aws_secret',
  'gcp_key',
  'azure_secret',
]);

// Regex patterns applied to string values in the response body to catch
// patterns like actual credit card numbers, JWT tokens, or SSH private keys
// that may be stored under innocuously-named keys.
const SENSITIVE_VALUE_PATTERNS = [
  { name: 'SSH private key',    re: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'JWT token',          re: /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/ },
  { name: 'AWS access key',     re: /AKIA[0-9A-Z]{16}/ },
  { name: 'Generic secret hex', re: /^[0-9a-f]{64}$/i },
];

// ---------------------------------------------------------------------------
// Mass assignment probe payloads
// ---------------------------------------------------------------------------

// Property overrides injected alongside the existing request body.
// Each entry is { key, value, description }.
const MASS_ASSIGN_PAYLOADS = [
  { key: 'isAdmin',    value: true,    description: 'admin flag elevation' },
  { key: 'role',       value: 'admin', description: 'role escalation to admin' },
  { key: 'verified',   value: true,    description: 'account verification bypass' },
  { key: 'active',     value: true,    description: 'account activation bypass' },
  { key: 'banned',     value: false,   description: 'ban bypass' },
  { key: 'premium',    value: true,    description: 'subscription tier escalation' },
  { key: 'credits',    value: 99999,   description: 'credit balance manipulation' },
  { key: 'price',      value: 0,       description: 'price zeroing' },
  { key: 'discount',   value: 100,     description: 'full discount injection' },
  { key: 'userType',   value: 'admin', description: 'user type escalation' },
  { key: 'permissions', value: ['*'],  description: 'wildcard permission grant' },
];

// ---------------------------------------------------------------------------
// Helper: flatten JSON object keys (top-level only, case-insensitive lookup)
// ---------------------------------------------------------------------------

/**
 * Recursively collects all leaf key names from a JSON object/array up to
 * `maxDepth` levels. Used for response scanning.
 *
 * @param {*}      obj
 * @param {number} [maxDepth=3]
 * @param {number} [currentDepth=0]
 * @returns {string[]}
 */
function collectKeys(obj, maxDepth = 3, currentDepth = 0) {
  if (!obj || typeof obj !== 'object' || currentDepth > maxDepth) return [];
  const keys = [];
  for (const [k, v] of Object.entries(Array.isArray(obj) ? Object.fromEntries(obj.entries()) : obj)) {
    keys.push(k);
    if (v && typeof v === 'object') {
      keys.push(...collectKeys(v, maxDepth, currentDepth + 1));
    }
  }
  return keys;
}

/**
 * Recursively collects all scalar string values from a JSON object up to
 * `maxDepth` levels. Used for value-pattern scanning.
 *
 * @param {*}      obj
 * @param {number} [maxDepth=3]
 * @param {number} [currentDepth=0]
 * @returns {Array<{key: string, value: string}>}
 */
function collectStringValues(obj, maxDepth = 3, currentDepth = 0) {
  if (!obj || typeof obj !== 'object' || currentDepth > maxDepth) return [];
  const entries = [];
  const items = Array.isArray(obj) ? obj.slice(0, 10) : Object.entries(obj);
  for (const item of (Array.isArray(obj) ? items.entries() : items)) {
    const [k, v] = Array.isArray(item) ? item : item;
    if (typeof v === 'string') {
      entries.push({ key: String(k), value: v });
    } else if (v && typeof v === 'object') {
      entries.push(...collectStringValues(v, maxDepth, currentDepth + 1));
    }
  }
  return entries;
}

// ---------------------------------------------------------------------------
// Check 1: Excessive Data Exposure (OWASP API3 / WSTG-INFO-05)
// ---------------------------------------------------------------------------

/**
 * Scans a decoded response body for sensitive field names and value patterns
 * that indicate over-exposure of internal data.
 *
 * This is a passive check — it does not make any network calls.
 * It is called from scan.js after a response has been received.
 *
 * @param {TransactionDTO} tx           The transaction that produced this response.
 * @param {*}              responseBody Decoded JSON body (object/array), or null.
 * @returns {object[]}                  Array of findings (may be empty).
 */
export function checkExcessiveDataExposure(tx, responseBody) {
  if (!responseBody || typeof responseBody !== 'object') return [];

  const results = [];

  // --- Key name scan ---
  const allKeys = collectKeys(responseBody);
  const hitKeys = allKeys.filter((k) => SENSITIVE_KEYS.has(k.toLowerCase()));
  const uniqueHitKeys = [...new Set(hitKeys)];

  if (uniqueHitKeys.length > 0) {
    results.push(finding({
      category: 'bopla',
      title: 'Excessive Data Exposure — sensitive fields in response',
      severity: 'high',
      url: tx.url,
      evidence: `Response body contains sensitive field(s): [${uniqueHitKeys.join(', ')}]. These fields must be filtered server-side before serialization. (OWASP API3 / WSTG-INFO-05)`,
    }, 'EXCESSIVE_EXPOSURE'));
  }

  // --- Value pattern scan ---
  const stringValues = collectStringValues(responseBody);
  for (const { key, value } of stringValues) {
    for (const { name, re } of SENSITIVE_VALUE_PATTERNS) {
      if (re.test(value)) {
        results.push(finding({
          category: 'bopla',
          title: `Excessive Data Exposure — ${name} value in response`,
          severity: 'high',
          url: tx.url,
          evidence: `Field "${key}" contains a value matching pattern for ${name}. Verify this is intentional and not a leak of internal credentials. (OWASP API3 / WSTG-INFO-05)`,
        }, 'EXCESSIVE_EXPOSURE'));
        break; // One finding per key is enough.
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// Check 2: Mass Assignment (OWASP API3 / WSTG-BUSL-07 / ASTF-ATHZ-03)
// ---------------------------------------------------------------------------

/**
 * Tests whether a JSON endpoint is vulnerable to mass assignment by injecting
 * administrative property overrides alongside the existing request body.
 *
 * For each payload in MASS_ASSIGN_PAYLOADS:
 *   1. Merges the injected key into a copy of the existing request body (or
 *      into a minimal `{}` if no body exists).
 *   2. Dispatches the mutated request with the original headers.
 *   3. If the server returns 200/201 and the response body contains the
 *      injected key with a matching or truthy value, flags mass assignment.
 *
 * Safe-by-default: skipped unless the transaction method is POST, PUT, or
 * PATCH AND `allowMutating` is true, OR the method is GET with a JSON body
 * (rare but possible in some APIs).
 *
 * @param {TransactionDTO} tx
 * @param {number}         timeout
 * @param {boolean}        [allowMutating=false]
 * @returns {Promise<object[]>}
 */
export async function checkMassAssignment(tx, timeout, allowMutating = false) {
  // Restrict to endpoints that actually accept and return JSON.
  const contentType = tx.headers?.['content-type'] ?? '';
  const acceptsJson = contentType.includes('application/json') || tx.bodyFormat === 'json';

  // Mass assignment requires us to send a mutated body — only POST/PUT/PATCH
  // carry request bodies in standard practice.
  const isWriteMethod = /^(POST|PUT|PATCH)$/i.test(tx.method);
  if (!isWriteMethod && !acceptsJson) return [];
  if (isWriteMethod && !allowMutating) return [];

  const findings = [];
  const baseBody = (tx.body && typeof tx.body === 'object' && !Array.isArray(tx.body))
    ? { ...tx.body }
    : {};

  for (const { key, value, description } of MASS_ASSIGN_PAYLOADS) {
    // Skip if this key is already present in the original payload — we
    // cannot tell if the server is reflecting our injection or pre-existing data.
    if (key in baseBody) continue;

    const mutatedBody = { ...baseBody, [key]: value };

    const resp = await safeFetch(tx.url, {
      method: tx.method,
      headers: {
        ...tx.headers,
        'content-type': 'application/json',
      },
      body: JSON.stringify(mutatedBody),
      standard: 'WSTG-BUSL-07',
    }, timeout);

    if (!resp || (resp.status !== 200 && resp.status !== 201)) continue;

    let responseBody;
    try { responseBody = await resp.json(); } catch { continue; }

    // Confirm reflection: the injected key appears in the response with the
    // expected value (or a truthy value for boolean injections).
    if (responseBody && typeof responseBody === 'object' && key in responseBody) {
      const reflected = responseBody[key];
      const isReflected = reflected === value
        || (typeof value === 'boolean' && Boolean(reflected) === value)
        || (typeof value === 'string' && String(reflected).toLowerCase() === value.toLowerCase());

      if (isReflected) {
        findings.push(finding({
          category: 'bopla',
          title: 'Mass Assignment — injected property accepted by server',
          severity: 'high',
          url: tx.url,
          evidence: `Injected "${key}": ${JSON.stringify(value)} (${description}). Server responded HTTP ${resp.status} and reflected "${key}": ${JSON.stringify(reflected)} in the response body. The server is binding all request properties without a field allowlist. (OWASP API3 / WSTG-BUSL-07 / ASTF-ATHZ-03)`,
        }, 'MASS_ASSIGNMENT'));
        // One confirmed mass-assignment finding per endpoint is sufficient.
        break;
      }
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Aggregated runner
// ---------------------------------------------------------------------------

/**
 * Aggregates both BOPLA checks for a single TransactionDTO.
 *
 * @param {TransactionDTO} tx
 * @param {number}         timeout
 * @param {object}         [options={}]
 * @param {boolean}        [options.allowMutating=false]
 * @param {*}              [options.responseBody]   Pre-fetched response body for passive check.
 * @returns {Promise<object[]>}
 */
export async function runBoplaChecks(tx, timeout, options = {}) {
  const { allowMutating = false, responseBody = null } = options;

  const results = [];

  // Passive: excessive data exposure (no network calls).
  if (responseBody !== null) {
    results.push(...checkExcessiveDataExposure(tx, responseBody));
  }

  // Active: mass assignment injection (network calls, gated by allowMutating).
  results.push(...await checkMassAssignment(tx, timeout, allowMutating));

  return results;
}

