/**
 * mutations.js - Mutation & Tampering Engine
 *
 * Provides three async generator functions that yield candidate mutation
 * objects from a canonical TransactionDTO without making any network calls.
 *
 * Safe-by-default policy (OWASP ASTF):
 *   - State-altering HTTP methods (POST, PUT, PATCH, DELETE) are skipped
 *     unless `allowMutating` is explicitly set to true.
 *   - Only GET, HEAD, and OPTIONS are replayed by default.
 *
 * Mutation object shape (all generators):
 * ```
 * {
 *   tx:             TransactionDTO,   // original, unmodified
 *   mutatedUrl:     string,
 *   mutatedBody:    object|string|null,
 *   mutatedHeaders: Record<string,string>,
 *   mutationType:   'IDOR'|'BFLA_UNAUTH'|'BFLA_CROSSTENANT'|'PARAM_FUZZ',
 *   mutationDetail: string,           // human-readable description of change
 * }
 * ```
 *
 * Standards coverage:
 *   IDOR mutations  → OWASP API1 / WSTG-ATHZ-02 / ASTF-ATHZ-01
 *   BFLA mutations  → OWASP API5 / WSTG-ATHZ-03 / ASTF-ATHZ-02
 *   Param fuzz      → OWASP API3 / WSTG-BUSL-07 / ASTF-INPT-01
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Regex patterns for ID detection in URL path segments.
const INTEGER_RE = /^\d+$/;
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Query-parameter key names commonly used as object IDs.
const ID_PARAM_KEYS = new Set([
  'id', 'user_id', 'userId', 'account_id', 'accountId',
  'order_id', 'orderId', 'product_id', 'productId',
  'resource_id', 'resourceId', 'item_id', 'itemId',
  'object_id', 'objectId', 'record_id', 'recordId',
  'profile_id', 'profileId', 'doc_id', 'docId',
]);

// Administrative path patterns that are candidates for BFLA testing.
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Returns true if the transaction's HTTP method is safe to replay without
 * explicit operator consent.
 *
 * @param {string} method
 * @returns {boolean}
 */
function isIdempotent(method) {
  return IDEMPOTENT_METHODS.has((method ?? 'GET').toUpperCase());
}

/**
 * Produces a deterministic "neighbour" UUID by flipping the last octet.
 * This keeps the UUID structurally valid (version 4, variant bits intact)
 * while producing a different object reference.
 *
 * @param {string} uuid
 * @returns {string}
 */
function neighbourUuid(uuid) {
  const parts = uuid.split('-');
  // Last group is 12 hex chars; increment by 1 mod 0xffffffffffff.
  const lastGroup = parts[4];
  const n = (BigInt(`0x${lastGroup}`) + 1n) % 0xffffffffffffn;
  parts[4] = n.toString(16).padStart(12, '0');
  return parts.join('-');
}

/**
 * Deeply clones a plain object/array/primitive (no symbols, no Dates).
 * Used to prevent accidental mutation of the original TransactionDTO.
 *
 * @param {*} val
 * @returns {*}
 */
function deepClone(val) {
  if (val === null || typeof val !== 'object') return val;
  if (Array.isArray(val)) return val.map(deepClone);
  return Object.fromEntries(Object.entries(val).map(([k, v]) => [k, deepClone(v)]));
}

/**
 * Injects fuzz payloads into all string-valued keys of a JSON object,
 * one key at a time, yielding a new mutated body per key×payload combination.
 *
 * Does not recurse into nested objects by design — top-level params only.
 *
 * @param {object} body      Decoded JSON body object.
 * @param {string[]} payloads Fuzz payload strings.
 * @yields {{ body: object, key: string, payload: string }}
 */
function* injectIntoJsonBody(body, payloads) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return;
  for (const [key, originalValue] of Object.entries(body)) {
    // Only inject into scalar string/number fields to avoid breaking type-strict APIs.
    if (typeof originalValue !== 'string' && typeof originalValue !== 'number') continue;
    for (const payload of payloads) {
      const mutated = deepClone(body);
      mutated[key] = payload;
      yield { body: mutated, key, payload };
    }
  }
}

// ---------------------------------------------------------------------------
// Generator 1: IDOR mutations (OWASP API1 / WSTG-ATHZ-02 / ASTF-ATHZ-01)
// ---------------------------------------------------------------------------

/**
 * Generates IDOR candidate mutations by detecting object IDs in path segments
 * and query parameters, then producing ±1 (integer) or neighbour (UUID) variants.
 *
 * Safe-by-default: non-idempotent methods are skipped unless allowMutating=true.
 *
 * @param {TransactionDTO} tx
 * @param {boolean} [allowMutating=false]
 * @yields {MutationObject}
 */
export function* generateIdorMutations(tx, allowMutating = false) {
  if (!isIdempotent(tx.method) && !allowMutating) return;

  let parsed;
  try { parsed = new URL(tx.url); } catch { return; }

  const segments = parsed.pathname.split('/').filter(Boolean);

  // --- Integer path segments ---
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (!INTEGER_RE.test(seg)) continue;

    const original = parseInt(seg, 10);
    const candidates = new Set([original + 1, original - 1].filter((n) => n >= 0));

    for (const alt of candidates) {
      const mutUrl = new URL(parsed);
      const segs = [...segments];
      segs[i] = String(alt);
      mutUrl.pathname = '/' + segs.join('/');

      yield {
        tx,
        mutatedUrl:     mutUrl.toString(),
        mutatedBody:    deepClone(tx.body),
        mutatedHeaders: { ...tx.headers },
        mutationType:   'IDOR',
        mutationDetail: `Integer path segment: ${seg} → ${alt}`,
      };
    }
  }

  // --- UUID v4 path segments ---
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (!UUID_V4_RE.test(seg)) continue;

    const altUuid = neighbourUuid(seg);
    const mutUrl = new URL(parsed);
    const segs = [...segments];
    segs[i] = altUuid;
    mutUrl.pathname = '/' + segs.join('/');

    yield {
      tx,
      mutatedUrl:     mutUrl.toString(),
      mutatedBody:    deepClone(tx.body),
      mutatedHeaders: { ...tx.headers },
      mutationType:   'IDOR',
      mutationDetail: `UUID path segment: ${seg} → ${altUuid}`,
    };
  }

  // --- Query parameter IDs ---
  for (const [key, value] of parsed.searchParams.entries()) {
    if (!ID_PARAM_KEYS.has(key)) continue;

    // Integer-looking query param value.
    if (INTEGER_RE.test(value)) {
      const original = parseInt(value, 10);
      for (const alt of [original + 1, original - 1].filter((n) => n >= 0)) {
        const mutUrl = new URL(parsed);
        mutUrl.searchParams.set(key, String(alt));
        yield {
          tx,
          mutatedUrl:     mutUrl.toString(),
          mutatedBody:    deepClone(tx.body),
          mutatedHeaders: { ...tx.headers },
          mutationType:   'IDOR',
          mutationDetail: `Query param ?${key}=${value} → ${alt}`,
        };
      }
    }

    // UUID-looking query param value.
    if (UUID_V4_RE.test(value)) {
      const altUuid = neighbourUuid(value);
      const mutUrl = new URL(parsed);
      mutUrl.searchParams.set(key, altUuid);
      yield {
        tx,
        mutatedUrl:     mutUrl.toString(),
        mutatedBody:    deepClone(tx.body),
        mutatedHeaders: { ...tx.headers },
        mutationType:   'IDOR',
        mutationDetail: `Query param ?${key}=${value} → ${altUuid}`,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Generator 2: BFLA mutations (OWASP API5 / WSTG-ATHZ-03 / ASTF-ATHZ-02)
// ---------------------------------------------------------------------------

/**
 * Generates Broken Function Level Authorization (BFLA) mutations for
 * privileged-looking endpoints by stripping auth (unauthenticated probe)
 * and substituting a cross-tenant token (privilege escalation probe).
 *
 * Requires a secondaryAuthToken to produce the cross-tenant mutation;
 * the unauthenticated mutation is always produced for privileged endpoints.
 *
 * Safe-by-default applies: write-verb endpoints skipped unless allowMutating=true.
 *
 * @param {TransactionDTO} tx
 * @param {string|null}    secondaryAuthToken  Bearer token for User B.
 * @param {boolean}        [allowMutating=false]
 * @yields {MutationObject}
 */
export function* generateBflaMutations(tx, secondaryAuthToken, allowMutating = false) {
  if (!isIdempotent(tx.method) && !allowMutating) return;

  // Only target endpoints that look like privileged admin/management routes.
  const isPrivileged = PRIVILEGED_PATH_PATTERNS.some((re) => re.test(tx.url));
  if (!isPrivileged) return;

  // Build header sets for the two BFLA mutation variants.
  const headersWithoutAuth = Object.fromEntries(
    Object.entries(tx.headers).filter(([k]) => k !== 'authorization' && k !== 'cookie')
  );

  // Mutation 1: Unauthenticated probe — drop all auth headers.
  yield {
    tx,
    mutatedUrl:     tx.url,
    mutatedBody:    deepClone(tx.body),
    mutatedHeaders: headersWithoutAuth,
    mutationType:   'BFLA_UNAUTH',
    mutationDetail: `Unauthenticated probe on privileged endpoint: ${tx.method} ${tx.url}`,
  };

  // Mutation 2: Cross-tenant probe — replace Authorization with secondary token.
  if (secondaryAuthToken) {
    const crossTenantHeaders = {
      ...headersWithoutAuth,
      authorization: secondaryAuthToken.startsWith('Bearer ')
        ? secondaryAuthToken
        : `Bearer ${secondaryAuthToken}`,
    };
    yield {
      tx,
      mutatedUrl:     tx.url,
      mutatedBody:    deepClone(tx.body),
      mutatedHeaders: crossTenantHeaders,
      mutationType:   'BFLA_CROSSTENANT',
      mutationDetail: `Cross-tenant probe (secondary auth) on: ${tx.method} ${tx.url}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Generator 3: Parameter fuzz mutations (OWASP API3 / WSTG-BUSL-07)
// ---------------------------------------------------------------------------

// Default fuzz payload library covering:
//   - SQLi entry points
//   - XSS reflection probes
//   - Path traversal
//   - SSTI detection
//   - Null/boundary values
export const DEFAULT_FUZZ_PAYLOADS = [
  // SQL injection probes
  "' OR '1'='1",
  "' OR 1=1--",
  "\" OR \"1\"=\"1",
  "1; DROP TABLE users--",
  // XSS probes
  '<script>alert(1)</script>',
  '"><img src=x onerror=alert(1)>',
  // Path traversal probes
  '../../../etc/passwd',
  '..\\..\\..\\windows\\win.ini',
  // SSTI probes
  '{{7*7}}',
  '${7*7}',
  // Null / boundary
  '',
  'null',
  '0',
  '-1',
  '999999999',
];

/**
 * Generates parameter fuzzing mutations for a transaction, injecting
 * each payload into:
 *   1. All query string parameters.
 *   2. All top-level keys of a JSON request body (if bodyFormat === 'json').
 *
 * Preserves overall request structure — never corrupts JSON syntax.
 * Safe-by-default: write-verb endpoints skipped unless allowMutating=true.
 *
 * @param {TransactionDTO} tx
 * @param {string[]}       [payloads]       Custom payload list; defaults to DEFAULT_FUZZ_PAYLOADS.
 * @param {boolean}        [allowMutating=false]
 * @yields {MutationObject}
 */
export function* generateParamMutations(tx, payloads = DEFAULT_FUZZ_PAYLOADS, allowMutating = false) {
  if (!isIdempotent(tx.method) && !allowMutating) return;

  let parsed;
  try { parsed = new URL(tx.url); } catch { return; }

  // --- Query string parameter injection ---
  for (const [key] of parsed.searchParams.entries()) {
    for (const payload of payloads) {
      const mutUrl = new URL(parsed);
      mutUrl.searchParams.set(key, payload);
      yield {
        tx,
        mutatedUrl:     mutUrl.toString(),
        mutatedBody:    deepClone(tx.body),
        mutatedHeaders: { ...tx.headers },
        mutationType:   'PARAM_FUZZ',
        mutationDetail: `Query param ?${key} → "${payload.slice(0, 40)}"`,
      };
    }
  }

  // --- JSON body key injection ---
  if (tx.bodyFormat === 'json' && tx.body && typeof tx.body === 'object') {
    for (const { body: mutBody, key, payload } of injectIntoJsonBody(tx.body, payloads)) {
      yield {
        tx,
        mutatedUrl:     parsed.toString(),
        mutatedBody:    mutBody,
        mutatedHeaders: { ...tx.headers },
        mutationType:   'PARAM_FUZZ',
        mutationDetail: `JSON body key "${key}" → "${payload.slice(0, 40)}"`,
      };
    }
  }
}

