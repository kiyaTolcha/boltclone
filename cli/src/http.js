/**
 * http.js - Hardened HTTP transport layer
 *
 * Provides:
 *   - timeoutFetch / safeFetch: abort-controller-wrapped native fetch.
 *   - createRateLimiter(rps): token-bucket dispatch gate (default 15 QPS).
 *   - pool(items, limit, worker): bounded-concurrency async pool.
 *
 * Every request dispatched through timeoutFetch automatically carries:
 *   X-Bolt-Test-Run:    <per-session UUID>   (APM isolation)
 *   X-Synthetic-Test:   true
 *   X-Bolt-Standard:    <opts.standard>      (optional taxonomy tag)
 *   User-Agent:         BOLTCLONE-SecurityScanner/1.0.0
 *
 * Responses with gzip or br content-encoding are transparently decompressed
 * using Node.js built-in zlib streams before the body is returned.
 */

'use strict';

import { randomUUID } from 'node:crypto';
import zlib from 'node:zlib';
import { Readable } from 'node:stream';

// A single UUID shared across the entire CLI process invocation so that all
// requests in one scan can be correlated in backend APM / access logs.
const SESSION_RUN_ID = randomUUID();

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

/**
 * Creates a token-bucket rate limiter that ensures at most `rps` requests per
 * second are dispatched. Returns a function that, when called, returns a
 * Promise that resolves when a token is available.
 *
 * Usage:
 *   const throttle = createRateLimiter(15);
 *   await throttle();
 *   const resp = await fetch(url);
 *
 * @param {number} rps  Maximum requests per second (default 15).
 * @returns {() => Promise<void>}
 */
export function createRateLimiter(rps = 15) {
  const intervalMs = 1000 / rps;
  let lastDispatch = 0;

  return function throttle() {
    return new Promise((resolve) => {
      const now = Date.now();
      const sinceLastMs = now - lastDispatch;
      const waitMs = Math.max(0, intervalMs - sinceLastMs);
      lastDispatch = now + waitMs;
      if (waitMs === 0) {
        resolve();
      } else {
        setTimeout(resolve, waitMs);
      }
    });
  };
}

// Module-level default throttle (15 QPS). Callers that need a different rate
// create their own limiter via createRateLimiter() and pass it in opts.
let _defaultThrottle = createRateLimiter(15);

/**
 * Reconfigures the module-level default rate limiter.
 * Called by the CLI orchestrator when --rate-limit is provided.
 *
 * @param {number} rps
 */
export function setDefaultRateLimit(rps) {
  _defaultThrottle = createRateLimiter(rps);
}

// ---------------------------------------------------------------------------
// Decompression helper
// ---------------------------------------------------------------------------

/**
 * Decompresses a fetch Response body if the content-encoding is gzip or br.
 * Returns a new Response with the decoded body and without the
 * content-encoding header so callers can call .text() / .json() normally.
 *
 * For uncompressed responses the original Response is returned unchanged.
 *
 * @param {Response} resp
 * @returns {Promise<Response>}
 */
async function decompressResponse(resp) {
  const encoding = (resp.headers.get('content-encoding') ?? '').toLowerCase().trim();
  if (encoding !== 'gzip' && encoding !== 'br' && encoding !== 'deflate') {
    return resp;
  }

  // Read raw bytes from the response body.
  const arrayBuffer = await resp.arrayBuffer();
  const inputBuffer = Buffer.from(arrayBuffer);

  // Decompress synchronously via zlib.
  let decompressed;
  try {
    if (encoding === 'gzip') {
      decompressed = zlib.gunzipSync(inputBuffer);
    } else if (encoding === 'br') {
      decompressed = zlib.brotliDecompressSync(inputBuffer);
    } else {
      // deflate
      decompressed = zlib.inflateSync(inputBuffer);
    }
  } catch {
    // If decompression fails, return the original (body is already consumed so
    // we reconstruct a minimal response with the raw bytes as text).
    return new Response(inputBuffer, {
      status: resp.status,
      statusText: resp.statusText,
      headers: resp.headers,
    });
  }

  // Build a new Headers map without content-encoding to prevent downstream
  // double-decompression attempts.
  const newHeaders = new Headers(resp.headers);
  newHeaders.delete('content-encoding');
  newHeaders.delete('content-length'); // length has changed post-decompression

  return new Response(decompressed, {
    status: resp.status,
    statusText: resp.statusText,
    headers: newHeaders,
  });
}

// ---------------------------------------------------------------------------
// Core fetch wrappers
// ---------------------------------------------------------------------------

/**
 * Wraps native fetch with:
 *   - AbortController timeout (default 8 s).
 *   - Automatic injection of scanner identification headers.
 *   - Rate-limiter gate (uses module default unless opts.throttle is provided).
 *   - Transparent response decompression.
 *
 * @param {string}  url
 * @param {object}  [opts={}]             fetch init options.
 * @param {number}  [timeoutMs=8000]      Hard abort timeout in milliseconds.
 * @param {object}  [opts.standard]       OWASP taxonomy tag (e.g. 'WSTG-ATHZ-02').
 * @param {Function}[opts.throttle]       Custom rate-limiter; overrides module default.
 * @returns {Promise<Response>}
 */
export async function timeoutFetch(url, opts = {}, timeoutMs = 8000) {
  // Apply rate limiting before dispatch.
  const throttle = opts.throttle ?? _defaultThrottle;
  await throttle();

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  // Merge scanner identification headers with caller-supplied headers.
  // Caller headers take precedence over defaults (but we always set the
  // bolt-specific headers so they cannot be accidentally omitted).
  const callerHeaders = opts.headers ?? {};
  const mergedHeaders = {
    'User-Agent': 'BOLTCLONE-SecurityScanner/1.0.0',
    // Merge caller headers before bolt headers so bolt headers always win.
    ...(typeof callerHeaders === 'object' && !Array.isArray(callerHeaders)
      ? callerHeaders
      : Object.fromEntries(new Headers(callerHeaders).entries())),
    // Synthetic traffic classification — always overwrite.
    'X-Bolt-Test-Run': SESSION_RUN_ID,
    'X-Synthetic-Test': 'true',
    ...(opts.standard ? { 'X-Bolt-Standard': opts.standard } : {}),
  };

  // Strip internal opts fields that fetch() does not understand.
  const { throttle: _t, standard: _s, ...fetchOpts } = opts;

  let resp;
  try {
    resp = await fetch(url, {
      ...fetchOpts,
      headers: mergedHeaders,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  // Transparently decompress before returning.
  return decompressResponse(resp);
}

/**
 * safeFetch — like timeoutFetch but swallows all errors and returns null.
 * Use when a failure to reach an endpoint should be treated as "no finding"
 * rather than a thrown exception.
 *
 * @param {string}  url
 * @param {object}  [opts={}]
 * @param {number}  [timeoutMs=8000]
 * @returns {Promise<Response|null>}
 */
export async function safeFetch(url, opts = {}, timeoutMs = 8000) {
  try {
    return await timeoutFetch(url, opts, timeoutMs);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Concurrency pool
// ---------------------------------------------------------------------------

/**
 * Bounded-concurrency pool: runs `worker` over `items` with at most `limit`
 * in-flight at once.
 *
 * @template T, R
 * @param {T[]}                          items
 * @param {number}                       limit
 * @param {(item: T, index: number) => Promise<R>} worker
 * @returns {Promise<R[]>}
 */
export async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;

  async function runner() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  }

  const runners = Array.from({ length: Math.min(limit, items.length) }, runner);
  await Promise.all(runners);
  return results;
}

/**
 * Exposes the current session run ID for use in test assertions.
 * @returns {string}
 */
export function getSessionRunId() {
  return SESSION_RUN_ID;
}
