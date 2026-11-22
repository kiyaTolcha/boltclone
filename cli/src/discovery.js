import { safeFetch, pool } from './http.js';
import { createHash } from 'node:crypto';

const COMMON_PATHS = [
  '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
  '/health', '/status', '/version', '/.well-known/security.txt',
  '/login', '/admin', '/robots.txt', '/sitemap.xml',
  '/openapi.json', '/swagger.json', '/swagger-ui', '/.env', '/.git/config'
];

/**
 * Fetches the root page (following redirects) and returns a body fingerprint
 * for SPA catch-all detection. Returns { hash } or null on failure.
 */
async function getRootFingerprint(baseUrl, timeout) {
  const resp = await safeFetch(baseUrl, { method: 'GET' }, timeout);
  if (!resp) return null;
  const ct = (resp.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('text/html')) return null;
  const text = await resp.text().catch(() => '');
  const hash = createHash('md5').update(text.slice(0, 4096)).digest('hex');
  return { hash };
}

/**
 * Paths that should NEVER legitimately return HTML from an API or file server.
 * When these return text/html with a body matching the root shell, they are
 * SPA catch-all responses — not real endpoints.
 */
const NEVER_HTML_PATHS = new Set([
  '/.env', '/.git/config', '/openapi.json', '/swagger.json',
  '/sitemap.xml', '/robots.txt', '/health', '/status', '/version',
  '/.well-known/security.txt'
]);

/**
 * Returns true when an endpoint is a SPA catch-all false-positive.
 * Requires ALL of:
 *   1. Response is text/html
 *   2. Path is in the NEVER_HTML_PATHS set
 *   3. Body fingerprint matches the root page (same SPA shell)
 */
function isSpaFallback(ct, bodyHash, rootFingerprint, path) {
  if (!rootFingerprint) return false;
  if (!ct.includes('text/html')) return false;
  if (!NEVER_HTML_PATHS.has(path)) return false;
  return bodyHash === rootFingerprint.hash;
}

export async function discoverEndpoints(baseUrl, { concurrency, timeout }) {
  const found = [];

  // Fingerprint root once (following redirects) for catch-all detection.
  const rootFingerprint = await getRootFingerprint(baseUrl, timeout);

  await pool(COMMON_PATHS, concurrency, async (path) => {
    const url = new URL(path, baseUrl).toString();
    // Follow redirects so we see the final response (not a Heroku HTTP→HTTPS 302).
    const resp = await safeFetch(url, { method: 'GET' }, timeout);
    if (!resp || resp.status >= 400) return;

    const ct = (resp.headers.get('content-type') || '').toLowerCase();
    const text = await resp.text().catch(() => '');
    const bodyHash = createHash('md5').update(text.slice(0, 4096)).digest('hex');

    if (isSpaFallback(ct, bodyHash, rootFingerprint, path)) return;

    found.push({ path, url, status: resp.status });
  });

  const robots = found.find((f) => f.path === '/robots.txt');
  if (robots) {
    const resp = await safeFetch(robots.url, {}, timeout);
    if (resp) {
      const text = await resp.text().catch(() => '');
      const paths = [...text.matchAll(/^(?:Allow|Disallow):\s*(\S+)/gim)]
        .map((m) => m[1])
        .filter((p) => p && p !== '/' && !found.some((f) => f.path === p));
      await pool(paths.slice(0, 30), concurrency, async (path) => {
        const url = new URL(path, baseUrl).toString();
        const r = await safeFetch(url, { method: 'GET' }, timeout);
        if (!r || r.status >= 400) return;
        const rct = (r.headers.get('content-type') || '').toLowerCase();
        const rt = await r.text().catch(() => '');
        const rh = createHash('md5').update(rt.slice(0, 4096)).digest('hex');
        if (!isSpaFallback(rct, rh, rootFingerprint, path)) {
          found.push({ path, url, status: r.status });
        }
      });
    }
  }

  const sitemap = found.find((f) => f.path === '/sitemap.xml');
  if (sitemap) {
    const resp = await safeFetch(sitemap.url, {}, timeout);
    if (resp) {
      const text = await resp.text().catch(() => '');
      const locs = [...text.matchAll(/<loc>([^<]+)<\/loc>/gi)].map((m) => m[1]).slice(0, 30);
      locs.forEach((loc) => {
        try {
          const u = new URL(loc);
          if (!found.some((f) => f.url === u.toString())) {
            found.push({ path: u.pathname, url: u.toString(), status: null });
          }
        } catch { /* ignore malformed loc */ }
      });
    }
  }

  return found;
}

export async function enumerateSubdomains(hostname, { timeout }) {
  const resp = await safeFetch(
    `https://crt.sh/?q=%25.${encodeURIComponent(hostname)}&output=json`,
    {},
    Math.max(timeout, 15000)
  );
  if (!resp) return [];

  const data = await resp.json().catch(() => null);
  if (!Array.isArray(data)) return [];

  const names = new Set();
  data.forEach((row) => {
    (row.name_value || '').split('\n').forEach((n) => {
      const clean = n.trim().toLowerCase().replace(/^\*\./, '');
      if (clean && clean.endsWith(hostname.toLowerCase())) names.add(clean);
    });
  });

  return Array.from(names).sort();
}
