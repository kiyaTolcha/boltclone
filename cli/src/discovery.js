import { safeFetch, pool } from './http.js';
import { createHash } from 'node:crypto';

const COMMON_PATHS = [
  '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
  '/health', '/status', '/version', '/.well-known/security.txt',
  '/login', '/admin', '/robots.txt', '/sitemap.xml',
  '/openapi.json', '/swagger.json', '/swagger-ui', '/.env', '/.git/config'
];

/**
 * Fetches the root page and returns a fingerprint used to detect SPA catch-all
 * responses. Returns { hash, contentType } where hash is an MD5-ish of the
 * first 4 KB of the body, or null on network failure.
 */
async function getRootFingerprint(baseUrl, timeout) {
  const resp = await safeFetch(baseUrl, { method: 'GET', redirect: 'manual' }, timeout);
  if (!resp) return null;
  const ct = (resp.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('text/html')) return null; // Non-HTML roots don't do SPA catch-all
  const text = await resp.text().catch(() => '');
  const hash = createHash('md5').update(text.slice(0, 4096)).digest('hex');
  return { hash, contentType: ct };
}

/**
 * Returns true when a discovered endpoint looks like a SPA catch-all:
 *   - Responds with text/html, AND
 *   - The first 4 KB of body hashes identically to the root page, OR
 *   - The status is 200 but content-type is text/html for a path like /.env or /.git/config
 *     that should never serve HTML.
 */
function isSpaFallback(resp, bodyHash, rootFingerprint, path) {
  if (!rootFingerprint) return false;
  const ct = (resp.headers.get('content-type') || '').toLowerCase();
  if (!ct.includes('text/html')) return false;

  // If body fingerprint matches root — it's the same catch-all page
  if (bodyHash && bodyHash === rootFingerprint.hash) return true;

  // Heuristic: paths that should NEVER serve HTML are almost certainly SPA fallbacks
  const neverHtmlPaths = ['/.env', '/.git/config', '/openapi.json', '/swagger.json',
    '/sitemap.xml', '/robots.txt', '/health', '/status', '/version'];
  if (neverHtmlPaths.some((p) => path === p || path.startsWith(p + '?'))) return true;

  return false;
}

export async function discoverEndpoints(baseUrl, { concurrency, timeout }) {
  const found = [];

  // Fingerprint root page once so we can detect SPA catch-all 200s
  const rootFingerprint = await getRootFingerprint(baseUrl, timeout);

  await pool(COMMON_PATHS, concurrency, async (path) => {
    const url = new URL(path, baseUrl).toString();
    const resp = await safeFetch(url, { method: 'GET', redirect: 'manual' }, timeout);
    if (!resp || resp.status >= 400) return;

    // Clone body for fingerprinting (body can only be consumed once)
    const text = await resp.text().catch(() => '');
    const bodyHash = createHash('md5').update(text.slice(0, 4096)).digest('hex');

    if (isSpaFallback(resp, bodyHash, rootFingerprint, path)) return; // Filter SPA catch-all

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
        const r = await safeFetch(url, { method: 'GET', redirect: 'manual' }, timeout);
        if (!r || r.status >= 400) return;
        const t = await r.text().catch(() => '');
        const bh = createHash('md5').update(t.slice(0, 4096)).digest('hex');
        if (!isSpaFallback(r, bh, rootFingerprint, path)) found.push({ path, url, status: r.status });
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
