import { safeFetch, pool } from './http.js';

const COMMON_PATHS = [
  '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
  '/health', '/status', '/version', '/.well-known/security.txt',
  '/login', '/admin', '/robots.txt', '/sitemap.xml',
  '/openapi.json', '/swagger.json', '/swagger-ui', '/.env', '/.git/config'
];

export async function discoverEndpoints(baseUrl, { concurrency, timeout }) {
  const found = [];

  await pool(COMMON_PATHS, concurrency, async (path) => {
    const url = new URL(path, baseUrl).toString();
    const resp = await safeFetch(url, { method: 'GET', redirect: 'manual' }, timeout);
    if (resp && resp.status < 400) {
      found.push({ path, url, status: resp.status });
    }
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
        if (r && r.status < 400) found.push({ path, url, status: r.status });
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
