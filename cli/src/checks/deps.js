import { safeFetch, pool } from '../http.js';

const LIB_PATTERNS = [
  { name: 'jquery', re: /jquery[.-](\d+\.\d+\.\d+)/i },
  { name: 'bootstrap', re: /bootstrap[.@-](\d+\.\d+\.\d+)/i },
  { name: 'angular', re: /angular(?:js)?[.@-](\d+\.\d+\.\d+)/i },
  { name: 'vue', re: /vue(?:\.js)?[.@-](\d+\.\d+\.\d+)/i },
  { name: 'react', re: /react(?:-dom)?[.@-](\d+\.\d+\.\d+)/i },
  { name: 'lodash', re: /lodash[.@-](\d+\.\d+\.\d+)/i },
  { name: 'moment', re: /moment[.@-](\d+\.\d+\.\d+)/i },
  { name: 'handlebars', re: /handlebars[.@-](\d+\.\d+\.\d+)/i },
  { name: 'ember-source', re: /ember[.@-](\d+\.\d+\.\d+)/i },
  { name: 'backbone', re: /backbone[.@-](\d+\.\d+\.\d+)/i }
];

const BANNER_PATTERNS = [
  { name: 'jquery', re: /jquery\s+v?(\d+\.\d+\.\d+)/i },
  { name: 'bootstrap', re: /bootstrap\s+v?(\d+\.\d+\.\d+)/i },
  { name: 'angular', re: /angularjs\s+v?(\d+\.\d+\.\d+)/i },
  { name: 'vue', re: /vue\.js\s+v?(\d+\.\d+\.\d+)/i }
];

function detectFromString(str, patterns) {
  const hits = [];
  for (const { name, re } of patterns) {
    const m = str.match(re);
    if (m) hits.push({ name, version: m[1] });
  }
  return hits;
}

async function fingerprintLibraries(baseUrl, timeout) {
  const resp = await safeFetch(baseUrl, {}, timeout);
  if (!resp) return { libs: [], headers: {} };

  const html = await resp.text().catch(() => '');
  const headers = {
    server: resp.headers.get('server'),
    poweredBy: resp.headers.get('x-powered-by')
  };

  const found = new Map();
  detectFromString(html, LIB_PATTERNS).forEach((h) => found.set(h.name, h.version));

  const scriptSrcs = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)]
    .map((m) => m[1])
    .slice(0, 25);

  detectFromString(scriptSrcs.join('\n'), LIB_PATTERNS).forEach((h) => {
    if (!found.has(h.name)) found.set(h.name, h.version);
  });

  // For scripts without a version in the URL, fetch a small prefix and look for banner comments.
  const unresolvedSrcs = scriptSrcs.filter((src) => detectFromString(src, LIB_PATTERNS).length === 0).slice(0, 8);
  await pool(unresolvedSrcs, 4, async (src) => {
    let url;
    try { url = new URL(src, baseUrl).toString(); } catch { return; }
    const r = await safeFetch(url, {}, timeout);
    if (!r) return;
    const text = await r.text().catch(() => '');
    detectFromString(text.slice(0, 2000), BANNER_PATTERNS).forEach((h) => {
      if (!found.has(h.name)) found.set(h.name, h.version);
    });
  });

  return { libs: Array.from(found.entries()).map(([name, version]) => ({ name, version })), headers };
}

async function queryOsv(libs, timeout) {
  if (libs.length === 0) return new Map();

  const body = {
    queries: libs.map((lib) => ({
      version: lib.version,
      package: { name: lib.name, ecosystem: 'npm' }
    }))
  };

  const resp = await safeFetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }, Math.max(timeout, 10000));

  if (!resp) return new Map();
  const data = await resp.json().catch(() => null);
  if (!data?.results) return new Map();

  const byLib = new Map();
  data.results.forEach((result, i) => {
    const vulns = result.vulns || [];
    if (vulns.length) byLib.set(libs[i].name, vulns.map((v) => v.id));
  });
  return byLib;
}

export async function runDependencyChecks(baseUrl, timeout) {
  const findings = [];
  const { libs, headers } = await fingerprintLibraries(baseUrl, timeout);

  if (headers.server) {
    findings.push({ category: 'deps', title: 'Server header discloses software/version', severity: 'low', url: baseUrl, evidence: `Server: ${headers.server}` });
  }
  if (headers.poweredBy) {
    findings.push({ category: 'deps', title: 'X-Powered-By header discloses technology', severity: 'low', url: baseUrl, evidence: `X-Powered-By: ${headers.poweredBy}` });
  }

  if (libs.length) {
    const vulnMap = await queryOsv(libs, timeout);
    libs.forEach((lib) => {
      const vulnIds = vulnMap.get(lib.name);
      if (vulnIds?.length) {
        findings.push({
          category: 'deps',
          title: `Known-vulnerable dependency: ${lib.name}@${lib.version}`,
          severity: 'high',
          url: baseUrl,
          evidence: `OSV advisories: ${vulnIds.slice(0, 5).join(', ')}${vulnIds.length > 5 ? ` (+${vulnIds.length - 5} more)` : ''}`
        });
      } else {
        findings.push({
          category: 'deps',
          title: `Detected dependency: ${lib.name}@${lib.version}`,
          severity: 'info',
          url: baseUrl,
          evidence: 'No known OSV advisories at time of scan.'
        });
      }
    });
  }

  return findings;
}
