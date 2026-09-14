import { safeFetch, timeoutFetch } from '../http.js';

export async function checkRateLimit(url, timeout) {
  const attempts = await Promise.all(
    Array.from({ length: 8 }, () => timeoutFetch(url, { method: 'GET' }, timeout).catch((e) => e))
  );
  const statuses = attempts.filter((r) => r instanceof Response).map((r) => r.status);
  if (statuses.length === 0) return null;
  if (!statuses.includes(429) && statuses.filter((s) => s >= 200 && s < 300).length > 5) {
    return { category: 'access', title: 'No rate-limiting detected', severity: 'medium', url, evidence: `8 rapid requests, statuses: ${statuses.join(', ')}` };
  }
  return null;
}

export async function checkIdorBola(url, timeout) {
  let target;
  try { target = new URL(url); } catch { return null; }
  const segments = target.pathname.split('/').filter(Boolean);
  const idx = segments.findIndex((s) => /^\d+$/.test(s));
  if (idx === -1) return null;

  const original = segments[idx];
  const alt = String(Number(original) + 1);
  const trial = new URL(target);
  trial.pathname = target.pathname.replace(`/${original}`, `/${alt}`);

  const [origResp, altResp] = await Promise.all([
    safeFetch(target.toString(), {}, timeout),
    safeFetch(trial.toString(), {}, timeout)
  ]);
  if (!origResp || origResp.status < 200 || origResp.status >= 300) return null;
  if (altResp && altResp.status >= 200 && altResp.status < 300) {
    return { category: 'access', title: 'Potential IDOR/BOLA', severity: 'high', url: trial.toString(), evidence: `Adjacent object id ${alt} accessible without authorization (status ${altResp.status})` };
  }
  return null;
}

export async function checkCsrf(url, timeout) {
  const resp = await safeFetch(url, { method: 'OPTIONS' }, timeout);
  const allow = resp?.headers.get('access-control-allow-methods') || '';
  if (/put|delete|post/i.test(allow)) {
    return { category: 'access', title: 'Potential CSRF risk', severity: 'medium', url, evidence: `CORS preflight allows state-changing methods: ${allow}` };
  }
  return null;
}

export async function checkCors(url, timeout) {
  const resp = await safeFetch(url, { method: 'OPTIONS', headers: { Origin: 'https://attacker.example' } }, timeout);
  if (!resp) return null;
  const allowOrigin = resp.headers.get('access-control-allow-origin') || '';
  const allowCreds = resp.headers.get('access-control-allow-credentials') || '';
  if (allowOrigin === '*' && allowCreds === 'true') {
    return { category: 'access', title: 'CORS misconfiguration', severity: 'high', url, evidence: `allow-origin: ${allowOrigin}, allow-credentials: ${allowCreds}` };
  }
  if (allowOrigin === 'https://attacker.example') {
    return { category: 'access', title: 'CORS reflects arbitrary Origin', severity: 'medium', url, evidence: `Server reflected an untrusted Origin back: ${allowOrigin}` };
  }
  return null;
}

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
    return { category: 'access', title: 'Potential SSRF vector', severity: 'high', url: trial.toString(), evidence: 'Endpoint fetched and returned cloud metadata content.' };
  }
  return null;
}

export async function checkSecurityHeaders(url, timeout) {
  const resp = await safeFetch(url, {}, timeout);
  if (!resp) return null;
  const checks = {
    'Content-Security-Policy': 'content-security-policy',
    'Strict-Transport-Security': 'strict-transport-security',
    'X-Frame-Options': 'x-frame-options',
    'X-Content-Type-Options': 'x-content-type-options',
    'Referrer-Policy': 'referrer-policy'
  };
  const missing = Object.entries(checks).filter(([, h]) => !resp.headers.get(h)).map(([name]) => name);
  if (missing.length) {
    return { category: 'access', title: 'Missing security headers', severity: 'low', url, evidence: `Missing: ${missing.join(', ')}` };
  }
  return null;
}

export async function checkTraceMethod(url, timeout) {
  const resp = await safeFetch(url, { method: 'TRACE' }, timeout);
  if (!resp || resp.status !== 200) return null;
  const text = await resp.text().catch(() => '');
  if (text.toUpperCase().includes('TRACE')) {
    return {
      category: 'access',
      title: 'TRACE method enabled (Cross-Site Tracing risk)',
      severity: 'medium',
      url,
      evidence: 'Server responded 200 to a TRACE request and echoed the request back. Disable TRACE to prevent XST attacks.'
    };
  }
  return null;
}

export async function checkHostHeaderInjection(url, timeout) {
  const resp = await safeFetch(url, {
    headers: { Host: 'evil.boltclone-probe.internal' }
  }, timeout);
  if (!resp) return null;
  const text = await resp.text().catch(() => '');
  if (text.includes('evil.boltclone-probe.internal')) {
    return {
      category: 'access',
      title: 'Host header injection vulnerability',
      severity: 'high',
      url,
      evidence: 'Response body reflected the injected Host header. Exploitable for password-reset poisoning and cache poisoning.'
    };
  }
  return null;
}

export async function checkApiVersioning(url, timeout) {
  let base;
  try { base = new URL(url); } catch { return null; }
  // Only attempt if the path has at least one segment to prepend a version to
  const oldVersions = ['v0', 'v1', 'v2'].filter(
    (v) => !base.pathname.startsWith(`/${v}`) && !base.pathname.includes(`/${v}/`)
  );
  for (const ver of oldVersions.slice(0, 2)) {
    const trial = new URL(base);
    trial.pathname = `/${ver}${base.pathname}`;
    const resp = await safeFetch(trial.toString(), {}, timeout);
    if (resp && resp.status >= 200 && resp.status < 300) {
      return {
        category: 'access',
        title: 'Stale API version accessible',
        severity: 'medium',
        url: trial.toString(),
        evidence: `Older API version /${ver}/ responded with HTTP ${resp.status}. Legacy versions may lack current security patches.`
      };
    }
  }
  return null;
}

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
    checkApiVersioning(url, timeout)
  ]);
  return results.filter(Boolean);
}
