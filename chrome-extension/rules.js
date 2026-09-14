function groupById(logEntries) {
  const byId = new Map();
  logEntries.forEach((entry) => {
    if (!entry.id) return;
    const existing = byId.get(entry.id) || {};
    byId.set(entry.id, { ...existing, ...entry });
  });
  return Array.from(byId.values());
}

function analyzeTraffic(logEntries) {
  const findings = [];
  const merged = groupById(logEntries);

  merged.forEach((entry) => {
    if (!entry.url) return;

    if (entry.url.includes('/api/') && entry.method === 'GET' && entry.statusCode >= 200 && entry.statusCode < 300) {
      const parts = new URL(entry.url).pathname.split('/').filter(Boolean);
      const idSegments = parts.filter((p) => /^\d+$/.test(p));
      if (idSegments.length) {
        findings.push({
          type: 'BOLA',
          severity: 'high',
          message: `Potential object enumeration via ID path in ${entry.method} ${entry.url}`,
          entry
        });
      }
    }
  });

  merged.forEach((entry) => {
    if (entry.requestHeaders?.some((h) => h.name.toLowerCase() === 'authorization')) {
      const role = entry.requestHeaders.find((h) => h.name.toLowerCase() === 'x-user-role');
      if (!role) {
        findings.push({ type: 'RBAC', severity: 'medium', message: `Missing role header when accessing ${entry.url}`, entry });
      }
    }
  });

  const massAssignCandidates = merged.filter((entry) => entry.method === 'POST' && entry.requestBody?.formData);
  massAssignCandidates.forEach((entry) => {
    const fields = Object.keys(entry.requestBody.formData || {});
    const dangerous = ['isAdmin', 'role', 'userType', 'permissions'];
    if (fields.some((f) => dangerous.includes(f))) {
      findings.push({ type: 'MassAssignment', severity: 'high', message: `Potential mass assignment fields in request to ${entry.url}: ${fields.join(', ')}`, entry });
    }
  });

  // Rule 4: Sensitive tokens in URL query params
  merged.forEach((entry) => {
    if (!entry.url) return;
    try {
      const params = new URL(entry.url).searchParams;
      const sensitiveKeys = ['token', 'api_key', 'apikey', 'access_token', 'secret', 'password', 'passwd', 'authorization'];
      const found = sensitiveKeys.filter((k) => params.has(k));
      if (found.length) {
        findings.push({
          type: 'TokenInUrl',
          severity: 'high',
          message: `Sensitive parameter(s) [${found.join(', ')}] passed in URL query string — tokens in URLs are logged by proxies, CDNs and browser history.`,
          entry
        });
      }
    } catch { /* ignore malformed URL */ }
  });

  // Rule 5: Missing cookie security flags (from Set-Cookie response headers)
  merged.forEach((entry) => {
    if (!entry.responseHeaders) return;
    const setCookie = entry.responseHeaders.find((h) => h.name.toLowerCase() === 'set-cookie');
    if (!setCookie || !setCookie.value) return;
    const val = setCookie.value;
    const issues = [];
    if (!/;\s*secure/i.test(val))   issues.push('Secure');
    if (!/;\s*httponly/i.test(val)) issues.push('HttpOnly');
    if (!/;\s*samesite/i.test(val)) issues.push('SameSite');
    if (issues.length) {
      findings.push({
        type: 'CookieFlags',
        severity: 'medium',
        message: `Cookie at ${entry.url} is missing flags: ${issues.join(', ')}.`,
        entry
      });
    }
  });

  // Rule 6: Cleartext HTTP request carrying sensitive data (Authorization or Cookie header)
  merged.forEach((entry) => {
    if (!entry.url || !entry.url.startsWith('http://')) return;
    const hasAuth = entry.requestHeaders?.some((h) =>
      h.name.toLowerCase() === 'authorization' || h.name.toLowerCase() === 'cookie'
    );
    if (hasAuth) {
      findings.push({
        type: 'CleartextAuth',
        severity: 'high',
        message: `Authentication credentials sent over plain HTTP (not HTTPS) to ${entry.url} — susceptible to network interception.`,
        entry
      });
    }
  });

  // Rule 7: Server version disclosure in response headers
  merged.forEach((entry) => {
    if (!entry.responseHeaders) return;
    const serverHeader = entry.responseHeaders.find((h) => h.name.toLowerCase() === 'server');
    const poweredBy   = entry.responseHeaders.find((h) => h.name.toLowerCase() === 'x-powered-by');
    const versionPattern = /[0-9]+\.[0-9]+/;
    if (serverHeader && versionPattern.test(serverHeader.value || '')) {
      findings.push({
        type: 'ServerVersionDisclosure',
        severity: 'low',
        message: `Server header discloses version info: "${serverHeader.value}" from ${entry.url}.`,
        entry
      });
    }
    if (poweredBy && poweredBy.value) {
      findings.push({
        type: 'TechDisclosure',
        severity: 'low',
        message: `X-Powered-By header discloses technology stack: "${poweredBy.value}" from ${entry.url}.`,
        entry
      });
    }
  });

  return findings;
}

function analyzeHosts(logEntries) {
  const merged = groupById(logEntries);
  const byHost = new Map();

  merged.forEach((entry) => {
    if (!entry.url) return;
    let origin;
    try {
      origin = new URL(entry.url).origin;
    } catch {
      return;
    }
    if (!byHost.has(origin)) byHost.set(origin, []);
    byHost.get(origin).push(entry);
  });

  const results = [];

  byHost.forEach((entries, origin) => {
    const tags = [];

    const authEntries = entries.filter((e) => e.requestHeaders?.some((h) => h.name.toLowerCase() === 'authorization'));
    const hasBearerAuth = authEntries.some((e) => e.requestHeaders.some((h) => h.name.toLowerCase() === 'authorization' && /^bearer/i.test(h.value || '')));
    const hasBasicAuth = authEntries.some((e) => e.requestHeaders.some((h) => h.name.toLowerCase() === 'authorization' && /^basic/i.test(h.value || '')));
    const hasHttp = entries.some((e) => e.url.startsWith('http://'));

    if (hasBearerAuth) tags.push({ label: 'Auth Present', kind: 'green' });
    if (hasBasicAuth || authEntries.length === 0 || (authEntries.length > 0 && hasHttp)) tags.push({ label: 'Weak Auth', kind: 'red' });

    const statuses = entries.filter((e) => typeof e.statusCode === 'number').map((e) => e.statusCode);
    const requestCount = entries.filter((e) => e.type === 'request').length;
    if (requestCount > 8 && !statuses.includes(429)) tags.push({ label: 'No Rate Limits', kind: 'purple' });

    const responseHeaderEntries = entries.filter((e) => e.responseHeaders);
    const missingHsts = responseHeaderEntries.length > 0 && origin.startsWith('https://') &&
      !responseHeaderEntries.some((e) => e.responseHeaders.some((h) => h.name.toLowerCase() === 'strict-transport-security'));
    if (missingHsts) tags.push({ label: 'Missing HSTS', kind: 'amber' });

    const corsIssue = responseHeaderEntries.some((e) => {
      const allowMethods = e.responseHeaders.find((h) => h.name.toLowerCase() === 'access-control-allow-methods');
      const allowOrigin = e.responseHeaders.find((h) => h.name.toLowerCase() === 'access-control-allow-origin');
      return (allowOrigin?.value === '*' && authEntries.length > 0) || /put|delete/i.test(allowMethods?.value || '');
    });
    if (corsIssue) tags.push({ label: 'CORS Issues', kind: 'purple' });

    const piiPattern = /(email|ssn|password|creditcard|dob|phone)/i;
    const hasPii = entries.some((e) => piiPattern.test(e.url));
    if (hasPii) tags.push({ label: 'PII Exposed', kind: 'amber' });

    if (tags.length === 0) return;

    results.push({
      origin,
      name: origin.replace(/^https?:\/\//, '').split('.')[0],
      tags
    });
  });

  return results;
}

if (typeof self !== 'undefined') {
  self.analyzeTraffic = analyzeTraffic;
  self.analyzeHosts = analyzeHosts;
} else if (typeof window !== 'undefined') {
  window.analyzeTraffic = analyzeTraffic;
  window.analyzeHosts = analyzeHosts;
}
if (typeof globalThis !== 'undefined') {
  globalThis.analyzeTraffic = analyzeTraffic;
  globalThis.analyzeHosts = analyzeHosts;
}
