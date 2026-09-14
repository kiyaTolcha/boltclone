import { safeFetch } from '../http.js';

// Safely extract all Set-Cookie headers, compatible with Node 18+ and older runtimes.
function getSetCookieHeaders(resp) {
  if (typeof resp.headers.getSetCookie === 'function') {
    return resp.headers.getSetCookieHeaders?.() ?? resp.headers.getSetCookie();
  }
  const raw = resp.headers.get('set-cookie');
  return raw ? [raw] : [];
}

export async function checkCookieSecurity(url, timeout) {
  const resp = await safeFetch(url, {}, timeout);
  if (!resp) return [];

  const cookies = getSetCookieHeaders(resp);
  if (!cookies.length) return [];

  const findings = [];

  const missingSecure   = cookies.some((c) => !/;\s*secure/i.test(c));
  const missingHttpOnly = cookies.some((c) => !/;\s*httponly/i.test(c));
  const missingSameSite = cookies.some((c) => !/;\s*samesite/i.test(c));
  const sessionNoExpiry = cookies.some(
    (c) => /session/i.test(c) && !/;\s*(max-age|expires)/i.test(c)
  );

  if (missingSecure) {
    findings.push({
      category: 'cookies',
      title: 'Cookie missing Secure flag',
      severity: 'medium',
      url,
      evidence: 'At least one Set-Cookie header lacks the Secure attribute, allowing transmission over plain HTTP.'
    });
  }
  if (missingHttpOnly) {
    findings.push({
      category: 'cookies',
      title: 'Cookie missing HttpOnly flag',
      severity: 'medium',
      url,
      evidence: 'At least one Set-Cookie header lacks HttpOnly, exposing cookie values to JavaScript (XSS risk).'
    });
  }
  if (missingSameSite) {
    findings.push({
      category: 'cookies',
      title: 'Cookie missing SameSite attribute',
      severity: 'low',
      url,
      evidence: 'At least one cookie has no SameSite attribute, increasing cross-site request forgery risk.'
    });
  }
  if (sessionNoExpiry) {
    findings.push({
      category: 'cookies',
      title: 'Session cookie has no expiry',
      severity: 'low',
      url,
      evidence: 'A session cookie is missing Max-Age/Expires, creating a persistent browser session that does not expire.'
    });
  }

  return findings;
}

export async function runCookieChecks(url, timeout) {
  return checkCookieSecurity(url, timeout);
}
