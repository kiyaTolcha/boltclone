import { safeFetch } from '../http.js';

function withParam(url, name, value) {
  const trial = new URL(url);
  trial.searchParams.set(name, value);
  return trial;
}

export async function checkSqlInjection(url, timeout) {
  const trial = withParam(url, 'q', "' OR '1'='1");
  const resp = await safeFetch(trial.toString(), { method: 'GET' }, timeout);
  if (!resp || resp.status < 200 || resp.status >= 300) return null;
  const text = await resp.text().catch(() => '');
  if (/sql|syntax error|odbc|ora-\d{5}|sqlite_/i.test(text)) {
    return { category: 'injection', title: 'Potential SQL Injection', severity: 'high', url: trial.toString(), evidence: `Response contained SQL error indicators (status ${resp.status})` };
  }
  return null;
}

export async function checkXss(url, timeout) {
  const payload = '<script>alert(1)</script>';
  const trial = withParam(url, 'q', payload);
  const resp = await safeFetch(trial.toString(), { method: 'GET' }, timeout);
  if (!resp || resp.status < 200 || resp.status >= 300) return null;
  const text = await resp.text().catch(() => '');
  if (text.includes(payload)) {
    return { category: 'injection', title: 'Potential Reflected XSS', severity: 'high', url: trial.toString(), evidence: 'Payload reflected unescaped in response body.' };
  }
  return null;
}

export async function checkOpenRedirect(url, timeout) {
  const trial = withParam(url, 'redirect', 'https://example.com/');
  const resp = await safeFetch(trial.toString(), { redirect: 'manual' }, timeout);
  if (!resp) return null;
  const location = resp.headers.get('location') || '';
  if (resp.status >= 300 && resp.status < 400 && location.includes('example.com')) {
    return { category: 'injection', title: 'Potential Open Redirect', severity: 'high', url: trial.toString(), evidence: `Redirected to ${location}` };
  }
  return null;
}

export async function checkDirectoryTraversal(url, timeout) {
  const trial = withParam(url, 'file', '../../../../etc/passwd');
  const resp = await safeFetch(trial.toString(), {}, timeout);
  if (!resp || resp.status < 200 || resp.status >= 300) return null;
  const text = await resp.text().catch(() => '');
  if (text.includes('root:') || text.includes('/bin/bash')) {
    return { category: 'injection', title: 'Potential Directory Traversal', severity: 'high', url: trial.toString(), evidence: 'Response contained /etc/passwd content.' };
  }
  return null;
}

export async function runInjectionChecks(url, timeout) {
  const results = await Promise.all([
    checkSqlInjection(url, timeout),
    checkXss(url, timeout),
    checkOpenRedirect(url, timeout),
    checkDirectoryTraversal(url, timeout)
  ]);
  return results.filter(Boolean);
}
