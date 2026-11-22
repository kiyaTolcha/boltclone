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

export async function checkSsti(url, timeout) {
  // Payloads for Jinja2, Twig, FreeMarker, EL, Pebble, Ruby ERB, Smarty
  const payloads = ['{{7*7}}', '${7*7}', '#{7*7}', '<%= 7*7 %>', '{% 7*7 %}', '*{7*7}', '{7*7}'];
  for (const payload of payloads) {
    const trial = withParam(url, 'q', payload);
    const resp = await safeFetch(trial.toString(), { method: 'GET' }, timeout);
    if (!resp || resp.status < 200 || resp.status >= 300) continue;

    const ct = (resp.headers.get('content-type') || '').toLowerCase();
    const text = await resp.text().catch(() => '');

    if (!text.includes('49')) continue;

    // --- SPA / client-side template false-positive guard ---
    // If the response is HTML, the "49" must appear OUTSIDE of:
    //   (a) any <script>...</script> block (Angular/React evaluation happens client-side)
    //   (b) a JSON object embedded in a data-* attribute or window.__STATE__ assignment
    // The simplest reliable signal: strip all <script> blocks and check if "49" remains.
    if (ct.includes('text/html')) {
      const stripped = text.replace(/<script[\s\S]*?<\/script>/gi, '');
      // After stripping scripts, "49" must appear in visible HTML or a JSON response body.
      // Also reject if the entire response is a single-page app shell (no visible text nodes
      // containing "49" outside of attribute values and tags).
      const visibleMatch = stripped.match(/(?<!["\w])49(?![\w"])/);
      if (!visibleMatch) continue; // "49" only lived inside <script> — client-side eval, skip
    }

    return {
      category: 'injection',
      title: 'Potential Server-Side Template Injection (SSTI)',
      severity: 'high',
      url: trial.toString(),
      evidence: `Payload "${payload}" was evaluated — response contained "49" (7×7) outside script context.`
    };
  }
  return null;
}

export async function checkXxe(url, timeout) {
  const xxePayload = `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>`;
  const resp = await safeFetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/xml' },
    body: xxePayload
  }, timeout);
  if (!resp || resp.status < 200 || resp.status >= 300) return null;
  const text = await resp.text().catch(() => '');
  if (text.includes('root:') || text.includes('/bin/bash') || text.includes('/bin/sh')) {
    return {
      category: 'injection',
      title: 'Potential XXE (XML External Entity Injection)',
      severity: 'high',
      url,
      evidence: 'Response included /etc/passwd content after XML external entity injection.'
    };
  }
  return null;
}

export async function runInjectionChecks(url, timeout) {
  const results = await Promise.all([
    checkSqlInjection(url, timeout),
    checkXss(url, timeout),
    checkOpenRedirect(url, timeout),
    checkDirectoryTraversal(url, timeout),
    checkSsti(url, timeout),
    checkXxe(url, timeout)
  ]);
  return results.filter(Boolean);
}
