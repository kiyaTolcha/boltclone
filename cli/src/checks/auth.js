import { safeFetch } from '../http.js';
import { readFile } from 'node:fs/promises';

const LOGIN_PATH_HINTS = ['login', 'signin', 'sign-in', 'auth', 'session'];
const DEFAULT_LOGIN_PATHS = ['/login', '/api/login', '/api/auth/login', '/auth/login', '/rest/user/login'];
const DEFAULT_CREDS = [
  { username: 'admin', password: 'admin' },
  { username: 'admin', password: 'password' },
  { username: 'admin', password: '123456' },
  { username: 'test', password: 'test' },
  { username: 'user', password: 'user' }
];

const FAILURE_HINTS = /invalid|incorrect|unauthorized|denied|failed|wrong (username|password|email)/i;

export async function loadCreds(credsFile) {
  if (!credsFile) return DEFAULT_CREDS;
  try {
    const text = await readFile(credsFile, 'utf8');
    const parsed = JSON.parse(text);
    if (Array.isArray(parsed) && parsed.every((c) => c.username && c.password)) return parsed;
  } catch { /* fall through to default */ }
  return DEFAULT_CREDS;
}

function findLoginCandidates(baseUrl, discovered) {
  const fromDiscovery = discovered
    .filter((d) => LOGIN_PATH_HINTS.some((hint) => d.path.toLowerCase().includes(hint)))
    .map((d) => d.url);

  const defaults = DEFAULT_LOGIN_PATHS.map((p) => new URL(p, baseUrl).toString());
  return Array.from(new Set([...fromDiscovery, ...defaults])).slice(0, 3);
}

async function attemptLogin(loginUrl, cred, timeout) {
  const bodies = [
    { username: cred.username, password: cred.password },
    { email: cred.username, password: cred.password }
  ];

  for (const body of bodies) {
    const resp = await safeFetch(loginUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'manual'
    }, timeout);
    if (!resp) continue;

    const setCookie = resp.headers.get('set-cookie') || '';
    const text = await resp.text().catch(() => '');
    const looksSuccessful =
      (resp.status >= 200 && resp.status < 300 && (setCookie || /token|jwt|session/i.test(text))) ||
      (resp.status >= 300 && resp.status < 400 && !/login|signin/i.test(resp.headers.get('location') || ''));
    const looksFailed = resp.status === 401 || resp.status === 403 || FAILURE_HINTS.test(text);

    if (looksSuccessful && !looksFailed) {
      return { success: true, status: resp.status };
    }
  }
  return { success: false };
}

export async function runAuthChecks(baseUrl, discovered, timeout, credsFile) {
  const findings = [];
  const candidates = findLoginCandidates(baseUrl, discovered);
  const creds = await loadCreds(credsFile);

  for (const loginUrl of candidates) {
    let responded = false;
    for (const cred of creds.slice(0, 5)) {
      const result = await attemptLogin(loginUrl, cred, timeout);
      if (result.success) {
        responded = true;
        findings.push({
          category: 'auth',
          title: 'Default/weak credentials accepted',
          severity: 'high',
          url: loginUrl,
          evidence: `Login succeeded with ${cred.username}:${cred.password}`
        });
        break;
      }
    }
    if (!responded) {
      // Only report "endpoint exists" as informational if we got any response at all.
      const probe = await safeFetch(loginUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }, timeout);
      if (probe) {
        findings.push({
          category: 'auth',
          title: 'Login endpoint found (no default credentials matched)',
          severity: 'info',
          url: loginUrl,
          evidence: `Tested ${creds.slice(0, 5).length} common credential pairs, none succeeded.`
        });
      }
    }
  }

  return findings;
}
