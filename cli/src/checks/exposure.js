import { safeFetch, pool } from '../http.js';

/**
 * Sensitive paths probed for unintended exposure.
 * Each entry: { path, title, severity, verify? }
 * `verify` is a regex run against response body for confirmation.
 * Without `verify`, a 200 status alone is sufficient.
 */
const SENSITIVE_PATHS = [
  // Source / credentials
  { path: '/.env',             title: 'Environment file exposed (.env)',          severity: 'high',   verify: /[A-Z_]+=.+/ },
  { path: '/.git/HEAD',        title: 'Git repository exposed (.git/HEAD)',        severity: 'high',   verify: /ref:|HEAD/ },
  { path: '/.git/config',      title: 'Git config file exposed',                  severity: 'high',   verify: /\[core\]/ },
  { path: '/config.json',      title: 'Config file exposed (config.json)',         severity: 'high',   verify: /key|secret|password|token/i },
  { path: '/secrets.json',     title: 'Secrets file exposed (secrets.json)',       severity: 'high',   verify: null },
  { path: '/phpinfo.php',      title: 'PHP info page exposed',                    severity: 'high',   verify: /PHP Version|phpinfo/i },

  // Admin / debug surfaces
  { path: '/admin',            title: 'Admin panel accessible',                   severity: 'medium', verify: null },
  { path: '/debug',            title: 'Debug endpoint accessible',                severity: 'medium', verify: null },
  { path: '/console',          title: 'Developer console accessible',             severity: 'high',   verify: null },
  { path: '/actuator',         title: 'Spring Actuator endpoint exposed',         severity: 'high',   verify: /actuator|health|beans/i },
  { path: '/actuator/env',     title: 'Spring Actuator /env exposed',             severity: 'high',   verify: null },
  { path: '/actuator/heapdump',title: 'Spring Actuator heap dump exposed',        severity: 'high',   verify: null },
  { path: '/server-status',    title: 'Apache server-status exposed',             severity: 'medium', verify: /Apache|requests currently/i },
  { path: '/server-info',      title: 'Apache server-info exposed',               severity: 'medium', verify: /Apache|Server Information/i },

  // API documentation (informational)
  { path: '/swagger-ui.html',  title: 'Swagger UI exposed',                       severity: 'info',   verify: /swagger/i },
  { path: '/swagger-ui',       title: 'Swagger UI exposed',                       severity: 'info',   verify: /swagger/i },
  { path: '/swagger.json',     title: 'Swagger spec exposed (swagger.json)',       severity: 'info',   verify: /swagger/i },
  { path: '/openapi.json',     title: 'OpenAPI spec exposed (openapi.json)',       severity: 'info',   verify: /openapi/i },
  { path: '/api-docs',         title: 'API documentation exposed (/api-docs)',     severity: 'info',   verify: null },
  { path: '/redoc',            title: 'ReDoc API documentation exposed',          severity: 'info',   verify: /redoc|ReDoc/i },

  // Backup / dump files
  { path: '/backup.zip',       title: 'Backup archive exposed (backup.zip)',       severity: 'high',   verify: null },
  { path: '/backup.tar.gz',    title: 'Backup archive exposed (backup.tar.gz)',    severity: 'high',   verify: null },
  { path: '/dump.sql',         title: 'Database dump exposed (dump.sql)',          severity: 'high',   verify: /INSERT|CREATE TABLE/i },
  { path: '/db.sql',           title: 'Database dump exposed (db.sql)',            severity: 'high',   verify: /INSERT|CREATE TABLE/i },
  { path: '/backup.sql',       title: 'Database dump exposed (backup.sql)',        severity: 'high',   verify: /INSERT|CREATE TABLE/i },

  // CMS / framework signatures
  { path: '/wp-login.php',     title: 'WordPress login page detected',            severity: 'info',   verify: /WordPress/i },
  { path: '/wp-json/wp/v2/users', title: 'WordPress user enumeration via REST',   severity: 'medium', verify: /"id":\d+/ },
  { path: '/metrics',          title: 'Prometheus metrics endpoint exposed',       severity: 'medium', verify: /# HELP|# TYPE/ },
  { path: '/trace',            title: 'Trace/debug route exposed',                severity: 'medium', verify: null },
];

export async function runExposureChecks(baseUrl, timeout) {
  const findings = [];
  const seen = new Set();

  await pool(SENSITIVE_PATHS, 8, async ({ path, title, severity, verify }) => {
    let url;
    try { url = new URL(path, baseUrl).toString(); } catch { return; }

    const resp = await safeFetch(url, {}, timeout);
    if (!resp || resp.status !== 200) return;

    // Read body for content verification
    const body = await resp.text().catch(() => '');
    if (verify && !verify.test(body)) return;

    // Deduplicate same title (e.g. swagger-ui appearing twice)
    const key = title;
    if (seen.has(key)) return;
    seen.add(key);

    findings.push({ category: 'exposure', title, severity, url, evidence: `HTTP 200 response from ${url}${verify ? ' with matching content signature' : ''}` });
  });

  return findings;
}
