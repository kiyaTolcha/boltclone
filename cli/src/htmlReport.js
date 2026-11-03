// Self-contained HTML report generator for the CLI.
// Keeps the CLI independent from the chrome-extension directory.
//
// Phase 4: Adds four-standard taxonomy tags per finding and interactive
// standard-based filter buttons (OWASP Web 2021, OWASP API 2023, WSTG, ASTF).

function generateHtmlReport({ target = 'Target Site', findings = [], meta = {}, traffic = [], discovered = [] }) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => {
    const sev = (f.severity || 'info').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  });

  // Count findings per standard for filter button badges.
  const stdCounts = { owaspWeb: 0, owaspApi: 0, wstg: 0, astf: 0 };
  findings.forEach((f) => {
    if (!f.standards) return;
    if (f.standards.owaspWeb) stdCounts.owaspWeb++;
    if (f.standards.owaspApi) stdCounts.owaspApi++;
    if (f.standards.wstg)     stdCounts.wstg++;
    if (f.standards.astf)     stdCounts.astf++;
  });

  const timestamp = new Date().toLocaleString();
  const endpointCount = meta.endpointCount || discovered.length || new Set(traffic.map((t) => t.url)).size || 1;
  const durationText = meta.durationMs ? `${(meta.durationMs / 1000).toFixed(1)}s` : 'N/A';

  const remediations = {
    'BOLA': 'Enforce object-level access controls (IDOR checks) in backend controllers before returning data or processing requests.',
    'RBAC': 'Validate user roles and permissions on every privileged endpoint. Do not rely solely on client-side headers.',
    'MassAssignment': 'Use DTOs (Data Transfer Objects) or explicit field allowlists when binding request bodies to database models.',
    'CORS': 'Remove wildcard Access-Control-Allow-Origin headers on sensitive routes. Specify trusted origins explicitly.',
    'Missing HSTS Header': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
    'Missing Content-Security-Policy': "Implement a restrictive CSP header (e.g. default-src 'self') to mitigate XSS risks.",
    'Missing X-Frame-Options': 'Add header: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.',
    'Missing X-Content-Type-Options': 'Add header: X-Content-Type-Options: nosniff to prevent MIME-sniffing.',
    'Server Version Disclosure': 'Disable Server or X-Powered-By response headers in web server/framework configurations.',
    'Potential SQL Injection': 'Use parameterized queries and ORM bindings; never concatenate raw user input into SQL.',
    'Potential Reflected XSS': 'Escape / sanitize all output and enforce a Content-Security-Policy header.',
    'Potential Open Redirect': 'Validate redirect destinations against a strict allowlist of trusted hosts.',
    'Potential Directory Traversal': 'Canonicalize file paths and reject any path that escapes the intended root directory.',
    'No rate-limiting detected': 'Implement per-IP and per-user request throttling with 429 responses and retry-after headers.',
    'Potential IDOR/BOLA': 'Enforce ownership checks on every object identifier before returning or mutating data.',
    'Potential CSRF risk': 'Use anti-CSRF tokens for all state-changing requests and set SameSite=Strict on session cookies.',
    'CORS misconfiguration': 'Restrict Access-Control-Allow-Origin to an explicit list of trusted origins.',
    'CORS reflects arbitrary Origin': 'Do not echo back arbitrary Origin values; validate against a fixed allowlist.',
    'Potential SSRF vector': 'Enforce an outbound request allowlist and block all access to link-local / cloud metadata ranges.',
    'Missing security headers': 'Add security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy.',
    'Invalid or untrusted certificate chain': 'Obtain a certificate from a trusted CA and ensure the full chain is served.',
    'Certificate expired': 'Renew the TLS certificate immediately and automate future renewals (e.g. Let\'s Encrypt + ACME).',
    'Certificate expiring soon': 'Schedule an immediate certificate renewal before expiry.',
    'Weak TLS protocol version': 'Disable TLS 1.0 and 1.1; require TLS 1.2+ and prefer TLS 1.3.',
    'Weak cipher suite': 'Disable RC4, DES, NULL, and MD5-based cipher suites; use AEAD ciphers only.',
    'Default/weak credentials accepted': 'Remove or change all default credentials; enforce strong password policies and MFA.',
    // Phase 3/4 additions
    'Confirmed BOLA — cross-tenant object access': 'Enforce strict ownership checks per-object, per-user. Use opaque references, not sequential IDs.',
    'BFLA — Privileged endpoint accessible without authentication': 'Require authentication on all administrative endpoints; fail-closed on missing credentials.',
    'BFLA — Privileged endpoint accessible to unprivileged role': 'Implement function-level RBAC checks; deny access unless the user holds the required role.',
    'Excessive Data Exposure — sensitive fields in response': 'Apply explicit field allowlists in API serializers; never expose internal or secret fields.',
    'Mass Assignment — injected property accepted by server': 'Use allowlists to bind only expected request properties; reject unknown fields.',
  };

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /**
   * Builds taxonomy badge HTML from a finding's standards object.
   * Returns empty string if no standards are attached.
   */
  function standardsBadges(standards) {
    if (!standards) return '';
    const parts = [];
    if (standards.owaspWeb) parts.push(`<span class="std-tag std-web" data-std="owaspWeb">OWASP ${escapeHtml(standards.owaspWeb)}</span>`);
    if (standards.owaspApi) parts.push(`<span class="std-tag std-api" data-std="owaspApi">OWASP ${escapeHtml(standards.owaspApi)}</span>`);
    if (standards.wstg)     parts.push(`<span class="std-tag std-wstg" data-std="wstg">${escapeHtml(standards.wstg)}</span>`);
    if (standards.astf)     parts.push(`<span class="std-tag std-astf" data-std="astf">${escapeHtml(standards.astf)}</span>`);
    return parts.length > 0 ? `<div class="std-tags">${parts.join(' ')}</div>` : '';
  }

  /**
   * Builds data-attributes for standard-based filtering.
   */
  function standardsDataAttrs(standards) {
    if (!standards) return '';
    const attrs = [];
    if (standards.owaspWeb) attrs.push(`data-owasp-web="${escapeHtml(standards.owaspWeb)}"`);
    if (standards.owaspApi) attrs.push(`data-owasp-api="${escapeHtml(standards.owaspApi)}"`);
    if (standards.wstg)     attrs.push(`data-wstg="${escapeHtml(standards.wstg)}"`);
    if (standards.astf)     attrs.push(`data-astf="${escapeHtml(standards.astf)}"`);
    return attrs.join(' ');
  }

  const findingsRows = findings.map((f) => {
    const sev = (f.severity || 'info').toLowerCase();
    const title = f.title || f.message || f.type || 'Security Finding';
    const cat = f.category || f.type || 'general';
    const url = f.url || f.entry?.url || target;
    const evidence = f.evidence || f.message || 'No additional evidence recorded';
    const rec = remediations[f.title] || remediations[f.type] || 'Review API endpoint implementation against OWASP Security Best Practices.';
    const stdBadges = standardsBadges(f.standards);
    const stdAttrs = standardsDataAttrs(f.standards);

    return `
      <tr class="finding-row severity-${sev}" data-severity="${sev}" ${stdAttrs}>
        <td><span class="badge badge-${sev}">${sev.toUpperCase()}</span></td>
        <td>
          <div class="finding-title">${escapeHtml(title)}</div>
          <div class="finding-url"><a href="${escapeHtml(url)}" target="_blank">${escapeHtml(url)}</a></div>
          ${stdBadges}
        </td>
        <td><span class="category-tag">${escapeHtml(cat)}</span></td>
        <td>
          <div class="evidence-box">${escapeHtml(evidence)}</div>
          <div class="recommendation"><strong>Remediation:</strong> ${escapeHtml(rec)}</div>
        </td>
      </tr>
    `;
  }).join('');

  const geminiSection = meta.geminiAnalysis ? `
    <div class="ai-card">
      <div class="ai-header">✨ Google Gemini AI Threat Synthesis</div>
      <div class="ai-score">Risk Score: <strong>${meta.geminiAnalysis.overallRiskScore ?? 'N/A'}/100</strong></div>
      <p class="ai-summary">${escapeHtml(meta.geminiAnalysis.executiveSummary || '')}</p>
      ${meta.geminiAnalysis.attackPath ? `<p class="ai-attack"><strong>Attack Scenario:</strong> ${escapeHtml(meta.geminiAnalysis.attackPath)}</p>` : ''}
      ${(meta.geminiAnalysis.priorityFixes?.length) ? `
        <div class="ai-fixes-title">Priority Fixes:</div>
        <ol class="ai-fixes">${meta.geminiAnalysis.priorityFixes.map((f) => `<li>${escapeHtml(f)}</li>`).join('')}</ol>
      ` : ''}
    </div>
  ` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BOLTCLONE Security Assessment Report - ${escapeHtml(target)}</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --high: #ef4444;
      --medium: #f59e0b;
      --low: #3b82f6;
      --info: #64748b;
      --accent: #6366f1;
      --ai: #7c3aed;
      --std-web: #ef4444;
      --std-api: #f59e0b;
      --std-wstg: #22d3ee;
      --std-astf: #a78bfa;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background-color: var(--bg); color: var(--text); padding: 30px 20px; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }
    .logo { font-size: 24px; font-weight: 800; letter-spacing: 1px; color: #fff; display: flex; align-items: center; gap: 10px; }
    .logo span { color: var(--accent); }
    .meta-info { font-size: 13px; color: var(--text-muted); text-align: right; }

    .dashboard-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; margin-bottom: 30px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 20px; text-align: center; }
    .card-num { font-size: 36px; font-weight: 800; margin-top: 5px; }
    .card-high { color: var(--high); }
    .card-medium { color: var(--medium); }
    .card-low { color: var(--low); }
    .card-info { color: var(--info); }

    .ai-card { background: linear-gradient(135deg, #1e1b4b, #1e293b); border: 1px solid #4c1d95; border-radius: 10px; padding: 24px; margin-bottom: 30px; }
    .ai-header { font-size: 16px; font-weight: 800; color: #c4b5fd; margin-bottom: 10px; }
    .ai-score { font-size: 20px; font-weight: 700; color: #fff; margin-bottom: 12px; }
    .ai-summary { color: #e2e8f0; margin-bottom: 10px; }
    .ai-attack { color: #e2e8f0; margin-bottom: 10px; }
    .ai-fixes-title { font-weight: 700; color: #c4b5fd; margin-bottom: 6px; }
    .ai-fixes { color: #e2e8f0; padding-left: 20px; }
    .ai-fixes li { margin-bottom: 4px; }

    .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 15px; }
    .filter-group { display: flex; gap: 8px; flex-wrap: wrap; }
    .filter-btn { background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }
    .filter-btn.active, .filter-btn:hover { background: var(--accent); border-color: var(--accent); color: #fff; }
    .btn-print { background: #22c55e; border: none; color: #fff; padding: 8px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 13px; }
    .btn-print:hover { opacity: 0.9; }

    .filter-label { font-size: 11px; font-weight: 700; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px; margin-bottom: 4px; }

    /* Standard filter buttons — color-coded per standard */
    .std-filter-btn { font-size: 12px; padding: 6px 12px; border-radius: 5px; cursor: pointer; font-weight: 600; transition: all 0.2s; border: 1px solid var(--border); background: var(--card-bg); color: var(--text); }
    .std-filter-btn.active-web,  .std-filter-btn[data-filter="owaspWeb"]:hover  { background: var(--std-web);  border-color: var(--std-web);  color: #fff; }
    .std-filter-btn.active-api,  .std-filter-btn[data-filter="owaspApi"]:hover  { background: var(--std-api);  border-color: var(--std-api);  color: #000; }
    .std-filter-btn.active-wstg, .std-filter-btn[data-filter="wstg"]:hover      { background: var(--std-wstg); border-color: var(--std-wstg); color: #000; }
    .std-filter-btn.active-astf, .std-filter-btn[data-filter="astf"]:hover      { background: var(--std-astf); border-color: var(--std-astf); color: #000; }

    /* Standard tags inline on findings */
    .std-tags { margin-top: 6px; display: flex; gap: 4px; flex-wrap: wrap; }
    .std-tag { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 10px; font-weight: 700; text-transform: uppercase; }
    .std-web  { background: rgba(239,68,68,0.15); color: var(--std-web); border: 1px solid rgba(239,68,68,0.3); }
    .std-api  { background: rgba(245,158,11,0.15); color: var(--std-api); border: 1px solid rgba(245,158,11,0.3); }
    .std-wstg { background: rgba(34,211,238,0.15); color: var(--std-wstg); border: 1px solid rgba(34,211,238,0.3); }
    .std-astf { background: rgba(167,139,250,0.15); color: var(--std-astf); border: 1px solid rgba(167,139,250,0.3); }

    table { width: 100%; border-collapse: collapse; background: var(--card-bg); border-radius: 10px; overflow: hidden; border: 1px solid var(--border); }
    th { background: #162032; text-align: left; padding: 14px 16px; font-size: 13px; color: var(--text-muted); text-transform: uppercase; border-bottom: 1px solid var(--border); }
    td { padding: 16px; border-bottom: 1px solid var(--border); font-size: 14px; vertical-align: top; }

    .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; color: #fff; }
    .badge-high { background: var(--high); }
    .badge-medium { background: var(--medium); }
    .badge-low { background: var(--low); }
    .badge-info { background: var(--info); }

    .category-tag { background: #334155; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
    .finding-title { font-weight: 700; font-size: 15px; margin-bottom: 4px; }
    .finding-url { font-size: 12px; color: var(--accent); word-break: break-all; }
    .finding-url a { color: var(--accent); text-decoration: none; }
    .evidence-box { background: #0f172a; padding: 10px; border-radius: 6px; font-family: monospace; font-size: 12px; margin-bottom: 8px; border-left: 3px solid var(--border); color: #cbd5e1; }
    .recommendation { font-size: 12px; color: #64748b; background: #1e293b; padding: 8px; border-radius: 4px; }

    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .container { max-width: 100%; }
      .toolbar, .std-toolbar, .btn-print { display: none; }
      .card, table, .ai-card { border: 1px solid #ccc; background: #fff; color: #000; }
      th { background: #f1f5f9; color: #000; }
      td { border-bottom: 1px solid #eee; }
      .evidence-box { background: #f8fafc; color: #000; border: 1px solid #ddd; }
      .std-tag { border: 1px solid #aaa; color: #333; background: #f0f0f0; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">
        🛡️ BOLT<span>CLONE</span> Executive Security Report
      </div>
      <div class="meta-info">
        <div><strong>Target:</strong> ${escapeHtml(target)}</div>
        <div><strong>Generated:</strong> ${timestamp}</div>
        <div><strong>Endpoints Scanned:</strong> ${endpointCount} | <strong>Duration:</strong> ${durationText}</div>
      </div>
    </header>

    <div class="dashboard-cards">
      <div class="card"><div>HIGH SEVERITY</div><div class="card-num card-high">${counts.high}</div></div>
      <div class="card"><div>MEDIUM SEVERITY</div><div class="card-num card-medium">${counts.medium}</div></div>
      <div class="card"><div>LOW SEVERITY</div><div class="card-num card-low">${counts.low}</div></div>
      <div class="card"><div>INFORMATIONAL</div><div class="card-num card-info">${counts.info}</div></div>
    </div>

    ${geminiSection}

    <div class="toolbar">
      <div>
        <div class="filter-label">Filter by Severity</div>
        <div class="filter-group">
          <button class="filter-btn active" onclick="filterSev('all')">All (${findings.length})</button>
          <button class="filter-btn" onclick="filterSev('high')">High (${counts.high})</button>
          <button class="filter-btn" onclick="filterSev('medium')">Medium (${counts.medium})</button>
          <button class="filter-btn" onclick="filterSev('low')">Low (${counts.low})</button>
        </div>
      </div>
      <button class="btn-print" onclick="window.print()">🖨️ Print / Save PDF</button>
    </div>

    <div class="toolbar std-toolbar">
      <div>
        <div class="filter-label">Filter by OWASP Standard</div>
        <div class="filter-group">
          <button class="std-filter-btn" data-filter="all" onclick="filterStd('all')">All Findings (${findings.length})</button>
          <button class="std-filter-btn" data-filter="owaspWeb" onclick="filterStd('owaspWeb')">OWASP Top 10 Web 2021 (${stdCounts.owaspWeb})</button>
          <button class="std-filter-btn" data-filter="owaspApi" onclick="filterStd('owaspApi')">OWASP API Top 10 2023 (${stdCounts.owaspApi})</button>
          <button class="std-filter-btn" data-filter="wstg" onclick="filterStd('wstg')">OWASP WSTG v4.2 (${stdCounts.wstg})</button>
          <button class="std-filter-btn" data-filter="astf" onclick="filterStd('astf')">OWASP ASTF (${stdCounts.astf})</button>
        </div>
      </div>
    </div>

    <table>
      <thead>
        <tr>
          <th style="width: 100px;">Severity</th>
          <th>Finding &amp; URL</th>
          <th style="width: 120px;">Category</th>
          <th>Evidence &amp; Remediation</th>
        </tr>
      </thead>
      <tbody>
        ${findingsRows || '<tr><td colspan="4" style="text-align:center; padding:30px; color:#94a3b8;">No security vulnerabilities identified.</td></tr>'}
      </tbody>
    </table>
  </div>

  <script>
    // Severity filter (existing behavior preserved).
    function filterSev(sev) {
      document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
      // Reset standard filter when severity is changed.
      document.querySelectorAll('.std-filter-btn').forEach(btn => {
        btn.classList.remove('active-web', 'active-api', 'active-wstg', 'active-astf');
        if (btn.dataset.filter === 'all') btn.classList.add('active');
      });
      document.querySelectorAll('.finding-row').forEach(row => {
        row.style.display = (sev === 'all' || row.dataset.severity === sev) ? '' : 'none';
      });
    }

    // OWASP Standard filter — shows only findings tagged with the selected standard.
    function filterStd(std) {
      // Update standard filter button states.
      document.querySelectorAll('.std-filter-btn').forEach(btn => {
        btn.classList.remove('active-web', 'active-api', 'active-wstg', 'active-astf');
      });
      const activeBtn = event.target;
      if (std === 'owaspWeb') activeBtn.classList.add('active-web');
      else if (std === 'owaspApi') activeBtn.classList.add('active-api');
      else if (std === 'wstg') activeBtn.classList.add('active-wstg');
      else if (std === 'astf') activeBtn.classList.add('active-astf');

      // Reset severity filter to "All".
      document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
      document.querySelector('.filter-btn').classList.add('active');

      // Apply standard filter.
      document.querySelectorAll('.finding-row').forEach(row => {
        if (std === 'all') {
          row.style.display = '';
          return;
        }
        // Map filter key to data attribute name.
        const attrMap = { owaspWeb: 'owaspWeb', owaspApi: 'owaspApi', wstg: 'wstg', astf: 'astf' };
        const attr = 'data-' + attrMap[std].replace(/([A-Z])/g, '-$1').toLowerCase();
        row.style.display = row.hasAttribute(attr) ? '' : 'none';
      });
    }
  </script>
</body>
</html>`;
}

export function buildCliHtmlReport(target, findings, meta = {}) {
  return generateHtmlReport({
    target,
    findings,
    meta,
    discovered: meta.discovered || [],
    traffic: meta.importedTraffic || []
  });
}
