export function generateHtmlReport({ target = 'Target Site', findings = [], meta = {}, traffic = [], discovered = [] }) {
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => {
    const sev = (f.severity || 'info').toLowerCase();
    if (counts[sev] !== undefined) counts[sev]++;
  });

  const timestamp = new Date().toLocaleString();
  const endpointCount = meta.endpointCount || discovered.length || new Set(traffic.map(t => t.url)).size || 1;
  const durationText = meta.durationMs ? `${(meta.durationMs / 1000).toFixed(1)}s` : 'N/A';

  const remediations = {
    'BOLA': 'Enforce object-level access controls (IDOR checks) in backend controllers before returning data or processing requests.',
    'RBAC': 'Validate user roles and permissions on every privileged endpoint. Do not rely solely on client-side headers.',
    'MassAssignment': 'Use DTOs (Data Transfer Objects) or explicit field allowlists when binding request bodies to database models.',
    'CORS': 'Remove wildcard Access-Control-Allow-Origin headers on sensitive routes. Specify trusted origins explicitly.',
    'Missing HSTS Header': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.',
    'Missing Content-Security-Policy': 'Implement a restrictive CSP header (e.g. default-src \'self\') to mitigate XSS risks.',
    'Missing X-Frame-Options': 'Add header: X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.',
    'Missing X-Content-Type-Options': 'Add header: X-Content-Type-Options: nosniff to prevent MIME-sniffing.',
    'Server Version Disclosure': 'Disable Server or X-Powered-By response headers in web server/framework configurations.'
  };

  const findingsRows = findings.map((f, i) => {
    const sev = (f.severity || 'info').toLowerCase();
    const title = f.title || f.message || f.type || 'Security Finding';
    const cat = f.category || f.type || 'general';
    const url = f.url || f.entry?.url || target;
    const evidence = f.evidence || f.message || 'No additional evidence recorded';
    const rec = remediations[f.type] || remediations[f.title] || 'Review API endpoint implementation against OWASP Security Best Practices.';

    return `
      <tr class="finding-row severity-${sev}" data-severity="${sev}">
        <td><span class="badge badge-${sev}">${sev.toUpperCase()}</span></td>
        <td>
          <div class="finding-title">${escapeHtml(title)}</div>
          <div class="finding-url"><a href="${escapeHtml(url)}" target="_blank">${escapeHtml(url)}</a></div>
        </td>
        <td><span class="category-tag">${escapeHtml(cat)}</span></td>
        <td>
          <div class="evidence-box">${escapeHtml(evidence)}</div>
          <div class="recommendation"><strong>Remediation:</strong> ${escapeHtml(rec)}</div>
        </td>
      </tr>
    `;
  }).join('');

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

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
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
    body { background-color: var(--bg); color: var(--text); padding: 30px 20px; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }
    .logo { font-size: 24px; font-weight: 800; letter-spacing: 1px; color: #fff; display: flex; align-items: center; gap: 10px; }
    .logo span { color: var(--accent); }
    .meta-info { font-size: 13px; color: var(--text-muted); text-align: right; }
    
    .dashboard-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 10px; padding: 20px; text-align: center; }
    .card-num { font-size: 36px; font-weight: 800; margin-top: 5px; }
    .card-high { color: var(--high); }
    .card-medium { color: var(--medium); }
    .card-low { color: var(--low); }
    .card-info { color: var(--info); }
    
    .toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 15px; }
    .filter-group { display: flex; gap: 10px; }
    .filter-btn { background: var(--card-bg); border: 1px solid var(--border); color: var(--text); padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }
    .filter-btn.active, .filter-btn:hover { background: var(--accent); border-color: var(--accent); color: #fff; }
    
    .btn-print { background: #22c55e; border: none; color: #fff; padding: 8px 20px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 13px; }
    .btn-print:hover { opacity: 0.9; }

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
      .toolbar, .btn-print { display: none; }
      .card, table { border: 1px solid #ccc; background: #fff; color: #000; }
      th { background: #f1f5f9; color: #000; }
      td { border-bottom: 1px solid #eee; }
      .evidence-box { background: #f8fafc; color: #000; border: 1px solid #ddd; }
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

    <div class="toolbar">
      <div class="filter-group">
        <button class="filter-btn active" onclick="filterSev('all')">All (${findings.length})</button>
        <button class="filter-btn" onclick="filterSev('high')">High (${counts.high})</button>
        <button class="filter-btn" onclick="filterSev('medium')">Medium (${counts.medium})</button>
        <button class="filter-btn" onclick="filterSev('low')">Low (${counts.low})</button>
      </div>
      <button class="btn-print" onclick="window.print()">🖨️ Print / Save PDF</button>
    </div>

    <table>
      <thead>
        <tr>
          <th style="width: 100px;">Severity</th>
          <th>Finding & URL</th>
          <th style="width: 120px;">Category</th>
          <th>Evidence & Remediation</th>
        </tr>
      </thead>
      <tbody>
        ${findingsRows || '<tr><td colspan="4" style="text-align:center; padding:30px; color:#94a3b8;">No security vulnerabilities identified.</td></tr>'}
      </tbody>
    </table>
  </div>

  <script>
    function filterSev(sev) {
      document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
      event.target.classList.add('active');
      document.querySelectorAll('.finding-row').forEach(row => {
        if (sev === 'all' || row.dataset.severity === sev) {
          row.style.display = '';
        } else {
          row.style.display = 'none';
        }
      });
    }
  </script>
</body>
</html>`;
}

if (typeof self !== 'undefined') {
  self.generateHtmlReport = generateHtmlReport;
} else if (typeof window !== 'undefined') {
  window.generateHtmlReport = generateHtmlReport;
}
if (typeof globalThis !== 'undefined') {
  globalThis.generateHtmlReport = generateHtmlReport;
}
