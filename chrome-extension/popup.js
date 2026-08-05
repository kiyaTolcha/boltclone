const NOISE_HEADERS = new Set([
  'accept-encoding', 'accept-language', 'connection', 'host', 'user-agent',
  'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user',
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform', 'upgrade-insecure-requests',
  'cache-control', 'pragma', 'priority', 'te', 'origin', 'referer',
  'content-length', 'date', 'connection', 'keep-alive', 'vary', 'server'
]);

let els = {};
let darkTheme = false;

function initPopup() {
  document.querySelectorAll('[id]').forEach((node) => { els[node.id] = node; });

  const missingEls = [];
  ['modeApi','modeAll','addRuleBtn','newRuleInput','ruleList','startCaptureBtn','stopCaptureBtn','discoverPage','testPage','methodChips','paramTypeChips','authTypeChips','wizApiList','wizCustomUrl','wizEndpointList','wizNext','wizBack','wizNew','rbacDismiss','rbacCta','testCardList','exportJson','exportOas','exportPostman','exportCsv','exportHtml','wzRateLimit','wzIdor','wzSql','wzXss','wzCsrf','wzSsrf','wzSecHeaders','wzOpenRedirect','wzCors','wzTraversal','themeToggle'].forEach((id) => {
    if (!els[id]) missingEls.push(id);
  });
  console.log('popup.js init: missing elements', missingEls);
  wireEvents();
  wireThemeToggle();
}

function showLanding(resetLabel = false) {
  showDashboard(false);
  if (els.startCaptureBtn) els.startCaptureBtn.textContent = resetLabel ? 'New' : 'Start Capture';
}

const state = {
  captureMode: 'api',
  scanState: 'stopped',
  traffic: [],
  merged: [],
  discoveredApis: [],
  analysis: [],
  hosts: [],
  captureRules: [],
  activeMainTab: 'discover',
  activeParamType: 'header',
  activeAuthType: 'jwt',
  wizard: { step: 1, api: null, endpoint: null, results: null },
  forceLanding: false
};

function wireEvents() {
  function safeListen(el, event, handler, options) {
    try {
      if (el && typeof el.addEventListener === 'function') el.addEventListener(event, handler, options);
    } catch (err) {
      console.error('safeListen failed for', el, event, err);
    }
  }

  safeListen(els.modeApi, 'click', () => setMode('api'));
  safeListen(els.modeAll, 'click', () => setMode('all'));
  safeListen(els.addRuleBtn, 'click', addRuleFromInput);
  safeListen(els.newRuleInput, 'keypress', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addRuleFromInput();
    }
  });

  safeListen(els.startCaptureBtn, 'click', () => {
    state.forceLanding = false;
    const typed = els.targetUrl?.value?.trim ? els.targetUrl.value.trim() : '';
    const origin = state.captureMode === 'api' && typed ? normalizeUrl(typed) : null;
    safeSendMessage({ type: 'setTargetOrigin', origin }, () => {
      safeSendMessage({ type: 'startScan' }, () => {
        state.scanState = 'running';
        showDashboard(true);
        refreshAll();
      });
    });
  });

  safeListen(els.stopCaptureBtn, 'click', () => {
    safeSendMessage({ type: 'stopScan' }, () => {
      state.scanState = 'stopped';
      state.forceLanding = true;
      showLanding(true);
      refreshAll();
    });
  });

  safeListen(els.ruleList, 'click', (e) => {
    const toggle = e.target.closest('.toggle-rule');
    const remove = e.target.closest('.remove-rule');
    if (toggle) {
      const id = toggle.dataset.ruleId;
      safeSendMessage({ type: 'toggleCaptureRule', id }, (res) => {
        if (res?.rules) {
          state.captureRules = res.rules;
          renderRuleList();
        }
      });
      return;
    }
    if (remove) {
      const id = remove.dataset.ruleId;
      safeSendMessage({ type: 'removeCaptureRule', id }, (res) => {
        if (res?.rules) {
          state.captureRules = res.rules;
          renderRuleList();
        }
      });
    }
  });

  document.querySelectorAll('.main-tab').forEach((btn) => {
    safeListen(btn, 'click', () => {
      state.activeMainTab = btn.dataset.target;
      document.querySelectorAll('.main-tab').forEach((b) => b.classList.toggle('active', b === btn));
      if (els.discoverPage) els.discoverPage.classList.toggle('active', btn.dataset.target === 'discover');
      if (els.testPage) els.testPage.classList.toggle('active', btn.dataset.target === 'test');
    });
  });

  document.querySelectorAll('.sub-tab[data-sub]').forEach((btn) => {
    safeListen(btn, 'click', () => {
      document.querySelectorAll('.sub-tab[data-sub]').forEach((b) => b.classList.toggle('active', b === btn));
      ['traffic', 'params', 'endpoints', 'auth'].forEach((key) => {
        if (els[`${key}Pane`]) els[`${key}Pane`].classList.toggle('active', key === btn.dataset.sub);
      });
    });
  });

  document.querySelectorAll('.sub-tab[data-sub2]').forEach((btn) => {
    safeListen(btn, 'click', () => {
      document.querySelectorAll('.sub-tab[data-sub2]').forEach((b) => b.classList.toggle('active', b === btn));
      if (els.securityPane) els.securityPane.classList.toggle('active', btn.dataset.sub2 === 'security');
      if (els.manipulatorPane) els.manipulatorPane.classList.toggle('active', btn.dataset.sub2 === 'manipulator');
    });
  });

  safeListen(els.methodChips, 'click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    const wasActive = chip.classList.contains('active');
    if (els.methodChips) els.methodChips.querySelectorAll('.chip').forEach((c) => c.classList.remove('active'));
    if (!wasActive) chip.classList.add('active');
    renderTraffic();
  });

  safeListen(els.paramTypeChips, 'click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    state.activeParamType = chip.dataset.ptype;
    if (els.paramTypeChips) els.paramTypeChips.querySelectorAll('.chip').forEach((c) => c.classList.toggle('active', c === chip));
    renderParams();
  });

  safeListen(els.authTypeChips, 'click', (e) => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    state.activeAuthType = chip.dataset.atype;
    if (els.authTypeChips) els.authTypeChips.querySelectorAll('.chip').forEach((c) => c.classList.toggle('active', c === chip));
    renderAuth();
  });

  safeListen(els.wizApiList, 'click', (e) => {
    const card = e.target.closest('[data-api]');
    if (!card) return;
    state.wizard.api = card.dataset.api;
    els.wizCustomUrl.value = '';
    updateWizardNav();
  });

  safeListen(els.wizCustomUrl, 'input', () => {
    if (els.wizCustomUrl.value.trim()) state.wizard.api = null;
    els.wizNext.disabled = !(state.wizard.api || els.wizCustomUrl.value.trim());
  });

  safeListen(els.wizEndpointList, 'click', (e) => {
    const card = e.target.closest('[data-endpoint-url]');
    if (!card) return;
    state.wizard.endpoint = { url: card.dataset.endpointUrl, method: card.dataset.endpointMethod };
    renderWizStep2();
    els.wizNext.disabled = false;
  });

  safeListen(els.wizNext, 'click', () => {
    if (state.wizard.step === 5) {
      resetWizard();
      return;
    }
    const customUrl = els.wizCustomUrl.value.trim();
    if (state.wizard.step === 1 && customUrl && !state.wizard.api) {
      const normalized = normalizeUrl(customUrl);
      state.wizard.endpoint = normalized ? { url: normalized, method: 'GET' } : null;
      state.wizard.step = 3;
    } else if (state.wizard.step < 5) {
      state.wizard.step += 1;
    }
    updateWizardNav();
  });

  safeListen(els.wizBack, 'click', () => {
    if (state.wizard.step > 1) state.wizard.step -= 1;
    if (state.wizard.step === 5) state.wizard.results = null;
    updateWizardNav();
  });

  safeListen(els.wizNew, 'click', resetWizard);

  safeListen(els.rbacDismiss, 'click', () => {
    if (els.rbacBanner) {
      els.rbacBanner.dataset.dismissed = 'true';
      els.rbacBanner.classList.add('hidden');
    }
  });

  safeListen(els.rbacCta, 'click', () => {
    const mainBtn = document.querySelector('.main-tab[data-target="test"]');
    const subBtn = document.querySelector('.sub-tab[data-sub2="manipulator"]');
    if (mainBtn) mainBtn.click();
    if (subBtn) subBtn.click();
    if (els.wzIdor) els.wzIdor.checked = true;
    if (els.wzSql) els.wzSql.checked = false;
    if (els.wzXss) els.wzXss.checked = false;
    if (els.wzCsrf) els.wzCsrf.checked = false;
    if (els.wzSsrf) els.wzSsrf.checked = false;
  });

  safeListen(els.testCardList, 'click', (e) => {
    const btn = e.target.closest('[data-run]');
    if (!btn) return;
    const subBtn = document.querySelector('.sub-tab[data-sub2="manipulator"]');
    if (subBtn) subBtn.click();
  });

  safeListen(els.exportJson, 'click', () => {
    safeSendMessage({ type: 'getAnalysis' }, (r) => {
      downloadFile('boltclone-analysis.json', JSON.stringify({ exportedAt: new Date().toISOString(), analysis: r?.analysis || [] }, null, 2));
    });
  });

  safeListen(els.exportOas, 'click', () => {
    safeSendMessage({ type: 'exportSpec' }, (r) => {
      if (r?.spec) downloadFile('boltclone-openapi.json', JSON.stringify(r.spec, null, 2));
    });
  });

  safeListen(els.exportPostman, 'click', () => {
    safeSendMessage({ type: 'exportPostmanSpec' }, (r) => {
      if (r?.spec) downloadFile('boltclone-postman.json', JSON.stringify(r.spec, null, 2));
    });
  });

  safeListen(els.exportHtml, 'click', () => {
    safeSendMessage({ type: 'exportHtmlReport' }, (r) => {
      if (r?.html) downloadFile('boltclone-security-report.html', r.html);
    });
  });

  safeListen(els.exportCsv, 'click', () => {
    const targetOrigin = normalizeUrl(els.targetUrl?.value?.trim ? els.targetUrl.value.trim() : '');
    safeSendMessage({ type: 'getAnalysis' }, (r) => {
      const filtered = (r?.analysis || []).filter((item) => {
        if (!targetOrigin || !item?.url) return true;
        return item.url.startsWith(targetOrigin);
      });
      const rows = filtered.map((item) => ({
        Type: item.type || '',
        Severity: item.severity || '',
        Message: item.message || '',
        URL: item.url || '',
        Method: item.method || '',
        StatusCode: item.statusCode || '',
        Timestamp: item.timestamp || ''
      }));
      const csv = generateCsv(rows);
      const filename = targetOrigin ? `boltclone-report-${targetOrigin.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9-_]/g, '_')}.csv` : 'boltclone-report.csv';
      downloadFile(filename, csv);
    });
  });
}

function timeoutFetch(url, opts = {}, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
    fetch(url, opts).then((resp) => { clearTimeout(timer); resolve(resp); })
      .catch((err) => { clearTimeout(timer); reject(err); });
  });
}

function normalizeUrl(value) {
  try {
    if (!value.startsWith('http://') && !value.startsWith('https://')) value = `https://${value}`;
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.host}`;
  } catch {
    return null;
  }
}

function downloadFile(filename, text) {
  const a = document.createElement('a');
  const mime = filename.endsWith('.csv') ? 'text/csv;charset=utf-8' : 'text/json;charset=utf-8';
  a.setAttribute('href', `data:${mime},` + encodeURIComponent(text));
  a.setAttribute('download', filename);
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function csvEscape(value) {
  if (value == null) return '';
  const text = String(value).replace(/"/g, '""');
  return `"${text}"`;
}

function generateCsv(rows) {
  if (!rows || !rows.length) return '';
  const headers = Object.keys(rows[0]);
  const lines = [headers.map(csvEscape).join(',')];
  rows.forEach((row) => {
    lines.push(headers.map((header) => csvEscape(row[header])).join(','));
  });
  return lines.join('\n');
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function statusClass(status) {
  if (!status) return 'status-error';
  if (status >= 200 && status < 300) return 'status-2xx';
  if (status >= 400 && status < 500) return 'status-4xx';
  return 'status-5xx';
}

function getMitigation(key) {
  if (!key) return 'Validate input and apply secure controls.';
  key = key.toLowerCase();
  if (key.includes('sql')) return 'Use parameterized queries and ORM bindings; forbid raw query concatenation.';
  if (key.includes('xss')) return 'Escape / sanitize output and enforce Content-Security-Policy.';
  if (key.includes('ssrf')) return 'Enforce allowlist of outbound hosts and block metadata IP ranges.';
  if (key.includes('csrf')) return 'Use anti-CSRF tokens and SameSite cookie policy.';
  if (key.includes('idor') || key.includes('bola')) return 'Enforce object ownership and ACL checks on all object IDs.';
  if (key.includes('headers')) return 'Add security headers: CSP, HSTS, X-Frame-Options, X-XSS-Protection.';
  if (key.includes('rate')) return 'Add throttling and per-user rate limits with monitoring.';
  return 'Validate and mitigate with secure coding controls.';
}

// --- Traffic aggregation -----------------------------------------------

function groupTrafficById(traffic) {
  const byId = new Map();
  traffic.forEach((entry) => {
    if (!entry.id) return;
    byId.set(entry.id, { ...(byId.get(entry.id) || {}), ...entry });
  });
  return Array.from(byId.values()).filter((e) => e.url && e.method);
}

function computeEndpoints(merged) {
  const byHost = new Map();
  merged.forEach((entry) => {
    let origin, pathname;
    try {
      const u = new URL(entry.url);
      origin = u.origin;
      pathname = u.pathname || '/';
    } catch { return; }
    if (!byHost.has(origin)) byHost.set(origin, new Map());
    const paths = byHost.get(origin);
    const key = `${entry.method} ${pathname}`;
    if (!paths.has(key)) {
      paths.set(key, { method: entry.method, path: pathname, status: entry.statusCode, count: 0, hasAuth: false });
    }
    const rec = paths.get(key);
    rec.count += 1;
    if (typeof entry.statusCode === 'number') rec.status = entry.statusCode;
    if (entry.requestHeaders?.some((h) => h.name.toLowerCase() === 'authorization')) rec.hasAuth = true;
  });
  return byHost;
}

function computeParams(merged) {
  const header = new Map();
  const body = new Map();
  const query = new Map();
  const response = new Map();

  const bump = (map, name, value, entry) => {
    if (!map.has(name)) map.set(name, { values: new Set(), used: new Set() });
    const rec = map.get(name);
    if (value !== undefined && value !== null) rec.values.add(String(value));
    try {
      const u = new URL(entry.url);
      rec.used.add(`${entry.method} ${u.pathname}`);
    } catch { /* ignore */ }
  };

  merged.forEach((entry) => {
    (entry.requestHeaders || []).forEach((h) => {
      const name = h.name.toLowerCase();
      if (NOISE_HEADERS.has(name)) return;
      bump(header, h.name, h.value, entry);
    });

    (entry.responseHeaders || []).forEach((h) => {
      const name = h.name.toLowerCase();
      if (NOISE_HEADERS.has(name) || name === 'content-type') return;
      bump(response, h.name, h.value, entry);
    });

    try {
      const u = new URL(entry.url);
      u.searchParams.forEach((value, name) => bump(query, name, value, entry));
    } catch { /* ignore */ }

    if (entry.requestBody?.formData) {
      Object.entries(entry.requestBody.formData).forEach(([name, values]) => {
        bump(body, name, Array.isArray(values) ? values[0] : values, entry);
      });
    }
    if (entry.requestBody?.raw?.[0]?.text) {
      try {
        const parsed = JSON.parse(entry.requestBody.raw[0].text);
        if (parsed && typeof parsed === 'object') {
          Object.entries(parsed).forEach(([name, value]) => bump(body, name, value, entry));
        }
      } catch { /* not JSON, skip */ }
    }
  });

  return { header, body, query, response };
}

function classifyAuth(merged) {
  const buckets = { jwt: new Map(), apikey: new Map(), basic: new Map(), cookie: new Map() };
  const bump = (map, key, entry) => {
    if (!map.has(key)) map.set(key, { count: 0, entries: [] });
    const rec = map.get(key);
    rec.count += 1;
    rec.entries.push(entry);
  };

  merged.forEach((entry) => {
    (entry.requestHeaders || []).forEach((h) => {
      const name = h.name.toLowerCase();
      const val = h.value || '';
      if (name === 'authorization') {
        if (/^bearer\s+ey/i.test(val)) bump(buckets.jwt, val.replace(/^bearer\s+/i, ''), entry);
        else if (/^basic\s+/i.test(val)) bump(buckets.basic, val, entry);
        else if (val) bump(buckets.apikey, val, entry);
      } else if (['x-api-key', 'api-key', 'apikey'].includes(name)) {
        bump(buckets.apikey, val, entry);
      } else if (name === 'cookie') {
        bump(buckets.cookie, val, entry);
      }
    });
  });

  return buckets;
}

function jwtStatus(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp) return Date.now() < payload.exp * 1000 ? 'Active' : 'Expired';
  } catch { /* not a valid JWT payload */ }
  return 'Detected';
}

// --- Rendering: Traffic --------------------------------------------------

function renderTraffic() {
  const merged = state.merged
    .slice()
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const methodCounts = new Map();
  merged.forEach((e) => methodCounts.set(e.method, (methodCounts.get(e.method) || 0) + 1));

  els.methodChips.innerHTML = Array.from(methodCounts.entries())
    .map(([method, count]) => `<button class="chip" data-method="${escapeHtml(method)}">${escapeHtml(method)} <span>${count}</span></button>`)
    .join('');

  const activeMethodChip = els.methodChips.querySelector('.chip.active');
  const filterMethod = activeMethodChip?.dataset.method;
  const rows = filterMethod ? merged.filter((e) => e.method === filterMethod) : merged;

  if (rows.length === 0) {
    els.trafficList.innerHTML = '<div class="empty-state">No traffic captured yet.</div>';
  } else {
    els.trafficList.innerHTML = rows.slice(0, 100).map((e) => {
      let path = e.url, host = '';
      try { const u = new URL(e.url); path = u.pathname || '/'; host = u.host; } catch { /* keep raw */ }
      return `<div class="card">
        <span class="method-badge method-${escapeHtml(e.method)}">${escapeHtml(e.method)}</span>
        <div class="main"><div class="path">${escapeHtml(path)}</div><div class="host">${escapeHtml(host)}</div></div>
        <span class="status-pill ${statusClass(e.statusCode)}">${e.statusCode || 'n/a'}</span>
      </div>`;
    }).join('');
  }

  els.countTraffic.textContent = String(merged.length);
}

// --- Rendering: Params -----------------------------------------------

function renderParams() {
  const merged = state.merged;
  const { header, body, query, response } = computeParams(merged);
  const inputCount = header.size + body.size + query.size;

  els.cntHeader.textContent = header.size;
  els.cntBody.textContent = body.size;
  els.cntQuery.textContent = query.size;
  els.cntInput.textContent = inputCount;
  els.cntResponse.textContent = response.size;
  els.countParams.textContent = String(inputCount + response.size);

  const kindMap = { header, body, query, response, input: null };
  let map = kindMap[state.activeParamType];
  if (state.activeParamType === 'input') {
    map = new Map([...header, ...body, ...query]);
  }

  const entries = Array.from((map || new Map()).entries());
  if (entries.length === 0) {
    els.paramsList.innerHTML = '<div class="empty-state">No parameters observed for this type yet.</div>';
    return;
  }

  els.paramsList.innerHTML = entries.map(([name, rec]) => {
    const values = Array.from(rec.values).slice(0, 3).map((v) => `<span class="param-value">${escapeHtml(v.length > 40 ? v.slice(0, 40) + '…' : v)}</span>`).join('');
    const used = Array.from(rec.used).slice(0, 4).join(', ');
    return `<div class="param-card">
      <div class="row1">
        <span><span class="param-kind">${escapeHtml(state.activeParamType)}</span> <span class="param-name">${escapeHtml(name)}</span></span>
        <span class="param-count">${rec.used.size}x</span>
      </div>
      <div class="param-values">${values}</div>
      <div class="param-used">Used in: ${escapeHtml(used)}</div>
    </div>`;
  }).join('');
}

// --- Rendering: Endpoints ----------------------------------------------

function renderEndpoints() {
  const merged = state.merged;
  const byHost = computeEndpoints(merged);

  els.countEndpoints.textContent = String(Array.from(byHost.values()).reduce((sum, m) => sum + m.size, 0));

  if (byHost.size === 0) {
    els.endpointsList.innerHTML = '<div class="empty-state">No endpoints discovered yet.</div>';
    return;
  }

  els.endpointsList.innerHTML = Array.from(byHost.entries()).map(([origin, paths]) => {
    const rows = Array.from(paths.values()).map((rec) => `
      <div class="card">
        <span class="method-badge method-${escapeHtml(rec.method)}">${escapeHtml(rec.method)}</span>
        <div class="main"><div class="path">${escapeHtml(rec.path)}</div></div>
        <span class="icons">${rec.hasAuth ? '🔒' : ''}</span>
        <span class="param-count">${rec.count}</span>
      </div>`).join('');
    return `<div class="host-group">
      <div class="host-group-head"><span>${escapeHtml(origin)}</span><span>${paths.size} endpoints</span></div>
      ${rows}
    </div>`;
  }).join('');
}

// --- Rendering: Auth -----------------------------------------------------

function renderAuth() {
  const merged = state.merged;
  const buckets = classifyAuth(merged);

  els.cntJwt.textContent = buckets.jwt.size;
  els.cntApiKey.textContent = buckets.apikey.size;
  els.cntBasic.textContent = buckets.basic.size;
  els.cntCookie.textContent = buckets.cookie.size;
  els.countAuth.textContent = String(buckets.jwt.size + buckets.apikey.size + buckets.basic.size + buckets.cookie.size);

  const map = buckets[state.activeAuthType] || new Map();
  const entries = Array.from(map.entries());

  if (entries.length === 0) {
    els.authList.innerHTML = '<div class="empty-state">No credentials of this type observed yet.</div>';
    return;
  }

  els.authList.innerHTML = entries.map(([token, rec]) => {
    const short = token.length > 28 ? `${token.slice(0, 14)}…${token.slice(-6)}` : token;
    const status = state.activeAuthType === 'jwt' ? jwtStatus(token) : 'Detected';
    return `<div class="auth-card">
      <span class="auth-kind">${escapeHtml(state.activeAuthType)}</span>
      <span class="auth-token" title="${escapeHtml(token)}">${escapeHtml(short)}</span>
      <span class="auth-status">${escapeHtml(status)}</span>
      <span class="auth-reqs">${rec.count} reqs</span>
    </div>`;
  }).join('');
}

// --- Rendering: Security tab ---------------------------------------------

function testProgressWidth(count) {
  if (count === 0) return 4;
  return Math.min(100, 20 + count * 15);
}

function renderSecurity() {
  const counts = { BOLA: 0, RBAC: 0, MassAssignment: 0 };
  state.analysis.forEach((f) => { if (counts[f.type] !== undefined) counts[f.type] += 1; });

  const merged = state.merged;
  const jwtCount = classifyAuth(merged).jwt.size;

  const cards = [
    { title: 'JWT Security Tests', count: jwtCount, key: 'jwt' },
    { title: 'BOLA Tests', count: counts.BOLA, key: 'bola' },
    { title: 'RBAC Tests', count: counts.RBAC, key: 'rbac' },
    { title: 'Mass Assignment Tests', count: counts.MassAssignment, key: 'mass' }
  ];

  els.testCardList.innerHTML = cards.map((c) => `
    <div class="test-card">
      <div class="row1">
        <span class="title">${escapeHtml(c.title)}</span>
        <span class="count">${c.count}</span>
      </div>
      <div class="row2">
        <div class="progress-track"><div class="progress-fill" style="width:${testProgressWidth(c.count)}%"></div></div>
        <button class="link-btn" data-run="${c.key}">Run Deep Test &rarr;</button>
      </div>
    </div>`).join('');

  const totalFindings = counts.BOLA + counts.RBAC + counts.MassAssignment;
  els.countSecurityFindings.textContent = String(totalFindings);
  els.testDot.classList.toggle('hidden', totalFindings === 0);

  if (state.hosts.length === 0) {
    els.detectedHostList.innerHTML = '<div class="empty-state">No traffic analyzed yet.</div>';
  } else {
    els.detectedHostList.innerHTML = state.hosts.map((h) => `
      <div class="detected-card">
        <strong>${escapeHtml(h.name)} API</strong>
        <div class="host">${escapeHtml(h.origin)}</div>
        <div class="tag-row">${h.tags.map((t) => `<span class="tag tag-${t.kind}">${escapeHtml(t.label)}</span>`).join('')}</div>
      </div>`).join('');
  }

  if (counts.RBAC > 0) {
    els.rbacCount.textContent = String(counts.RBAC);
    if (!els.rbacBanner.dataset.dismissed) els.rbacBanner.classList.remove('hidden');
  } else {
    els.rbacBanner.classList.add('hidden');
  }
}

function renderDiscoverAll() {
  renderTraffic();
  renderParams();
  renderEndpoints();
  renderAuth();
}

// --- Manipulator wizard --------------------------------------------------

function wizardApiList() {
  const byHost = new Map();
  state.discoveredApis.forEach((item) => {
    let origin;
    try { origin = new URL(item.url).origin; } catch { return; }
    if (!byHost.has(origin)) byHost.set(origin, { methods: new Set(), count: 0 });
    const rec = byHost.get(origin);
    rec.methods.add(item.method || 'GET');
    rec.count += 1;
  });
  return byHost;
}

function renderWizStep1() {
  const byHost = wizardApiList();
  if (byHost.size === 0) {
    els.wizApiList.innerHTML = '<div class="empty-state">No APIs discovered yet. Capture some traffic first.</div>';
    return;
  }
  els.wizApiList.innerHTML = Array.from(byHost.entries()).map(([origin, rec]) => {
    const selected = state.wizard.api === origin ? 'selected' : '';
    const methods = Array.from(rec.methods).slice(0, 2).map((m) => `<span class="method-badge method-${escapeHtml(m)}">${escapeHtml(m)}</span>`).join(' ');
    return `<div class="card selectable ${selected}" data-api="${escapeHtml(origin)}">
      <div class="main"><div class="path">${escapeHtml(origin)}</div><div class="host">${rec.count} endpoints</div></div>
      ${methods}
    </div>`;
  }).join('');
}

function renderWizStep2() {
  const endpoints = state.discoveredApis.filter((item) => {
    try { return new URL(item.url).origin === state.wizard.api; } catch { return false; }
  });
  const unique = new Map();
  endpoints.forEach((item) => {
    try {
      const u = new URL(item.url);
      const key = `${item.method} ${u.pathname}`;
      if (!unique.has(key)) unique.set(key, { method: item.method || 'GET', path: u.pathname, url: item.url });
    } catch { /* skip */ }
  });

  if (unique.size === 0) {
    els.wizEndpointList.innerHTML = '<div class="empty-state">No endpoints found for this API.</div>';
    return;
  }

  els.wizEndpointList.innerHTML = Array.from(unique.values()).map((rec) => {
    const selected = state.wizard.endpoint?.url === rec.url ? 'selected' : '';
    return `<div class="card selectable ${selected}" data-endpoint-url="${escapeHtml(rec.url)}" data-endpoint-method="${escapeHtml(rec.method)}">
      <span class="method-badge method-${escapeHtml(rec.method)}">${escapeHtml(rec.method)}</span>
      <div class="main"><div class="path">${escapeHtml(rec.path)}</div></div>
    </div>`;
  }).join('');
}

function renderWizStep4() {
  const target = state.wizard.endpoint?.url || state.wizard.api;
  const tests = Array.from(els.wizTestChecks.querySelectorAll('input[type=checkbox]:checked'))
    .map((cb) => cb.parentElement.textContent.trim());
  els.wizReview.innerHTML = `
    <dt>Target</dt><dd>${escapeHtml(target || '(none)')}</dd>
    <dt>Tests</dt><dd>${tests.length ? escapeHtml(tests.join(', ')) : 'None selected'}</dd>`;
}

async function runWizardTests() {
  const target = state.wizard.endpoint?.url || state.wizard.api;
  els.wizResults.innerHTML = '<div class="empty-state">Running tests…</div>';
  const findings = [];

  try {
    const url = new URL(target);

    if (els.wzRateLimit.checked) {
      const attempts = await Promise.all(Array.from({ length: 6 }, () => timeoutFetch(target, { method: 'GET', mode: 'cors' }, 8000).catch((e) => e)));
      const statuses = attempts.filter((r) => r instanceof Response).map((r) => r.status);
      if (!statuses.includes(429) && statuses.filter((s) => s >= 200 && s < 300).length > 3) {
        findings.push({ title: 'No rate-limiting detected', severity: 'medium', evidence: `Statuses: ${statuses.join(', ')}` });
      }
    }

    if (els.wzIdor.checked) {
      const segments = url.pathname.split('/').filter(Boolean);
      const idx = segments.findIndex((s) => /^\d+$/.test(s));
      if (idx !== -1) {
        const original = segments[idx];
        const alt = String(Number(original) + 1);
        const trial = new URL(target);
        trial.pathname = url.pathname.replace(`/${original}`, `/${alt}`);
        const resp = await timeoutFetch(trial.toString(), { method: 'GET', mode: 'cors' }, 8000).catch(() => null);
        if (resp && resp.status >= 200 && resp.status < 300) {
          findings.push({ title: 'Potential IDOR/BOLA', severity: 'high', evidence: `${trial.toString()} returned ${resp.status}` });
        }
      }
    }

    if (els.wzSql.checked) {
      const trial = new URL(target);
      trial.searchParams.set('q', "' OR '1'='1");
      const resp = await timeoutFetch(trial.toString(), { method: 'GET', mode: 'cors' }, 8000).catch(() => null);
      if (resp && resp.status >= 200 && resp.status < 300) {
        const text = await resp.text();
        if (text.toLowerCase().includes('sql') || text.toLowerCase().includes('syntax error')) {
          findings.push({ title: 'Potential SQL Injection', severity: 'high', evidence: `Response contained SQL error indicators (status ${resp.status})` });
        }
      }
    }

    if (els.wzXss.checked) {
      const trial = new URL(target);
      trial.searchParams.set('q', '<script>alert(1)</script>');
      const resp = await timeoutFetch(trial.toString(), { method: 'GET', mode: 'cors' }, 8000).catch(() => null);
      if (resp && resp.status >= 200 && resp.status < 300) {
        const text = await resp.text();
        if (text.includes('<script>alert(1)</script>')) {
          findings.push({ title: 'Potential Reflected XSS', severity: 'high', evidence: 'Payload reflected unescaped in response body.' });
        }
      }
    }

    if (els.wzCsrf.checked) {
      const resp = await timeoutFetch(target, { method: 'OPTIONS', mode: 'cors' }, 8000).catch(() => null);
      const allow = resp?.headers.get('access-control-allow-methods') || '';
      if (/put|delete|post/i.test(allow)) {
        findings.push({ title: 'Potential CSRF risk', severity: 'medium', evidence: `CORS allows: ${allow}` });
      }
    }

    if (els.wzSsrf.checked) {
      const trial = new URL(target);
      trial.searchParams.set('target', 'http://169.254.169.254/latest/meta-data/');
      const resp = await timeoutFetch(trial.toString(), { method: 'GET', mode: 'cors' }, 8000).catch(() => null);
      if (resp && resp.status >= 200 && resp.status < 300) {
        findings.push({ title: 'Potential SSRF vector', severity: 'high', evidence: 'Endpoint accepted an internal metadata URL parameter.' });
      }
    }

    if (els.wzOpenRedirect.checked) {
      const trial = new URL(target);
      trial.searchParams.set('redirect', 'http://example.com/');
      const resp = await timeoutFetch(trial.toString(), { method: 'GET', mode: 'cors' }, 8000).catch(() => null);
      const locationHeader = resp?.headers?.get('location') || '';
      if (resp && resp.status >= 300 && resp.status < 400 && locationHeader.includes('example.com')) {
        findings.push({ title: 'Potential Open Redirect', severity: 'high', evidence: `Redirected to ${locationHeader}` });
      } else if (resp && resp.status >= 200 && resp.status < 300) {
        const text = await resp.text();
        if (text.includes('http://example.com') || text.includes('https://example.com')) {
          findings.push({ title: 'Potential Open Redirect', severity: 'medium', evidence: 'External redirect URL reflected in response body.' });
        }
      }
    }

    if (els.wzCors.checked) {
      const resp = await timeoutFetch(target, { method: 'OPTIONS', mode: 'cors' }, 8000).catch(() => null);
      const allowOrigin = resp?.headers?.get('access-control-allow-origin') || '';
      const allowCreds = resp?.headers?.get('access-control-allow-credentials') || '';
      if (allowOrigin === '*' && allowCreds === 'true') {
        findings.push({ title: 'CORS misconfiguration', severity: 'medium', evidence: `allow-origin: ${allowOrigin}, allow-credentials: ${allowCreds}` });
      } else if (allowOrigin && allowOrigin.toLowerCase().includes(url.origin.toLowerCase()) && allowCreds === 'true') {
        findings.push({ title: 'CORS misconfiguration', severity: 'medium', evidence: `Origin reflected in CORS response: ${allowOrigin}` });
      }
    }

    if (els.wzTraversal.checked) {
      const trial = new URL(target);
      trial.searchParams.set('file', '../etc/passwd');
      const resp = await timeoutFetch(trial.toString(), { method: 'GET', mode: 'cors' }, 8000).catch(() => null);
      if (resp && resp.status >= 200 && resp.status < 300) {
        const text = await resp.text();
        if (text.includes('root:') || text.includes('/etc/passwd')) {
          findings.push({ title: 'Potential Directory Traversal', severity: 'high', evidence: 'Response contained /etc/passwd content.' });
        }
      }
    }

    if (els.wzSecHeaders.checked) {
      const resp = await timeoutFetch(target, { method: 'GET', mode: 'cors' }, 8000).catch(() => null);
      if (resp) {
        const checks = { csp: 'content-security-policy', hsts: 'strict-transport-security', xfo: 'x-frame-options' };
        const missing = Object.entries(checks).filter(([, header]) => !resp.headers.get(header)).map(([key]) => key.toUpperCase());
        if (missing.length) findings.push({ title: 'Missing security headers', severity: 'medium', evidence: `Missing: ${missing.join(', ')}` });
      }
    }
  } catch (err) {
    findings.push({ title: 'Test run failed', severity: 'low', evidence: err.message || String(err) });
  }

  state.wizard.results = findings;
  renderWizResults();
}

function renderWizResults() {
  const findings = state.wizard.results || [];
  if (findings.length === 0) {
    els.wizResults.innerHTML = '<div class="empty-state">No issues detected by the selected tests.</div>';
    return;
  }
  els.wizResults.innerHTML = findings.map((f) => `
    <div class="detected-card">
      <strong>${escapeHtml(f.title)}</strong>
      <div class="host">${escapeHtml(f.evidence)}</div>
      <div class="tag-row"><span class="tag tag-${f.severity === 'high' ? 'red' : f.severity === 'medium' ? 'amber' : 'purple'}">${escapeHtml(f.severity)}</span></div>
      <p class="param-used">Mitigation: ${escapeHtml(getMitigation(f.title))}</p>
    </div>`).join('');
}

function updateWizardNav() {
  const step = state.wizard.step;
  document.querySelectorAll('.step').forEach((el) => {
    const n = Number(el.dataset.step);
    el.classList.toggle('active', n === step);
    el.classList.toggle('done', n < step);
  });
  document.querySelectorAll('.wiz-step').forEach((el) => el.classList.remove('active'));
  els[`wizStep${step}`].classList.add('active');

  const captions = ['Pick API', 'Pick an endpoint', 'Choose tests', 'Review', 'Results'];
  els.stepCaption.textContent = `Step ${step} of 5 — ${captions[step - 1]}`;
  els.wizBack.classList.toggle('hidden', step === 1);

  const hasTarget = !!(state.wizard.api || els.wizCustomUrl.value.trim());
  const canAdvance = { 1: hasTarget, 2: !!state.wizard.endpoint, 3: true, 4: true, 5: true };
  els.wizNext.disabled = !canAdvance[step];
  els.wizNext.textContent = step === 4 ? 'Run Tests' : step === 5 ? 'Start Over' : 'Next';

  if (step === 1) renderWizStep1();
  if (step === 2) renderWizStep2();
  if (step === 4) renderWizReview();
  if (step === 5 && !state.wizard.results) runWizardTests();
}

function renderWizReview() { renderWizStep4(); }

function resetWizard() {
  state.wizard = { step: 1, api: null, endpoint: null, results: null };
  els.wizCustomUrl.value = '';
  updateWizardNav();
}

// --- Landing / capture control -------------------------------------------

function showDashboard(show) {
  els.landing.classList.toggle('hidden', show);
  els.dashboard.classList.toggle('hidden', !show);
  els.stopCaptureBtn.classList.toggle('hidden', !show);
}

function safeSendMessage(message, callback) {
  chrome.runtime.sendMessage(message, (res) => {
    if (chrome.runtime.lastError) {
      console.warn('sendMessage failed', message?.type, chrome.runtime.lastError.message);
      callback?.(null);
      return;
    }
    callback?.(res);
  });
}

function sendMessageAsync(message) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(message, (res) => {
      if (chrome.runtime.lastError) {
        console.warn('sendMessageAsync failed', message?.type, chrome.runtime.lastError.message);
        resolve(null);
        return;
      }
      resolve(res);
    });
  });
}

let refreshInFlight = false;
let refreshQueued = false;

async function refreshAll() {
  if (refreshInFlight) {
    refreshQueued = true;
    return;
  }
  refreshInFlight = true;
  try {
    await runRefreshAll();
  } finally {
    refreshInFlight = false;
    if (refreshQueued) {
      refreshQueued = false;
      refreshAll();
    }
  }
}

async function runRefreshAll() {
  const [trafficRes, discoveredRes, analysisRes, hostsRes, scanRes, rulesRes] = await Promise.all([
    sendMessageAsync({ type: 'getTraffic' }),
    sendMessageAsync({ type: 'getDiscoveredApis' }),
    sendMessageAsync({ type: 'getAnalysis' }),
    sendMessageAsync({ type: 'getHostAnalysis' }),
    sendMessageAsync({ type: 'getScanState' }),
    sendMessageAsync({ type: 'getCaptureRules' })
  ]);

  state.traffic = trafficRes?.traffic || [];
  state.merged = groupTrafficById(state.traffic);
  state.discoveredApis = discoveredRes?.discoveredApis || [];
  state.analysis = analysisRes?.analysis || [];
  state.hosts = hostsRes?.hosts || [];
  state.captureRules = rulesRes?.rules || [];
  state.scanState = scanRes?.scanState || 'stopped';

  // Ensure UI state is updated
  renderDiscoverAll();
  renderSecurity();
  renderRuleList();
  if (state.activeMainTab === 'test') renderWizStep1();
  const shouldShowDashboard = state.scanState === 'running' || (!state.forceLanding && state.traffic.length > 0);
  showDashboard(shouldShowDashboard);

  // Prefill target URL input from stored origin or active tab when empty
  try {
    chrome.storage.local.get({ boltcloneTargetOrigin: null, boltcloneCaptureMode: 'api' }, ({ boltcloneTargetOrigin, boltcloneCaptureMode }) => {
      state.captureMode = boltcloneCaptureMode || 'api';
      // reflect capture mode in the UI
      els.modeApi.classList.toggle('active', state.captureMode === 'api');
      els.modeAll.classList.toggle('active', state.captureMode === 'all');

      if (boltcloneTargetOrigin) {
        // set the field to the saved origin
        if (els.targetUrl) els.targetUrl.value = boltcloneTargetOrigin;
      } else {
        // if no saved origin and the input is empty, try to prefill from the active tab
        if (els.targetUrl && !els.targetUrl.value.trim()) {
          try {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
              const t = tabs && tabs[0];
              if (t && t.url) {
                const n = normalizeUrl(t.url);
                if (n) els.targetUrl.value = n;
              }
            });
          } catch (e) {
            // ignore tab lookup errors
          }
        }
      }
    });
  } catch (e) {
    // ignore storage read errors
  }
}

// --- Event wiring ----------------------------------------------------

function addRuleFromInput() {
  const value = els.newRuleInput.value.trim();
  if (!value) return;
  safeSendMessage({ type: 'addCaptureRule', value }, (res) => {
    if (res?.rules) {
      state.captureRules = res.rules;
      els.newRuleInput.value = '';
      renderRuleList();
    }
  });
}

function renderRuleList() {
  if (!els.ruleList) return;
  if (!state.captureRules.length) {
    els.ruleList.innerHTML = '<div class="empty-state">No capture rules yet. Add a hostname, origin, path, or wildcard.</div>';
    return;
  }

  els.ruleList.innerHTML = state.captureRules.map((rule) => {
    const status = rule.enabled ? 'enabled' : 'disabled';
    return `<div class="card rule-card ${status}" data-rule-id="${escapeHtml(rule.id)}">
      <div class="row1">
        <div class="rule-value">${escapeHtml(rule.value)}</div>
        <div class="rule-actions">
          <button class="btn pill tiny toggle-rule" data-rule-id="${escapeHtml(rule.id)}">${rule.enabled ? 'Disable' : 'Enable'}</button>
          <button class="btn pill danger tiny remove-rule" data-rule-id="${escapeHtml(rule.id)}">Remove</button>
        </div>
      </div>
    </div>`;
  }).join('');
}

function setMode(mode) {
  state.captureMode = mode;
  els.modeApi.classList.toggle('active', mode === 'api');
  els.modeAll.classList.toggle('active', mode === 'all');
  safeSendMessage({ type: 'setCaptureMode', mode });
}

function wireThemeToggle() {
  safeListen(els.themeToggle, 'click', () => {
    darkTheme = !darkTheme;
    document.documentElement.dataset.theme = darkTheme ? 'dark' : 'light';
    if (els.themeToggle) els.themeToggle.innerHTML = darkTheme ? '&#127769;' : '&#9728;';
  });
}

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local') return;
  if (changes.boltcloneTraffic || changes.discoveredApis || changes.boltcloneAnalysis || changes.boltcloneCaptureRules) {
    refreshAll();
  }
});

document.addEventListener('DOMContentLoaded', () => {
  try {
    initPopup();
    refreshAll();
    setInterval(refreshAll, 4000);
  } catch (err) {
    console.error('popup init failed', err);
  }
});
