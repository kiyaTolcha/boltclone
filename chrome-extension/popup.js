const targetInput = document.getElementById('targetUrl');
const proxyInput = document.getElementById('proxyUrl');
const modeApiButton = document.getElementById('modeApi');
const modeAllButton = document.getElementById('modeAll');
const scanCurrentTab = document.getElementById('chScanCurrent');
const scanAllTabs = document.getElementById('chScanAllTabs');
const allTrafficProxy = document.getElementById('allTrafficProxy');
const scanButton = document.getElementById('scanButton');
const fromTabButton = document.getElementById('fromTabButton');
const openSidePanelButton = document.getElementById('openSidePanel');
const startBgScanButton = document.getElementById('startBgScan');
const stopBgScanButton = document.getElementById('stopBgScan');
const exportAnalysisButton = document.getElementById('exportAnalysis');
const exportOpenApiButton = document.getElementById('exportOpenApi');
const result = document.getElementById('result');
const status = document.getElementById('status');
const historyList = document.getElementById('historyList');
const discoveryList = document.getElementById('discoveryList');
const refreshDiscovery = document.getElementById('refreshDiscovery');
const tabButtons = document.querySelectorAll('.tab-btn');

const severityColors = {
  critical: '#ff5c64',
  high: '#ff9f43',
  medium: '#ffd166',
  low: '#69d0a3'
};

function severityColor(s) {
  return severityColors[s] || '#94caff';
}

function setActivePage(pageId) {
  const pages = ['capturePage', 'discoveryPage', 'historyPage'];
  pages.forEach((p) => {
    const el = document.getElementById(p);
    if (el) {
      el.classList.toggle('active', p === pageId);
    }
  });

  tabButtons.forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.target === pageId);
  });
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

function updateCaptureModeUi(mode) {
  if (mode === 'all') {
    modeAllButton?.classList.add('active');
    modeAllButton?.classList.remove('secondary');
    modeApiButton?.classList.remove('active');
    modeApiButton?.classList.add('secondary');
  } else {
    modeApiButton?.classList.add('active');
    modeApiButton?.classList.remove('secondary');
    modeAllButton?.classList.remove('active');
    modeAllButton?.classList.add('secondary');
  }
  status.textContent = `Capture mode: ${mode}.`;
}

function setCaptureMode(mode) {
  const normalized = mode === 'all' ? 'all' : 'api';
  chrome.runtime.sendMessage({ type: 'setCaptureMode', mode: normalized }, (response) => {
    console.log('setCaptureMode', response);
    updateCaptureModeUi(normalized);
  });
}

async function openSidePanel() {
  if (!chrome.sidePanel) {
    result.innerHTML = '<p class="entry">sidePanel API is unsupported in this browser.</p>';
    return;
  }

  try {
    if (chrome.sidePanel.setOptions) {
      await chrome.sidePanel.setOptions({ path: 'panel.html', enabled: true });
    }

    if (chrome.sidePanel.open) {
      await chrome.sidePanel.open({});
      result.innerHTML = '<p class="entry">Side panel opened successfully.</p>';
    } else {
      result.innerHTML = '<p class="entry">sidePanel.open() is not available; panel options set.</p>';
    }
  } catch (err) {
    result.innerHTML = `<p class="entry">Failed to open side panel: ${err.message || err}</p>`;
  }
}

async function aiEnrichScan(scan) {
  try {
    const useAi = document.getElementById('chUseAi').checked;
    if (!useAi) return scan;

    const mode = document.getElementById('aiMode').value;
    const apiKey = document.getElementById('aiKey').value.trim();

    const prompt = `APIsec BOLT local analysis request:\nTarget: ${scan.target}\nFindings:\n${scan.vulns.map((v) => `- ${v.title}: ${v.description} Evidence:${v.evidence}`).join('\n')}\nReturn a short remediation summary with risk prioritization.`;

    let responseJson;
    if (mode === 'openai') {
      if (!apiKey) {
        scan.ai = { error: 'OpenAI API key required.' };
        return scan;
      }
      responseJson = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: prompt }], max_tokens: 350 })
      }).then((r) => r.json());

      scan.ai = { provider: 'openai', summary: responseJson.choices?.[0]?.message?.content || 'No summary from OpenAI.' };
    } else {
      const localUrl = 'http://localhost:5000/api/llm';
      responseJson = await fetch(localUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt, model: 'local-llm' })
      }).then((r) => r.json());
      scan.ai = { provider: 'local', summary: responseJson?.answer || 'No local summary.' };
    }
  } catch (error) {
    scan.ai = { error: error.message || String(error) };
  }
  return scan;
}

function getFetchUrl(url) {
  const proxy = proxyInput.value.trim();
  return buildProxyUrl(url, proxy);
}

function renderResult(scan, append = false) {
  if (!append) {
    result.innerHTML = '';
  }

  const summary = document.createElement('div');
  summary.className = 'entry';
  summary.innerHTML = `<h3>Scan ${scan.target}</h3><p>Status: <strong>${scan.status}</strong>, OWASP coverage: <strong>${scan.owaspCoverage}/10</strong></p><p>Detected ${scan.vulns.length} issue(s)</p>`;
  result.appendChild(summary);

  const scoreBar = document.createElement('div');
  scoreBar.className = 'score-bar';
  scoreBar.innerHTML = `<div class="score-fill" style="width:${scan.score}%"></div><span class="score-value">${scan.score}%</span>`;
  result.appendChild(scoreBar);

  if (scan.vulns.length === 0) {
    const clearNote = document.createElement('p');
    clearNote.className = 'entry';
    clearNote.textContent = 'No vulnerability indicators found.';
    result.appendChild(clearNote);
  } else {
    scan.vulns.forEach((vuln) => {
      const node = document.createElement('div');
      node.className = 'vulnerability';
      node.style.borderColor = severityColor(vuln.severity);
      const mitigation = getMitigation(vuln.id || vuln.title);
      node.innerHTML = `<strong>${vuln.title}</strong> <small>${vuln.severity.toUpperCase()}</small><p>${vuln.description}</p><p><em>Evidence: ${vuln.evidence}</em></p><p class="mitigation"><strong>Mitigation:</strong> ${mitigation}</p>`;
      result.appendChild(node);
    });
  }

  if (scan.ai) {
    const aiContainer = document.createElement('div');
    aiContainer.className = 'vulnerability';
    aiContainer.style.borderColor = '#5d5dff';
    aiContainer.innerHTML = `<strong>AI Summary (${scan.ai.provider || 'ai'})</strong><p>${scan.ai.summary || scan.ai.error || 'No AI feedback.'}</p>`;
    result.appendChild(aiContainer);
  }
}

function renderHistory(entries) {
  historyList.innerHTML = '';
  if (!entries.length) {
    historyList.innerHTML = '<li>No prior scans.</li>';
    return;
  }
  entries.forEach((entry) => {
    const li = document.createElement('li');
    li.textContent = `${new Date(entry.scannedAt).toLocaleTimeString()} - ${entry.target} - ${entry.vulns.length} issues - score ${entry.score}%`;
    historyList.appendChild(li);
  });
}

function renderDiscoveredApis(entries) {
  if (!discoveryList) return;
  discoveryList.innerHTML = '';
  if (!entries || entries.length === 0) {
    discoveryList.innerHTML = '<li>No discovered API calls yet.</li>';
    return;
  }

  const unique = [];
  const seen = new Set();
  entries.slice(0, 40).forEach((item) => {
    const key = `${item.url}`;
    if (!seen.has(key)) {
      seen.add(key);
      unique.push(item);
    }
  });

  unique.forEach((item) => {
    const li = document.createElement('li');
    li.textContent = `${item.method || 'GET'} ${item.url} (${item.status || 'n/a'})`;
    li.title = `Saw at ${item.timestamp}`;
    discoveryList.appendChild(li);
  });
}

function loadDiscoveredApis() {
  chrome.runtime.sendMessage({ type: 'getDiscoveredApis' }, (response) => {
    if (response?.discoveredApis) {
      renderDiscoveredApis(response.discoveredApis);
    } else {
      chrome.storage.local.get({ discoveredApis: [] }, ({ discoveredApis = [] }) => {
        renderDiscoveredApis(discoveredApis);
      });
    }
  });
}

function updateScanStatus() {
  chrome.runtime.sendMessage({ type: 'getScanState' }, (response) => {
    const state = response?.scanState || 'stopped';
    status.textContent = `Background scan: ${state}.`; 
    setScanControlState(state);
  });
}

function loadAnalysis() {
  result.innerHTML = '<p class="entry">Loading latest background findings...</p>';
  chrome.runtime.sendMessage({ type: 'getAnalysis' }, (response) => {
    if (!response?.analysis || response.analysis.length === 0) {
      result.innerHTML = '<p class="entry">No vulnerability findings yet. Waiting for next background run.</p>';
      return;
    }

    result.innerHTML = '<p class="entry">Latest vulnerability analysis (background):</p>';
    response.analysis.forEach((item) => {
      const block = document.createElement('div');
      block.className = 'entry';
      block.innerHTML = `<strong>${item.title || 'Finding'}</strong>: ${item.description || 'No description'}<br/><small>${item.evidence || ''}</small>`;
      result.appendChild(block);
    });
  });
}

function downloadFile(filename, text) {
  const element = document.createElement('a');
  element.setAttribute('href', 'data:text/json;charset=utf-8,' + encodeURIComponent(text));
  element.setAttribute('download', filename);
  document.body.appendChild(element);
  element.click();
  document.body.removeChild(element);
}

function exportAnalysis() {
  chrome.runtime.sendMessage({ type: 'getAnalysis' }, (response) => {
    const data = response?.analysis || [];
    downloadFile('boltclone-analysis.json', JSON.stringify({ exportedAt: new Date().toISOString(), analysis: data }, null, 2));
    status.textContent = 'Analysis exported';
  });
}

function exportOpenApi() {
  chrome.runtime.sendMessage({ type: 'exportSpec' }, (response) => {
    if (response?.spec) {
      downloadFile('boltclone-openapi.json', JSON.stringify(response.spec, null, 2));
      status.textContent = 'OpenAPI spec exported';
    } else {
      status.textContent = 'OpenAPI spec export failed';
      console.error('exportSpec failed:', response);
    }
  });
}

function saveHistory(scan) {
  chrome.storage.local.get({ scanHistory: [] }, ({ scanHistory }) => {
    scanHistory.unshift({ ...scan, scannedAt: new Date().toISOString() });
    scanHistory = scanHistory.slice(0, 10);
    chrome.storage.local.set({ scanHistory });
    renderHistory(scanHistory);
  });
}

function normalizeUrl(value) {
  try {
    if (!value.startsWith('http://') && !value.startsWith('https://')) {
      value = `https://${value}`;
    }
    const parsed = new URL(value);
    return `${parsed.protocol}//${parsed.host}`; // base URL only
  } catch (error) {
    return null;
  }
}

function buildProxyUrl(targetUrl, proxyTemplate) {
  if (!proxyTemplate) {
    return targetUrl;
  }

  if (proxyTemplate.includes('{url}')) {
    return proxyTemplate.replace('{url}', encodeURIComponent(targetUrl));
  }

  try {
    const proxy = new URL(proxyTemplate);
    const result = new URL(proxy);
    if (result.search) {
      result.searchParams.set('url', targetUrl);
    } else {
      result.search = `?url=${encodeURIComponent(targetUrl)}`;
    }
    return result.toString();
  } catch (error) {
    return targetUrl;
  }
}

function timeoutFetch(url, opts = {}, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
    fetch(url, opts)
      .then((resp) => {
        clearTimeout(timer);
        resolve(resp);
      })
      .catch((err) => {
        clearTimeout(timer);
        reject(err);
      });
  });
}

async function runRateLimitTest(url) {
  const resolve = getFetchUrl(url);
  const requests = Array.from({ length: 8 }, () => timeoutFetch(resolve, { method: 'GET', mode: 'cors' }, 10000).catch((err) => err));
  const results = await Promise.all(requests);
  const statuses = results
    .filter((r) => r instanceof Response)
    .map((r) => r.status);

  const has429 = statuses.includes(429);
  const successCount = statuses.filter((s) => s >= 200 && s < 300).length;
  return { has429, successCount, statuses };
}

function isNumericSegment(pathSegment) {
  return /^[0-9]+$/.test(pathSegment);
}

async function runIdorBolaTest(url) {
  try {
    const target = new URL(url);
    const segments = target.pathname.split('/').filter(Boolean);
    const numericIndex = segments.findIndex(isNumericSegment);
    if (numericIndex === -1) {
      return null;
    }

    const originalValue = segments[numericIndex];
    const altValues = [String(Number(originalValue) + 1), String(Math.max(1, Number(originalValue) - 1))];

    const originalUrl = target.toString();
    const originalResp = await timeoutFetch(getFetchUrl(originalUrl), { method: 'GET', mode: 'cors' }, 10000).catch(() => null);
    if (!originalResp || originalResp.status < 200 || originalResp.status >= 300) {
      return null; // cannot confirm if endpoint not accessible
    }

    const altResults = [];
    for (const alt of altValues) {
      const trial = new URL(target.toString());
      trial.pathname = target.pathname.replace(`/${originalValue}`, `/${alt}`);
      const r = await timeoutFetch(getFetchUrl(trial.toString()), { method: 'GET', mode: 'cors' }, 10000).catch(() => null);
      altResults.push({ alt, status: r ? r.status : 0 });
    }

    const tooManyHits = altResults.filter((r) => r.status >= 200 && r.status < 300).length;
    if (tooManyHits > 0) {
      return {
        idor: true,
        evidence: `${altResults.map((i) => `${i.alt}:${i.status}`).join(', ')}`
      };
    }

    return null;
  } catch (error) {
    return null;
  }
}

async function runSqlInjectionTest(url) {
  try {
    const target = new URL(url);
    target.searchParams.set('q', "' OR '1'='1");
    const resp = await timeoutFetch(getFetchUrl(target.toString()), { method: 'GET', mode: 'cors' }, 10000).catch(() => null);
    if (!resp) return null;

    if (resp.status >= 200 && resp.status < 300) {
      const text = await resp.text();
      if (text.toLowerCase().includes('sql') || text.toLowerCase().includes('syntax error')) {
        return { sql: true, evidence: `Injected query returned ${resp.status} with SQL keywords in response` };
      }
      return { sql: true, evidence: `Injected query returned ${resp.status}` };
    }
    return null;
  } catch (error) {
    return null;
  }
}

async function runXssTest(url) {
  try {
    const target = new URL(url);
    target.searchParams.set('q', '<script>alert(1)</script>');
    const resp = await timeoutFetch(getFetchUrl(target.toString()), { method: 'GET', mode: 'cors' }, 10000).catch(() => null);
    if (!resp || resp.status < 200 || resp.status >= 300) return null;

    const text = await resp.text();
    if (text.includes('<script>alert(1)</script>') || text.toLowerCase().includes('script>alert')) {
      return { xss: true, evidence: 'Reflected XSS payload appears in response body.' };
    }
    return null;
  } catch (error) {
    return null;
  }
}

async function runSecurityHeadersTest(url) {
  try {
    const resp = await timeoutFetch(getFetchUrl(url), { method: 'GET', mode: 'cors' }, 10000).catch(() => null);
    if (!resp) return null;

    const headers = {
      xFrame: resp.headers.get('x-frame-options'),
      csp: resp.headers.get('content-security-policy'),
      hsts: resp.headers.get('strict-transport-security'),
      xssProtection: resp.headers.get('x-xss-protection'),
      referrerPolicy: resp.headers.get('referrer-policy')
    };

    const missing = Object.entries(headers).filter(([, v]) => !v).map(([k]) => k);
    if (missing.length > 0) {
      return { secheaders: true, evidence: `Missing security headers: ${missing.join(', ')}` };
    }
    return null;
  } catch (error) {
    return null;
  }
}

async function runCsrfTest(url) {
  try {
    const target = new URL(url);
    target.pathname = '/';
    const resp = await timeoutFetch(getFetchUrl(target.toString()), { method: 'OPTIONS', mode: 'cors' }, 10000).catch(() => null);
    if (!resp) return null;

    const allow = resp.headers.get('access-control-allow-methods') || '';
    if (allow.includes('PUT') || allow.includes('DELETE') || allow.includes('POST')) {
      return { csrf: true, evidence: `CORS allows stateful methods: ${allow}` };
    }
    return null;
  } catch (error) {
    return null;
  }
}

async function runSsrfTest(url) {
  try {
    const target = new URL(url);
    target.searchParams.set('target', 'http://169.254.169.254/latest/meta-data/');
    const resp = await timeoutFetch(getFetchUrl(target.toString()), { method: 'GET', mode: 'cors' }, 10000).catch(() => null);
    if (!resp || resp.status < 200 || resp.status >= 300) return null;

    const text = await resp.text();
    if (text.length > 10 || text.toLowerCase().includes('meta-data')) {
      return { ssrf: true, evidence: 'SSRF-like request returned potential metadata results.' };
    }
    return null;
  } catch (error) {
    return null;
  }
}

async function runEndpointsDiscovery(base) {
  const endpoints = ['/api', '/health', '/status', '/login', '/admin', '/openapi.json', '/swagger.json'];
  const found = [];
  for (const path of endpoints) {
    const url = `${base.replace(/\/+$/, '')}${path}`;
    const resp = await timeoutFetch(getFetchUrl(url), { method: 'GET', mode: 'cors' }, 6000).catch(() => null);
    if (resp && resp.status >= 200 && resp.status < 300) {
      found.push({ path, status: resp.status });
    }
  }
  return found;
}

async function scanTarget(rawTarget) {
  const target = normalizeUrl(rawTarget);
  const findings = [];
  if (!target) {
    return {
      target: rawTarget,
      status: 'failed',
      score: 0,
      owaspCoverage: 0,
      vulns: [{ title: 'Invalid target', severity: 'low', description: 'Target URL is invalid.', evidence: rawTarget }]
    };
  }

  let baseResponse = null;
  let corsBlocked = false;

  try {
    baseResponse = await timeoutFetch(getFetchUrl(target), { method: 'GET', mode: 'cors' }, 10000);
  } catch (error) {
    if (error instanceof TypeError && error.message.toLowerCase().includes('cors')) {
      corsBlocked = true;
    }
  }

  if (corsBlocked) {
    findings.push({ title: 'CORS Policy prevents in-browser API access', severity: 'medium', description: 'Target API rejects cross-site requests from untrusted origins.', evidence: 'Fetch TypeError from browser CORS enforcement.' });
  }

  if (!baseResponse) {
    return {
      target,
      status: 'failed',
      score: 20,
      owaspCoverage: 0,
      vulns: findings
    };
  }

  if (baseResponse.status === 401 || baseResponse.status === 403) {
    findings.push({ title: 'Authentication/Authorization observed', severity: 'low', description: 'API returns 401/403 without credentials.', evidence: `Status ${baseResponse.status}` });
  } else if (baseResponse.status >= 500) {
    findings.push({ title: 'Server error response', severity: 'high', description: 'Target returns 5xx status on unauthenticated request.', evidence: `Status ${baseResponse.status}` });
  }

  const shouldDoRateLimit = document.getElementById('chRateLimit').checked;
  const shouldDoIdor = document.getElementById('chIdor').checked;
  const shouldDoSql = document.getElementById('chSql').checked;
  const shouldDoXss = document.getElementById('chXss').checked;
  const shouldDoCsrf = document.getElementById('chCsrf').checked;
  const shouldDoSsrf = document.getElementById('chSsrf').checked;
  const shouldDoSecHeaders = document.getElementById('chSecHeaders').checked;

  if (shouldDoRateLimit) {
    const rateLimitResult = await runRateLimitTest(target);
    if (rateLimitResult.has429) {
      findings.push({ title: 'Rate limiting enforced', severity: 'low', description: 'HTTP 429 was returned while sending repeated requests.', evidence: `Response statuses: ${rateLimitResult.statuses.join(', ')}` });
    } else if (rateLimitResult.successCount > 3) {
      findings.push({ title: 'No rate-limiting detected', severity: 'medium', description: 'No HTTP 429 seen in rapid request burst.', evidence: `Response statuses: ${rateLimitResult.statuses.join(', ')}` });
    }
  }

  if (shouldDoIdor) {
    const idorResult = await runIdorBolaTest(target);
    if (idorResult) {
      findings.push({ title: 'Potential IDOR/BOLA', severity: 'high', description: 'Similar object IDs were accessible without authorization checks.', evidence: idorResult.evidence });
    }
  }

  if (shouldDoSql) {
    const sqlResult = await runSqlInjectionTest(target);
    if (sqlResult) {
      findings.push({ title: 'Potential SQL Injection endpoint', severity: 'high', description: 'Query injection payload accepted or produced indicators in response.', evidence: sqlResult.evidence });
    }
  }

  if (shouldDoXss) {
    const xssResult = await runXssTest(target);
    if (xssResult) {
      findings.push({ title: 'Potential XSS vulnerability', severity: 'high', description: 'Reflected script payload appeared in response body.', evidence: xssResult.evidence });
    }
  }

  if (shouldDoCsrf) {
    const csrfResult = await runCsrfTest(target);
    if (csrfResult) {
      findings.push({ title: 'Potential CSRF risk', severity: 'medium', description: 'State-changing methods allowed via CORS preflight.', evidence: csrfResult.evidence });
    }
  }

  if (shouldDoSsrf) {
    const ssrfResult = await runSsrfTest(target);
    if (ssrfResult) {
      findings.push({ title: 'Potential SSRF threat', severity: 'high', description: 'Injected URL query may reveal internal metadata content.', evidence: ssrfResult.evidence });
    }
  }

  if (shouldDoSecHeaders) {
    const headerResult = await runSecurityHeadersTest(target);
    if (headerResult) {
      findings.push({ title: 'Security headers missing', severity: 'medium', description: 'Critical response headers are not set.', evidence: headerResult.evidence });
    }
  }

  const discoveredEndpoints = await runEndpointsDiscovery(target);
  if (discoveredEndpoints.length > 0) {
    findings.push({ title: 'Common endpoint discovery', severity: 'low', description: `Found available endpoints: ${discoveredEndpoints.map((e) => e.path).join(', ')}`, evidence: `Endpoints statuses: ${discoveredEndpoints.map((e) => `${e.path}:${e.status}`).join(', ')}` });
  }

  const owaspCoverage = Math.max(0, 10 - findings.length);
  const score = Math.max(10, 100 - findings.length * 18);

  return {
    target,
    status: 'complete',
    score,
    owaspCoverage,
    vulns: findings
  };
}

async function doScan(rawTarget) {
  if (status) status.textContent = `Scanning ${rawTarget} ...`;
  const scan = await scanTarget(rawTarget);
  const enriched = await aiEnrichScan(scan);
  renderResult(enriched);
  saveHistory(enriched);
  if (status) status.textContent = `Last scan complete: ${scan.target}`;
  return enriched;
}

async function doScanAll() {
  scanButton.disabled = true;
  fromTabButton.disabled = true;
  result.innerHTML = '<p class="entry">Running discovery/scan across selected targets...</p>';

  const targets = new Set();
  const manual = targetInput.value.trim();
  if (manual) {
    const normalized = normalizeUrl(manual);
    if (normalized) targets.add(normalized);
  }

  const useCurrent = scanCurrentTab.checked;
  const useAllTabs = scanAllTabs.checked;

  if (useCurrent || useAllTabs) {
    const query = useAllTabs ? { currentWindow: true } : { active: true, currentWindow: true };
    const tabs = await new Promise((resolve) => chrome.tabs.query(query, resolve));
    tabs.forEach((tab) => {
      if (tab?.url) {
        const normalized = normalizeUrl(tab.url);
        if (normalized) targets.add(normalized);
      }
    });
  }

  if (targets.size === 0) {
    result.innerHTML = '<p class="entry">No URLs available to scan. Fill target or select tab options.</p>';
    scanButton.disabled = false;
    fromTabButton.disabled = false;
    return;
  }

  let first = true;
  for (const t of targets) {
    const scan = await scanTarget(t);
    const enriched = await aiEnrichScan(scan);
    renderResult(enriched, !first);
    saveHistory(enriched);
    first = false;
  }

  scanButton.disabled = false;
  fromTabButton.disabled = false;
}

scanButton.addEventListener('click', () => doScanAll());

fromTabButton.addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (tab?.url) {
      targetInput.value = tab.url;
      doScan(tab.url);
    } else {
      result.innerHTML = '<p class="entry">No active tab URL available.</p>';
    }
  });
});

if (modeApiButton) {
  modeApiButton.addEventListener('click', () => setCaptureMode('api'));
}
if (modeAllButton) {
  modeAllButton.addEventListener('click', () => setCaptureMode('all'));
}

function setScanControlState(scanState) {
  const running = scanState === 'running';
  if (startBgScanButton) {
    startBgScanButton.disabled = running;
    startBgScanButton.textContent = running ? 'Background Scan Running' : 'Start Background Scan';
    startBgScanButton.classList.toggle('disabled', running);
  }
  if (stopBgScanButton) {
    stopBgScanButton.disabled = !running;
    stopBgScanButton.textContent = running ? 'Stop Background Scan' : 'Background Scan Stopped';
    stopBgScanButton.classList.toggle('disabled', !running);
  }
}

if (startBgScanButton) {
  startBgScanButton.addEventListener('click', () => {
    startBgScanButton.disabled = true;
    stopBgScanButton.disabled = false;
    setScanControlState('running');
    chrome.runtime.sendMessage({ type: 'startScan' }, (resp) => {
      status.textContent = 'Background scanning is active. Traffic is being tracked automatically.';
      console.log('startScan', resp);
    });
  });
}

if (stopBgScanButton) {
  stopBgScanButton.addEventListener('click', () => {
    stopBgScanButton.disabled = true;
    startBgScanButton.disabled = false;
    setScanControlState('stopped');
    chrome.runtime.sendMessage({ type: 'stopScan' }, (resp) => {
      status.textContent = 'Background scanning stopped.';
      console.log('stopScan', resp);
    });
  });
}

if (openSidePanelButton) {
  openSidePanelButton.addEventListener('click', openSidePanel);
}

if (exportAnalysisButton) {
  exportAnalysisButton.addEventListener('click', exportAnalysis);
}

if (exportOpenApiButton) {
  exportOpenApiButton.addEventListener('click', exportOpenApi);
}

allTrafficProxy.addEventListener('click', async () => {
  const proxyUrl = proxyInput.value.trim();
  if (!proxyUrl) {
    result.innerHTML = '<p class="entry">Define proxy URL first for global traffic.</p>';
    return;
  }

  try {
    const rule = {
      mode: 'fixed_servers',
      rules: {
        proxyForHttp: { scheme: new URL(proxyUrl).protocol.replace(':', ''), host: new URL(proxyUrl).hostname, port: Number(new URL(proxyUrl).port || (new URL(proxyUrl).protocol === 'https:' ? 443 : 80)) },
        proxyForHttps: { scheme: new URL(proxyUrl).protocol.replace(':', ''), host: new URL(proxyUrl).hostname, port: Number(new URL(proxyUrl).port || (new URL(proxyUrl).protocol === 'https:' ? 443 : 80)) },
        bypassList: ['<local>']
      }
    };

    await chrome.proxy.settings.set({ value: rule, scope: 'regular' });
    result.innerHTML = '<p class="entry">Global proxy enabled for browser traffic.</p>';
  } catch (e) {
    result.innerHTML = `<p class="entry">Global proxy set failed: ${e.message}</p>`;
  }
});

chrome.storage.local.get({ scanHistory: [] }, ({ scanHistory }) => renderHistory(scanHistory));

if (refreshDiscovery) {
  refreshDiscovery.addEventListener('click', () => {
    setActivePage('discoveryPage');
    loadDiscoveredApis();
  });
}

if (tabButtons) {
  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => setActivePage(btn.dataset.target));
  });
}

chrome.storage.onChanged.addListener((changes) => {
  if (changes.discoveredApis) {
    renderDiscoveredApis(changes.discoveredApis.newValue || []);
  }
  if (changes.scanHistory) {
    renderHistory(changes.scanHistory.newValue || []);
  }
  if (changes.boltcloneAnalysis) {
    loadAnalysis();
  }
});

setActivePage('capturePage');
loadDiscoveredApis();
updateScanStatus();
loadAnalysis();

chrome.runtime.sendMessage({ type: 'getCaptureMode' }, (response) => {
  updateCaptureModeUi(response?.mode || 'api');
});

setInterval(() => {
  updateScanStatus();
  loadDiscoveredApis();
  loadAnalysis();
}, 3000);
