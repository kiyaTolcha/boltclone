const DISCOVERED_API_KEY = 'discoveredApis';
const MAX_DISCOVERED = 300;
const STATS_KEY = 'boltcloneTraffic';
const CAPTURE_RULES_KEY = 'boltcloneCaptureRules';

// load logic modules in service worker environment (import() is disallowed there)
importScripts('rules.js', 'openapi.js');

let captureMode = 'api';
let targetOrigin = null;
let captureRules = [];
let captureEnabled = false;

function loadCaptureMode() {
  chrome.storage.local.get({ boltcloneCaptureMode: 'api', boltcloneTargetOrigin: null, boltcloneCaptureRules: [], boltcloneScanState: 'stopped' }, ({ boltcloneCaptureMode, boltcloneTargetOrigin, boltcloneCaptureRules, boltcloneScanState }) => {
    captureMode = boltcloneCaptureMode || 'api';
    targetOrigin = boltcloneTargetOrigin || null;
    captureRules = Array.isArray(boltcloneCaptureRules) ? boltcloneCaptureRules : [];
    captureEnabled = boltcloneScanState === 'running';
    console.log('Background capture mode set:', captureMode, 'target:', targetOrigin, 'rules:', captureRules.length, 'enabled:', captureEnabled);
  });
}

function shouldCaptureTraffic(url) {
  if (!captureEnabled || !url) return false;
  return captureMode === 'all' ? true : matchesTarget(url);
}

function normalizeRulePattern(value) {
  if (!value || typeof value !== 'string') return null;
  return value.trim();
}

function captureRuleMatches(url, rule) {
  if (!rule || !rule.enabled) return false;
  const pattern = normalizeRulePattern(rule.value);
  if (!pattern) return false;
  try {
    const targetUrl = new URL(url);
    // Exact origin match or an origin/path prefix
    if (pattern.includes('://')) {
      const ruleUrl = new URL(pattern);
      if (ruleUrl.pathname === '/' || ruleUrl.pathname === '') {
        return targetUrl.origin === ruleUrl.origin;
      }
      return targetUrl.href.startsWith(ruleUrl.href.replace(/\/?$/, ''));
    }
    // Wildcard origin matching
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i');
      return regex.test(targetUrl.href) || regex.test(targetUrl.origin) || regex.test(targetUrl.host);
    }
    if (pattern.startsWith('/')) {
      return targetUrl.pathname.startsWith(pattern);
    }
    if (pattern.includes('/')) {
      return targetUrl.href.includes(pattern);
    }
    return targetUrl.host === pattern || targetUrl.host.endsWith(`.${pattern}`) || targetUrl.origin.includes(pattern);
  } catch {
    return url.includes(pattern);
  }
}

function matchesTarget(url) {
  if (!url) return false;
  try {
    if (captureRules.some((rule) => captureRuleMatches(url, rule))) return true;
    if (targetOrigin && new URL(url).origin === targetOrigin) return true;
    if (!targetOrigin) return isLikelyApiRequest(url);
    return false;
  } catch {
    return false;
  }
}

function scheduleScan() {
  console.log('Scheduling periodic scan alarm');
  chrome.alarms.create('boltcloneScan', { delayInMinutes: 0.1, periodInMinutes: 0.25 });
}

function stopScheduledScan() {
  console.log('Clearing periodic scan alarm');
  chrome.alarms.clear('boltcloneScan');
}

function analyzeNow() {
  try {
    chrome.storage.local.get({ [STATS_KEY]: [] }, ({ boltcloneTraffic }) => {
      const rawLog = boltcloneTraffic || [];
      console.log('analyzeNow rawLog length:', rawLog.length);
      if (rawLog.length > 0) {
        console.debug('analyzeNow sample entry:', rawLog[0]);
      }
      const findings = typeof analyzeTraffic === 'function' ? analyzeTraffic(rawLog) : [];
      console.log('analyzeNow findings count:', findings.length);
      const safeFindings = findings.map((f) => ({
        type: f.type,
        severity: f.severity,
        message: f.message,
        url: f.entry?.url,
        method: f.entry?.method,
        statusCode: f.entry?.statusCode,
        timestamp: f.entry?.timestamp
      }));
      chrome.storage.local.set({ boltcloneAnalysis: safeFindings });
      console.log('Periodic analysis result', safeFindings);
    });
  } catch (e) {
    console.error('Periodic analysis failed', e);
  }
}


function isLikelyApiRequest(url) {
  try {
    const u = new URL(url);
    const ext = u.pathname.split('.').pop().toLowerCase();
    const staticExt = ['png', 'jpg', 'jpeg', 'gif', 'svg', 'css', 'js', 'woff', 'woff2', 'ico', 'mp4', 'map'];
    if (staticExt.includes(ext)) return false;

    if (u.pathname.startsWith('/api') || u.pathname.endsWith('.json') || u.pathname.toLowerCase().includes('graphql')) {
      return true;
    }

    if (u.pathname.split('/').length > 2 && u.pathname.includes('/api')) {
      return true;
    }

    if (u.searchParams.toString().length > 0) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
}

function extractCandidate(url) {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return null;
  }
}

function normalizeRequestBody(requestBody) {
  if (!requestBody) return null;
  const normalized = {};
  if (requestBody.formData) {
    normalized.formData = requestBody.formData;
  }
  if (requestBody.raw) {
    // Convert raw typed arrays to safe text strings if possible
    normalized.raw = requestBody.raw.map((item) => {
      if (item.bytes instanceof ArrayBuffer || ArrayBuffer.isView(item.bytes)) {
        try {
          const bytes = item.bytes instanceof ArrayBuffer ? item.bytes : item.bytes.buffer;
          return { text: new TextDecoder().decode(bytes) };
        } catch (err) {
          return { text: null };
        }
      }
      return { text: null };
    });
  }
  return normalized;
}

let pendingTraffic = [];
let flushInProgress = false;

function saveTraffic(entry) {
  if (entry.requestBody) {
    entry.requestBody = normalizeRequestBody(entry.requestBody);
  }
  pendingTraffic.push(entry);
  scheduleFlush();
}

function scheduleFlush() {
  if (flushInProgress) return;
  flushInProgress = true;
  queueMicrotask(flushTraffic);
}

function flushTraffic() {
  if (pendingTraffic.length === 0) {
    flushInProgress = false;
    return;
  }
  const batch = pendingTraffic;
  pendingTraffic = [];

  chrome.storage.local.get({ [STATS_KEY]: [] }, ({ boltcloneTraffic }) => {
    const next = [...batch.slice().reverse(), ...(boltcloneTraffic || [])].slice(0, 1000);
    chrome.storage.local.set({ [STATS_KEY]: next }, () => {
      console.debug('Flushed traffic batch, size:', batch.length, 'total:', next.length);
      flushInProgress = false;
      if (pendingTraffic.length > 0) scheduleFlush();
    });
  });
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (!details.url || details.method === 'OPTIONS') return;

    if (!shouldCaptureTraffic(details.url)) return;

    const body = details.requestBody;

    saveTraffic({
      id: details.requestId,
      type: 'request',
      timestamp: new Date().toISOString(),
      url: details.url,
      method: details.method,
      requestBody: body || null,
      tabId: details.tabId
    });

    console.log('Captured request', details.url, 'method', details.method, 'mode', captureMode);
  },
  { urls: ['<all_urls>'] },
  ['requestBody']
);

chrome.webRequest.onSendHeaders.addListener(
  (details) => {
    if (!details.url || details.method === 'OPTIONS') return;

    if (!shouldCaptureTraffic(details.url)) return;

    saveTraffic({
      id: details.requestId,
      type: 'headers',
      timestamp: new Date().toISOString(),
      url: details.url,
      method: details.method,
      requestHeaders: details.requestHeaders || [],
      tabId: details.tabId
    });

    console.log('Captured request headers', details.url, 'method', details.method);
  },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'extraHeaders']
);

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (!details.url || details.method === 'OPTIONS') return;

    if (!shouldCaptureTraffic(details.url)) return;

    saveTraffic({
      id: details.requestId,
      type: 'response',
      timestamp: new Date().toISOString(),
      url: details.url,
      method: details.method,
      statusCode: details.statusCode,
      responseHeaders: details.responseHeaders || [],
      tabId: details.tabId
    });

    console.log('Captured response headers', details.url, 'status', details.statusCode);
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

chrome.runtime.onInstalled.addListener(async () => {
  chrome.storage.local.set({ [DISCOVERED_API_KEY]: [] });
  loadCaptureMode();

  if (chrome.sidePanel?.setPanelBehavior) {
    try {
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
      console.log('Side panel configured to open on action click');
    } catch (err) {
      console.warn('Failed to set side panel behavior:', err);
    }
  }
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'boltcloneScan') {
    analyzeNow();
  }
});

chrome.webRequest.onCompleted.addListener(
  async (details) => {
    if (!details.url || details.method === 'OPTIONS') return;

    if (!shouldCaptureTraffic(details.url)) return;

    const candidate = extractCandidate(details.url);
    if (!candidate) return;

    chrome.storage.local.get({ [DISCOVERED_API_KEY]: [] }, ({ discoveredApis }) => {
      const normalized = candidate.replace(/\/?$/, '');
      const existing = new Set(discoveredApis.map((item) => item.url));
      if (!existing.has(normalized)) {
        const next = [{ url: normalized, method: details.method, status: details.statusCode, timestamp: new Date().toISOString() }, ...discoveredApis].slice(0, MAX_DISCOVERED);
        chrome.storage.local.set({ [DISCOVERED_API_KEY]: next });
      }
    });
  },
  { urls: ['<all_urls>'] }
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return;

  if (message.type === 'getDiscoveredApis') {
    chrome.storage.local.get({ [DISCOVERED_API_KEY]: [] }, (data) => sendResponse({ discoveredApis: data[DISCOVERED_API_KEY] || [] }));
    return true;
  }

  if (message.type === 'startScan') {
    scheduleScan();
    captureEnabled = true;
    chrome.storage.local.set({ boltcloneScanState: 'running' });
    analyzeNow();
    sendResponse({ status: 'scheduled' });
    return;
  }

  if (message.type === 'stopScan') {
    stopScheduledScan();
    captureEnabled = false;
    chrome.storage.local.set({ boltcloneScanState: 'stopped' });
    sendResponse({ status: 'cancelled' });
    return;
  }

  if (message.type === 'getScanState') {
    chrome.storage.local.get({ boltcloneScanState: 'stopped' }, ({ boltcloneScanState }) => {
      sendResponse({ scanState: boltcloneScanState });
    });
    return true;
  }

  if (message.type === 'setCaptureMode') {
    const mode = message.mode === 'all' ? 'all' : 'api';
    captureMode = mode;
    chrome.storage.local.set({ boltcloneCaptureMode: mode }, () => {
      console.log('Capture mode updated to', mode);
      sendResponse({ mode });
    });
    return true;
  }

  if (message.type === 'setTargetOrigin') {
    targetOrigin = message.origin || null;
    chrome.storage.local.set({ boltcloneTargetOrigin: targetOrigin }, () => {
      console.log('Target origin updated to', targetOrigin);
      sendResponse({ origin: targetOrigin });
    });
    return true;
  }

  if (message.type === 'getCaptureMode') {
    chrome.storage.local.get({ boltcloneCaptureMode: 'api' }, ({ boltcloneCaptureMode }) => {
      sendResponse({ mode: boltcloneCaptureMode || 'api' });
    });
    return true;
  }

  if (message.type === 'getCaptureRules') {
    chrome.storage.local.get({ [CAPTURE_RULES_KEY]: [] }, (data) => {
      sendResponse({ rules: data[CAPTURE_RULES_KEY] || [] });
    });
    return true;
  }

  if (message.type === 'addCaptureRule') {
    const ruleValue = typeof message.value === 'string' ? message.value.trim() : '';
    if (!ruleValue) {
      sendResponse({ error: 'Rule value is required.' });
      return true;
    }
    const newRule = { id: crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`, value: ruleValue, enabled: true };
    chrome.storage.local.get({ [CAPTURE_RULES_KEY]: [] }, ({ boltcloneCaptureRules }) => {
      const next = [newRule, ...(Array.isArray(boltcloneCaptureRules) ? boltcloneCaptureRules : [])].slice(0, 100);
      chrome.storage.local.set({ [CAPTURE_RULES_KEY]: next }, () => {
        captureRules = next;
        sendResponse({ rule: newRule, rules: next });
      });
    });
    return true;
  }

  if (message.type === 'removeCaptureRule') {
    const ruleId = message.id;
    chrome.storage.local.get({ [CAPTURE_RULES_KEY]: [] }, ({ boltcloneCaptureRules }) => {
      const next = (boltcloneCaptureRules || []).filter((rule) => rule.id !== ruleId);
      chrome.storage.local.set({ [CAPTURE_RULES_KEY]: next }, () => {
        captureRules = next;
        sendResponse({ rules: next });
      });
    });
    return true;
  }

  if (message.type === 'toggleCaptureRule') {
    const ruleId = message.id;
    chrome.storage.local.get({ [CAPTURE_RULES_KEY]: [] }, ({ boltcloneCaptureRules }) => {
      const next = (boltcloneCaptureRules || []).map((rule) => rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule);
      chrome.storage.local.set({ [CAPTURE_RULES_KEY]: next }, () => {
        captureRules = next;
        sendResponse({ rules: next });
      });
    });
    return true;
  }

  if (message.type === 'getTraffic') {
    chrome.storage.local.get({ [STATS_KEY]: [] }, (data) => sendResponse({ traffic: data[STATS_KEY] || [] }));
    return true;
  }

  if (message.type === 'getAnalysis') {
    chrome.storage.local.get({ boltcloneAnalysis: [] }, (data) => sendResponse({ analysis: data.boltcloneAnalysis || [] }));
    return true;
  }

  if (message.type === 'exportSpec') {
    try {
      chrome.storage.local.get({ [STATS_KEY]: [] }, ({ boltcloneTraffic }) => {
        const spec = typeof buildOpenApi === 'function' ? buildOpenApi(boltcloneTraffic || []) : { openapi: '3.0.0', info: { title: 'BOLTCLONE API Inventory', version: '1.0.0' }, paths: {} };
        sendResponse({ spec });
      });
    } catch (err) {
      sendResponse({ error: err?.message || String(err) });
    }
    return true;
  }

  if (message.type === 'getHostAnalysis') {
    chrome.storage.local.get({ [STATS_KEY]: [] }, ({ boltcloneTraffic }) => {
      const hosts = typeof analyzeHosts === 'function' ? analyzeHosts(boltcloneTraffic || []) : [];
      sendResponse({ hosts });
    });
    return true;
  }
});

// Initialize capture mode on startup
loadCaptureMode();
