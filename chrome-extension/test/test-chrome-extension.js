#!/usr/bin/env node
/**
 * test-chrome-extension.js
 * ────────────────────────
 * Comprehensive unit & integration tests for all Chrome extension logic modules:
 *   1. rules.js       – analyzeTraffic() and analyzeHosts()
 *   2. openapi.js     – buildOpenApi()
 *   3. postman.js     – buildPostmanCollection()
 *   4. htmlReport.js  – generateHtmlReport()
 *
 * These modules register on globalThis, so we can load them in Node with vm.
 */

import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const EXT_DIR = path.resolve(__dirname, '..');

// ── Colours ──────────────────────────────────────────────
const green  = (s) => `\x1b[32m${s}\x1b[0m`;
const red    = (s) => `\x1b[31m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
const dim    = (s) => `\x1b[2m${s}\x1b[0m`;
const bold   = (s) => `\x1b[1m${s}\x1b[0m`;

// ── Load scripts into a shared sandbox ───────────────────
async function loadModule(filename) {
  const code = await readFile(path.join(EXT_DIR, filename), 'utf8');
  return code;
}

const sandbox = { globalThis: {}, self: {}, console, URL, TextDecoder, TextEncoder, ArrayBuffer, Uint8Array };
sandbox.globalThis = sandbox;
sandbox.self = sandbox;

const scripts = ['rules.js', 'openapi.js', 'postman.js', 'htmlReport.js'];
for (const s of scripts) {
  const code = await loadModule(s);
  vm.runInNewContext(code, sandbox, { filename: s });
}

const { analyzeTraffic, analyzeHosts, buildOpenApi, buildPostmanCollection, generateHtmlReport } = sandbox;

// ── Test Runner ──────────────────────────────────────────
let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, testName, detail = '') {
  if (condition) {
    console.log(`  ${green('✓')} ${testName}`);
    passed++;
  } else {
    console.log(`  ${red('✗')} ${testName}${detail ? ` — ${dim(detail)}` : ''}`);
    failed++;
    failures.push(testName);
  }
}

// ── Mock Traffic Data ────────────────────────────────────
// Simulates what chrome.webRequest listeners capture and merge by requestId
const mockTraffic = [
  // Request with numeric ID in path → BOLA
  {
    id: '1', type: 'request', url: 'https://api.example.com/api/users/123', method: 'GET',
    requestHeaders: [{ name: 'Authorization', value: 'Bearer eyJhbGciOi...' }],
    responseHeaders: [
      { name: 'set-cookie', value: 'session_id=abc; Path=/' },
      { name: 'server', value: 'nginx/1.25.3' },
      { name: 'x-powered-by', value: 'Express 4.18' }
    ],
    statusCode: 200
  },
  // POST with mass-assignment fields
  {
    id: '2', type: 'request', url: 'https://api.example.com/api/users', method: 'POST',
    requestBody: { formData: { name: ['Alice'], isAdmin: ['true'], role: ['superadmin'] } },
    requestHeaders: [{ name: 'Content-Type', value: 'application/json' }],
    statusCode: 201
  },
  // Token in query string
  {
    id: '3', type: 'request', url: 'https://api.example.com/api/data?api_key=sk-secret-1234&token=abc', method: 'GET',
    requestHeaders: [],
    statusCode: 200
  },
  // Missing cookie flags
  {
    id: '4', type: 'response', url: 'https://api.example.com/api/login', method: 'POST',
    responseHeaders: [
      { name: 'set-cookie', value: 'auth=xyz123; Path=/' }  // missing Secure, HttpOnly, SameSite
    ],
    statusCode: 200
  },
  // Cleartext HTTP with auth
  {
    id: '5', type: 'request', url: 'http://api.example.com/api/data', method: 'GET',
    requestHeaders: [{ name: 'Authorization', value: 'Bearer token123' }],
    statusCode: 200
  },
  // Missing role header (RBAC)
  {
    id: '6', type: 'request', url: 'https://api.example.com/api/admin', method: 'GET',
    requestHeaders: [{ name: 'Authorization', value: 'Bearer eyJ...' }],
    statusCode: 200
  },
  // Server version disclosure via Server header
  {
    id: '7', type: 'response', url: 'https://api.example.com/api/health', method: 'GET',
    responseHeaders: [
      { name: 'server', value: 'Apache/2.4.52' },
      { name: 'x-powered-by', value: 'PHP/8.1' }
    ],
    statusCode: 200
  },
  // Clean request (should trigger fewer findings)
  {
    id: '8', type: 'request', url: 'https://clean.example.com/status', method: 'GET',
    requestHeaders: [],
    responseHeaders: [
      { name: 'strict-transport-security', value: 'max-age=31536000' }
    ],
    statusCode: 200
  }
];

// Traffic for OpenAPI / Postman — richer request/response metadata
const specTraffic = [
  {
    id: '10', url: 'https://api.shop.io/api/products/42', method: 'GET',
    requestHeaders: [{ name: 'Authorization', value: 'Bearer eyJhbGciOi...' }],
    responseHeaders: [{ name: 'Content-Type', value: 'application/json' }],
    statusCode: 200
  },
  {
    id: '11', url: 'https://api.shop.io/api/products', method: 'POST',
    requestHeaders: [{ name: 'Content-Type', value: 'application/json' }, { name: 'X-API-Key', value: 'sk-test' }],
    statusCode: 201
  },
  {
    id: '12', url: 'https://api.shop.io/api/orders?status=pending&page=1', method: 'GET',
    requestHeaders: [{ name: 'Authorization', value: 'Basic dXNlcjpwYXNz' }],
    statusCode: 200
  },
  {
    id: '13', url: 'https://api.shop.io/api/users/550e8400-e29b-41d4-a716-446655440000/profile', method: 'GET',
    requestHeaders: [],
    statusCode: 200
  }
];

// ═══════════════════════════════════════════════════════
console.log(bold('\n🛡️  BOLTCLONE — Chrome Extension Test Suite'));
console.log(dim('   Testing pure-logic modules in Node.js sandbox\n'));

// ═══════════════════════════════════════════════════════
// 1. RULES.JS — analyzeTraffic()
// ═══════════════════════════════════════════════════════
console.log(bold(yellow('\n📦 1. rules.js → analyzeTraffic()')));
console.log(dim('────────────────────────────────────────'));

assert(typeof analyzeTraffic === 'function', 'analyzeTraffic is exported');

const findings = analyzeTraffic(mockTraffic);
assert(Array.isArray(findings), 'Returns an array');
assert(findings.length > 0, `Produces findings (got ${findings.length})`);

// Check specific rules fire
const types = findings.map((f) => f.type);
assert(types.includes('A') || types.includes('BOLA'), 'Detects BOLA / object enumeration');
assert(types.includes('MassAssignment'), 'Detects mass assignment');
assert(types.includes('TokenInUrl'), 'Detects tokens in URL query params');
assert(types.includes('CookieFlags'), 'Detects missing cookie flags');
assert(types.includes('CleartextAuth'), 'Detects cleartext HTTP auth');
assert(types.includes('RBAC'), 'Detects missing RBAC role headers');
assert(types.includes('ServerVersionDisclosure') || types.includes('TechDisclosure'), 'Detects server/tech version disclosure');

// Verify finding structure
findings.forEach((f, i) => {
  if (i === 0) {
    assert(f.type && f.severity && f.message, 'Finding has type, severity, message');
  }
});

// Severity values are valid
assert(findings.every((f) => ['high', 'medium', 'low', 'info'].includes(f.severity)), 'All severities are valid');

// Empty traffic → empty findings
const emptyFindings = analyzeTraffic([]);
assert(emptyFindings.length === 0, 'Empty traffic → 0 findings');

// ═══════════════════════════════════════════════════════
// 2. RULES.JS — analyzeHosts()
// ═══════════════════════════════════════════════════════
console.log(bold(yellow('\n📦 2. rules.js → analyzeHosts()')));
console.log(dim('────────────────────────────────────────'));

assert(typeof analyzeHosts === 'function', 'analyzeHosts is exported');

const hosts = analyzeHosts(mockTraffic);
assert(Array.isArray(hosts), 'Returns an array');
assert(hosts.length > 0, `Produces host results (got ${hosts.length})`);

// Verify host structure
hosts.forEach((h) => {
  assert(h.origin && h.name && Array.isArray(h.tags), `Host "${h.name}" has origin, name, tags`);
});

// Check expected tags are present across all hosts
const allTags = hosts.flatMap((h) => h.tags.map((t) => t.label));
assert(allTags.some((t) => /Auth|Weak/i.test(t)), 'Detects auth-related tag on at least one host');

// Empty traffic → empty hosts
const emptyHosts = analyzeHosts([]);
assert(emptyHosts.length === 0, 'Empty traffic → 0 hosts');

// ═══════════════════════════════════════════════════════
// 3. OPENAPI.JS — buildOpenApi()
// ═══════════════════════════════════════════════════════
console.log(bold(yellow('\n📦 3. openapi.js → buildOpenApi()')));
console.log(dim('────────────────────────────────────────'));

assert(typeof buildOpenApi === 'function', 'buildOpenApi is exported');

const spec = buildOpenApi(specTraffic);
assert(spec.openapi === '3.0.0', 'OpenAPI version is 3.0.0');
assert(spec.info?.title === 'BOLTCLONE API Inventory', 'Spec has correct title');
assert(typeof spec.paths === 'object', 'Spec has paths object');

const pathKeys = Object.keys(spec.paths);
assert(pathKeys.length >= 3, `Contains ≥3 paths (got ${pathKeys.length})`);

// Path parameterization: /api/products/42 → /api/products/{productId}
const productPath = pathKeys.find((p) => p.includes('{') && p.includes('product'));
assert(!!productPath, 'Numeric IDs are parameterized (e.g. {productId})');

// UUID parameterization: /api/users/<uuid>/profile → /api/users/{userUuid}/profile
const uuidPath = pathKeys.find((p) => p.includes('Uuid'));
assert(!!uuidPath, 'UUIDs are parameterized (e.g. {userUuid})');

// Query parameters
const ordersPath = pathKeys.find((p) => p.includes('orders'));
if (ordersPath) {
  const getOp = spec.paths[ordersPath]?.get;
  assert(getOp?.parameters?.some((p) => p.name === 'status' && p.in === 'query'), 'Query params extracted (status)');
  assert(getOp?.parameters?.some((p) => p.name === 'page' && p.in === 'query'), 'Query params extracted (page)');
}

// Security scheme detection
assert(spec.components?.securitySchemes?.bearerAuth, 'Detects Bearer auth scheme');
assert(spec.components?.securitySchemes?.basicAuth, 'Detects Basic auth scheme');
assert(spec.components?.securitySchemes?.apiKeyAuth, 'Detects API Key auth scheme');

// Empty traffic → valid but empty spec
const emptySpec = buildOpenApi([]);
assert(emptySpec.openapi === '3.0.0' && Object.keys(emptySpec.paths).length === 0, 'Empty traffic → valid empty spec');

// ═══════════════════════════════════════════════════════
// 4. POSTMAN.JS — buildPostmanCollection()
// ═══════════════════════════════════════════════════════
console.log(bold(yellow('\n📦 4. postman.js → buildPostmanCollection()')));
console.log(dim('────────────────────────────────────────'));

assert(typeof buildPostmanCollection === 'function', 'buildPostmanCollection is exported');

const postman = buildPostmanCollection(specTraffic);
assert(postman.info?.name === 'BOLTCLONE Captured Collection', 'Collection name is correct');
assert(postman.info?.schema?.includes('postman.com'), 'Schema URL references Postman');
assert(Array.isArray(postman.item), 'Collection has item array');
assert(postman.item.length >= 3, `Contains ≥3 items (got ${postman.item.length})`);

// Verify item structure
postman.item.forEach((item) => {
  assert(item.name && item.request, `Item "${item.name}" has name and request`);
  assert(item.request.method && item.request.url, `Item "${item.name}" has method and url`);
});

// Check URL decomposition
const firstItem = postman.item[0];
assert(Array.isArray(firstItem.request.url.host), 'URL host is decomposed into parts');
assert(Array.isArray(firstItem.request.url.path), 'URL path is decomposed into segments');
assert(firstItem.request.url.protocol === 'https', 'Protocol extracted correctly');

// Headers carried through
const authItem = postman.item.find((i) => i.request.header?.some((h) => h.key === 'Authorization'));
assert(!!authItem, 'Request headers are preserved in Postman items');

// Deduplication
const dupeTraffic = [
  { id: '20', url: 'https://api.test.io/a', method: 'GET' },
  { id: '21', url: 'https://api.test.io/a', method: 'GET' }
];
const dedupedPostman = buildPostmanCollection(dupeTraffic);
assert(dedupedPostman.item.length === 1, 'Duplicate entries are deduplicated');

// Empty traffic → valid but empty collection
const emptyPostman = buildPostmanCollection([]);
assert(emptyPostman.item.length === 0, 'Empty traffic → empty collection');

// ═══════════════════════════════════════════════════════
// 5. HTML REPORT — generateHtmlReport()
// ═══════════════════════════════════════════════════════
console.log(bold(yellow('\n📦 5. htmlReport.js → generateHtmlReport()')));
console.log(dim('────────────────────────────────────────'));

assert(typeof generateHtmlReport === 'function', 'generateHtmlReport is exported');

const reportFindings = [
  { severity: 'high', title: 'SQL Injection', category: 'injection', url: 'https://api.test.io/q', evidence: 'SQL error in response' },
  { severity: 'medium', title: 'Missing HSTS', category: 'access', url: 'https://api.test.io', evidence: 'No Strict-Transport-Security header' },
  { severity: 'low', title: 'Server version disclosed', category: 'info', url: 'https://api.test.io', evidence: 'nginx/1.25' },
  { severity: 'info', title: 'Swagger exposed', category: 'exposure', url: 'https://api.test.io/swagger', evidence: 'Swagger UI found' }
];

const html = generateHtmlReport({
  target: 'https://api.test.io',
  findings: reportFindings,
  meta: { endpointCount: 15, durationMs: 4200 },
  discovered: [],
  traffic: []
});

assert(typeof html === 'string', 'Returns HTML string');
assert(html.includes('<!DOCTYPE html'), 'Contains DOCTYPE');
assert(html.includes('BOLTCLONE'), 'Contains brand name');
assert(html.includes('api.test.io'), 'Contains target URL');
assert(html.includes('SQL Injection'), 'Contains finding title');
assert(html.includes('4.2s') || html.includes('4200'), 'Contains scan duration');
assert(html.includes('15'), 'Contains endpoint count');

// Severity cards
assert(html.includes('>1<') || html.includes('>1</'), 'High count card present');

// Filter buttons
assert(html.includes("filterSev('high')"), 'Has severity filter buttons');
assert(html.includes("filterSev('all')"), 'Has "All" filter button');

// XSS protection — escapeHtml
const xssFindings = [{ severity: 'high', title: '<script>alert(1)</script>', category: 'xss', url: 'https://evil.com', evidence: '<img onerror=alert(1)>' }];
const xssHtml = generateHtmlReport({ target: '<b>evil</b>', findings: xssFindings });
assert(!xssHtml.includes('<script>alert(1)</script>'), 'XSS in title is escaped');
assert(!xssHtml.includes('<b>evil</b>'), 'XSS in target is escaped');
assert(xssHtml.includes('&lt;script&gt;'), 'HTML entities used for escaping');

// Empty findings
const emptyHtml = generateHtmlReport({ target: 'https://clean.io', findings: [] });
assert(emptyHtml.includes('No security vulnerabilities'), 'Empty findings shows placeholder message');

// Print styles
assert(html.includes('@media print'), 'Contains print stylesheet');

// ═══════════════════════════════════════════════════════
// 6. INTEGRATION — Full analysis → Report pipeline
// ═══════════════════════════════════════════════════════
console.log(bold(yellow('\n📦 6. Integration: Traffic → Analysis → Report')));
console.log(dim('────────────────────────────────────────'));

// Simulate what background.js does: analyzeTraffic → generateHtmlReport
const analysisFindings = analyzeTraffic(mockTraffic);
const safeFindings = analysisFindings.map((f) => ({
  type: f.type,
  severity: f.severity,
  message: f.message,
  title: f.message,
  url: f.entry?.url,
  category: f.type
}));

const fullReport = generateHtmlReport({
  target: 'https://api.example.com',
  findings: safeFindings,
  meta: { endpointCount: mockTraffic.length, durationMs: 1500 },
  traffic: mockTraffic,
  discovered: []
});

assert(typeof fullReport === 'string' && fullReport.length > 500, 'Full pipeline produces substantial HTML');
assert(fullReport.includes('api.example.com'), 'Report references the target');
assert(fullReport.includes('finding-row'), 'Report contains finding rows');

// OpenAPI from traffic
const fullSpec = buildOpenApi(mockTraffic);
assert(Object.keys(fullSpec.paths).length > 0, 'OpenAPI spec generated from mock traffic');

// Postman from traffic
const fullPostman = buildPostmanCollection(mockTraffic);
assert(fullPostman.item.length > 0, 'Postman collection generated from mock traffic');

// Host analysis feeds into report
const hostAnalysis = analyzeHosts(mockTraffic);
assert(hostAnalysis.length > 0, 'Host analysis produces results from mock traffic');

// ═══════════════════════════════════════════════════════
// 7. MANIFEST VALIDATION
// ═══════════════════════════════════════════════════════
console.log(bold(yellow('\n📦 7. manifest.json validation')));
console.log(dim('────────────────────────────────────────'));

const manifestRaw = await readFile(path.join(EXT_DIR, 'manifest.json'), 'utf8');
let manifest;
try {
  manifest = JSON.parse(manifestRaw);
  assert(true, 'manifest.json is valid JSON');
} catch (e) {
  assert(false, 'manifest.json is valid JSON', e.message);
}

if (manifest) {
  assert(manifest.manifest_version === 3, 'Manifest V3');
  assert(manifest.name === 'BOLTCLONE', 'Extension name is BOLTCLONE');
  assert(manifest.permissions?.includes('webRequest'), 'Has webRequest permission');
  assert(manifest.permissions?.includes('storage'), 'Has storage permission');
  assert(manifest.permissions?.includes('tabs'), 'Has tabs permission');
  assert(manifest.background?.service_worker === 'background.js', 'Service worker is background.js');
  assert(manifest.action?.default_popup === 'panel.html', 'Default popup is panel.html');
  assert(manifest.host_permissions?.includes('<all_urls>'), 'Has <all_urls> host permission');

  // Verify all referenced files exist
  const referencedFiles = [
    manifest.background?.service_worker,
    manifest.action?.default_popup,
    manifest.devtools_page,
    manifest.side_panel?.default_path,
    ...(manifest.content_scripts?.[0]?.js || [])
  ].filter(Boolean);

  for (const file of referencedFiles) {
    try {
      await readFile(path.join(EXT_DIR, file));
      assert(true, `Referenced file "${file}" exists`);
    } catch {
      assert(false, `Referenced file "${file}" exists`);
    }
  }
}

// ═══════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════
console.log(bold('\n════════════════════════════════════════'));
console.log(bold('  📊 Chrome Extension Test Results'));
console.log(bold('════════════════════════════════════════'));
console.log(`  ${green(`Passed: ${passed}`)}`);
console.log(`  ${failed > 0 ? red(`Failed: ${failed}`) : dim(`Failed: ${failed}`)}`);
if (failures.length) {
  console.log(red('\n  Failed tests:'));
  failures.forEach((f) => console.log(red(`    • ${f}`)));
}
console.log(bold('════════════════════════════════════════\n'));

process.exitCode = failed > 0 ? 1 : 0;
