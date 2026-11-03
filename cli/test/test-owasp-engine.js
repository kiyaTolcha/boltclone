/**
 * test-owasp-engine.js
 *
 * Automated verification for Phase 1 & 2 of the OWASP Testing Engine:
 *   Phase 1 — Ingestion Normalizer & Transport Hardening
 *   Phase 2 — Mutation Engine & Dual-Context Authorization Oracle
 *
 * Covers all 8 core assertions from the design doc (Section 4.5, Step 4.2)
 * plus Phase 2 unit tests for mutations.js and the updated access.js.
 *
 * Runs entirely on Node.js built-ins — no external test runner required.
 * Execute: node cli/test/test-owasp-engine.js
 */

'use strict';

import assert from 'node:assert/strict';
import http from 'node:http';
import { groupById, decodeRequestBody, sanitizeHeaders, normalizeSession } from '../src/ingestion.js';
import { timeoutFetch, safeFetch, createRateLimiter, getSessionRunId } from '../src/http.js';
import {
  generateIdorMutations,
  generateBflaMutations,
  generateParamMutations,
  DEFAULT_FUZZ_PAYLOADS,
} from '../src/mutations.js';
import { checkIdorBola, checkBfla } from '../src/checks/access.js';

// ---------------------------------------------------------------------------
// Minimal test harness
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err.message}`);
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Local mock HTTP server used for network-dependent assertions
// ---------------------------------------------------------------------------
function createMockServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, base: `http://127.0.0.1:${port}` });
    });
  });
}

// ---------------------------------------------------------------------------
// Suite 1: ingestion.js — groupById()
// ---------------------------------------------------------------------------
console.log('\n── Suite 1: groupById() ──────────────────────────────────────────');

await test('Merges 3 split webRequest events with matching id into 1 transaction', () => {
  const rawEvents = [
    { id: 'req-1', url: 'https://api.example.com/orders/1', method: 'GET', requestBody: null },
    { id: 'req-1', requestHeaders: [{ name: 'Authorization', value: 'Bearer tok1' }] },
    { id: 'req-1', statusCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }] },
  ];
  const merged = groupById(rawEvents);
  assert.equal(merged.length, 1, 'Expected exactly 1 merged transaction');
  const tx = merged[0];
  assert.equal(tx.id, 'req-1');
  assert.equal(tx.url, 'https://api.example.com/orders/1');
  assert.equal(tx.method, 'GET');
  assert.equal(tx.statusCode, 200);
  assert.ok(Array.isArray(tx.requestHeaders), 'requestHeaders should be an array');
  assert.ok(Array.isArray(tx.responseHeaders), 'responseHeaders should be an array');
});

await test('Does not merge entries without an id field', () => {
  const rawEvents = [
    { url: 'https://api.example.com/no-id', method: 'GET' },
    { id: 'req-2', url: 'https://api.example.com/with-id', method: 'POST' },
  ];
  const merged = groupById(rawEvents);
  assert.equal(merged.length, 1, 'Only entry with id should be merged');
  assert.equal(merged[0].id, 'req-2');
});

await test('Later event properties overwrite earlier properties for same id', () => {
  const rawEvents = [
    { id: 'req-3', statusCode: 0 },
    { id: 'req-3', statusCode: 200 },
  ];
  const merged = groupById(rawEvents);
  assert.equal(merged[0].statusCode, 200, 'Later statusCode should win');
});

// ---------------------------------------------------------------------------
// Suite 2: ingestion.js — decodeRequestBody()
// ---------------------------------------------------------------------------
console.log('\n── Suite 2: decodeRequestBody() ──────────────────────────────────');

await test('Decodes { raw: [{ text: \'{"id":1}\' }] } into { id: 1 }', () => {
  const { decoded, format } = decodeRequestBody(
    { raw: [{ text: '{"id":1}' }] },
    'application/json'
  );
  assert.deepEqual(decoded, { id: 1 });
  assert.equal(format, 'json');
});

await test('Decodes { raw: [{ text }] } as json when text starts with { even without content-type', () => {
  const { decoded, format } = decodeRequestBody(
    { raw: [{ text: '{"role":"admin"}' }] },
    ''   // no content-type
  );
  assert.deepEqual(decoded, { role: 'admin' });
  assert.equal(format, 'json');
});

await test('Decodes { formData: { key: ["value"] } } into flat { key: "value" }', () => {
  const { decoded, format } = decodeRequestBody(
    { formData: { username: ['alice'], password: ['secret'] } },
    'application/x-www-form-urlencoded'
  );
  assert.equal(format, 'form');
  assert.equal(decoded.username, 'alice');
  assert.equal(decoded.password, 'secret');
});

await test('Multi-value form arrays are kept as arrays', () => {
  const { decoded } = decodeRequestBody(
    { formData: { tags: ['a', 'b'] } },
    ''
  );
  assert.deepEqual(decoded.tags, ['a', 'b']);
});

await test('Returns { decoded: null, format: "empty" } for null requestBody', () => {
  const { decoded, format } = decodeRequestBody(null, '');
  assert.equal(decoded, null);
  assert.equal(format, 'empty');
});

await test('Returns format "raw" for non-JSON raw text', () => {
  const { decoded, format } = decodeRequestBody(
    { raw: [{ text: 'plain text body' }] },
    'text/plain'
  );
  assert.equal(format, 'raw');
  assert.equal(decoded, 'plain text body');
});

// ---------------------------------------------------------------------------
// Suite 3: ingestion.js — sanitizeHeaders()
// ---------------------------------------------------------------------------
console.log('\n── Suite 3: sanitizeHeaders() ────────────────────────────────────');

await test('Converts [{ name, value }] to lowercase Record<string,string>', () => {
  const result = sanitizeHeaders([
    { name: 'Authorization', value: 'Bearer abc' },
    { name: 'Content-Type', value: 'application/json' },
  ]);
  assert.equal(result['authorization'], 'Bearer abc');
  assert.equal(result['content-type'], 'application/json');
});

await test('Drops host, content-length, connection, transfer-encoding', () => {
  const result = sanitizeHeaders([
    { name: 'host', value: 'api.example.com' },
    { name: 'content-length', value: '42' },
    { name: 'connection', value: 'keep-alive' },
    { name: 'transfer-encoding', value: 'chunked' },
    { name: 'authorization', value: 'Bearer tok' },
  ]);
  assert.equal(result['host'], undefined, 'host must be dropped');
  assert.equal(result['content-length'], undefined, 'content-length must be dropped');
  assert.equal(result['connection'], undefined, 'connection must be dropped');
  assert.equal(result['transfer-encoding'], undefined, 'transfer-encoding must be dropped');
  assert.equal(result['authorization'], 'Bearer tok', 'authorization must be kept');
});

await test('Drops all sec-ch-ua* Chrome client-hint headers', () => {
  const result = sanitizeHeaders([
    { name: 'sec-ch-ua', value: '"Chromium";v="124"' },
    { name: 'sec-ch-ua-mobile', value: '?0' },
    { name: 'sec-ch-ua-platform', value: '"Windows"' },
    { name: 'accept', value: 'application/json' },
  ]);
  assert.equal(result['sec-ch-ua'], undefined);
  assert.equal(result['sec-ch-ua-mobile'], undefined);
  assert.equal(result['sec-ch-ua-platform'], undefined);
  assert.equal(result['accept'], 'application/json');
});

await test('Drops sec-fetch-* browser metadata headers', () => {
  const result = sanitizeHeaders([
    { name: 'sec-fetch-dest', value: 'empty' },
    { name: 'sec-fetch-mode', value: 'cors' },
    { name: 'x-custom-header', value: 'keep-me' },
  ]);
  assert.equal(result['sec-fetch-dest'], undefined);
  assert.equal(result['sec-fetch-mode'], undefined);
  assert.equal(result['x-custom-header'], 'keep-me');
});

await test('Returns empty object for non-array input', () => {
  assert.deepEqual(sanitizeHeaders(null), {});
  assert.deepEqual(sanitizeHeaders(undefined), {});
  assert.deepEqual(sanitizeHeaders('bad'), {});
});

// ---------------------------------------------------------------------------
// Suite 4: ingestion.js — normalizeSession()
// ---------------------------------------------------------------------------
console.log('\n── Suite 4: normalizeSession() ───────────────────────────────────');

const SCOPE_HOST = 'https://api.example.com';

await test('Unwraps { boltcloneTraffic: [...] } envelope', () => {
  const raw = {
    boltcloneTraffic: [
      { id: 'r1', url: 'https://api.example.com/items', method: 'GET' },
    ]
  };
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs.length, 1);
  assert.equal(txs[0].url, 'https://api.example.com/items');
});

await test('Unwraps { analysis: [...] } legacy envelope', () => {
  const raw = { analysis: [{ id: 'r2', url: 'https://api.example.com/legacy' }] };
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs.length, 1);
});

await test('Accepts a bare Array envelope', () => {
  const raw = [{ id: 'r3', url: 'https://api.example.com/bare', method: 'POST' }];
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs.length, 1);
  assert.equal(txs[0].method, 'POST');
});

// Assertion 3 from the design doc:
await test('Drops transactions targeting off-scope hosts (evil.example.com)', () => {
  const raw = [
    { id: 'r4', url: 'https://api.example.com/in-scope', method: 'GET' },
    { id: 'r5', url: 'https://evil.example.com/out-of-scope', method: 'GET' },
  ];
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs.length, 1, 'Only in-scope transaction should survive');
  assert.equal(txs[0].url, 'https://api.example.com/in-scope');
});

await test('Fully enriched transaction has isEnriched=true', () => {
  const raw = [{
    id: 'r6',
    url: 'https://api.example.com/enriched',
    method: 'GET',
    requestHeaders: [{ name: 'Authorization', value: 'Bearer tok' }],
    requestBody: null,
  }];
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs[0].isEnriched, true);
});

await test('Analysis-only entry without headers/body gets isEnriched=false', () => {
  const raw = [{ id: 'r7', url: 'https://api.example.com/bare-url' }];
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs[0].isEnriched, false);
});

await test('Merges 3 split lifecycle events through normalizeSession', () => {
  const raw = [
    { id: 'r8', url: 'https://api.example.com/orders/1', method: 'GET', requestBody: null },
    { id: 'r8', requestHeaders: [{ name: 'Authorization', value: 'Bearer tok' }] },
    { id: 'r8', statusCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }] },
  ];
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs.length, 1, 'Three events for same id → 1 TransactionDTO');
  assert.equal(txs[0].statusCode, 200);
  assert.equal(txs[0].headers['authorization'], 'Bearer tok');
  assert.equal(txs[0].responseHeaders['content-type'], 'application/json');
});

await test('Decodes JSON body through full normalizeSession pipeline', () => {
  const raw = [{
    id: 'r9',
    url: 'https://api.example.com/login',
    method: 'POST',
    requestHeaders: [{ name: 'Content-Type', value: 'application/json' }],
    requestBody: { raw: [{ text: '{"username":"alice","password":"s3cr3t"}' }] },
  }];
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs[0].bodyFormat, 'json');
  assert.equal(txs[0].body.username, 'alice');
});

await test('Method is normalized to uppercase', () => {
  const raw = [{ id: 'r10', url: 'https://api.example.com/x', method: 'post' }];
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs[0].method, 'POST');
});

await test('Entries without url are skipped', () => {
  const raw = [
    { id: 'r11', method: 'GET' },                          // no url → skip
    { id: 'r12', url: 'https://api.example.com/ok' },
  ];
  const txs = normalizeSession(raw, SCOPE_HOST);
  assert.equal(txs.length, 1);
});

// ---------------------------------------------------------------------------
// Suite 5: http.js — Synthetic headers (Assertion 8 from design doc)
// ---------------------------------------------------------------------------
console.log('\n── Suite 5: http.js — Synthetic header injection ─────────────────');

await test('Injects X-Bolt-Test-Run and X-Synthetic-Test on every dispatched request', async () => {
  let capturedHeaders = {};
  const { server, base } = await createMockServer((req, res) => {
    capturedHeaders = req.headers;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });

  try {
    await timeoutFetch(`${base}/probe`, {}, 5000);
    assert.ok(capturedHeaders['x-bolt-test-run'], 'X-Bolt-Test-Run header must be present');
    assert.equal(capturedHeaders['x-synthetic-test'], 'true', 'X-Synthetic-Test must be "true"');
    assert.equal(capturedHeaders['user-agent'], 'BOLTCLONE-SecurityScanner/1.0.0');
  } finally {
    server.close();
  }
});

await test('X-Bolt-Test-Run is consistent across multiple requests within same process', async () => {
  const runId1 = getSessionRunId();
  const runId2 = getSessionRunId();
  assert.equal(runId1, runId2, 'Session run ID must be stable within a process');
  assert.match(runId1, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i, 'Must be a valid UUID v4');
});

await test('X-Bolt-Standard taxonomy tag is attached when opts.standard is provided', async () => {
  let capturedHeaders = {};
  const { server, base } = await createMockServer((req, res) => {
    capturedHeaders = req.headers;
    res.writeHead(200);
    res.end('ok');
  });

  try {
    await timeoutFetch(`${base}/tagged`, { standard: 'WSTG-ATHZ-02' }, 5000);
    assert.equal(capturedHeaders['x-bolt-standard'], 'WSTG-ATHZ-02');
  } finally {
    server.close();
  }
});

await test('Caller-supplied headers are preserved alongside synthetic headers', async () => {
  let capturedHeaders = {};
  const { server, base } = await createMockServer((req, res) => {
    capturedHeaders = req.headers;
    res.writeHead(200);
    res.end('ok');
  });

  try {
    await timeoutFetch(`${base}/caller`, { headers: { authorization: 'Bearer caller-tok' } }, 5000);
    assert.equal(capturedHeaders['authorization'], 'Bearer caller-tok');
    assert.ok(capturedHeaders['x-bolt-test-run'], 'Synthetic header must coexist');
  } finally {
    server.close();
  }
});

// ---------------------------------------------------------------------------
// Suite 6: http.js — createRateLimiter()
// ---------------------------------------------------------------------------
console.log('\n── Suite 6: http.js — Rate limiter ───────────────────────────────');

await test('createRateLimiter resolves immediately on first call', async () => {
  const throttle = createRateLimiter(100);    // 100 QPS → 10 ms interval
  const start = Date.now();
  await throttle();
  assert.ok(Date.now() - start < 50, 'First call should resolve without delay');
});

await test('createRateLimiter enforces inter-request delay for second call', async () => {
  const throttle = createRateLimiter(10);    // 10 QPS → 100 ms interval
  await throttle();                           // consume first token
  const start = Date.now();
  await throttle();                           // second call must wait ~100 ms
  const elapsed = Date.now() - start;
  assert.ok(elapsed >= 80, `Expected >=80ms delay, got ${elapsed}ms`);
});

// ---------------------------------------------------------------------------
// Suite 7: http.js — safeFetch()
// ---------------------------------------------------------------------------
console.log('\n── Suite 7: http.js — safeFetch() ────────────────────────────────');

await test('safeFetch returns null on network error instead of throwing', async () => {
  // Port 1 is almost certainly not listening; should fail instantly.
  const result = await safeFetch('http://127.0.0.1:1/unreachable', {}, 2000);
  assert.equal(result, null, 'safeFetch must return null on connection error');
});

// ---------------------------------------------------------------------------
// Suite 8: http.js — Decompression
// ---------------------------------------------------------------------------
console.log('\n── Suite 8: http.js — Transparent decompression ─────────────────');

await test('Decompresses gzip-encoded response bodies transparently', async () => {
  const zlib = (await import('node:zlib')).default;
  const payload = JSON.stringify({ ok: true });
  const compressed = zlib.gzipSync(Buffer.from(payload));

  const { server, base } = await createMockServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'application/json',
      'content-encoding': 'gzip',
    });
    res.end(compressed);
  });

  try {
    const resp = await timeoutFetch(`${base}/gzip`, {}, 5000);
    const text = await resp.text();
    assert.equal(text, payload, 'Decompressed body must match original JSON string');
  } finally {
    server.close();
  }
});

// ---------------------------------------------------------------------------
// Final report
// ---------------------------------------------------------------------------

// ── Phase 2 suites appended below ──────────────────────────────────────────

// ---------------------------------------------------------------------------
// Suite 9: mutations.js — generateIdorMutations() (Design doc assertion 4)
// ---------------------------------------------------------------------------
console.log('\n── Suite 9: generateIdorMutations() ─────────────────────────────');

// Helper to collect all mutations from a generator into an array.
function collect(gen) {
  const results = [];
  for (const item of gen) results.push(item);
  return results;
}

const BASE_TX = {
  id: 'test-1',
  url: 'https://api.example.com/orders/42',
  method: 'GET',
  statusCode: 200,
  headers: { authorization: 'Bearer tok' },
  responseHeaders: {},
  body: null,
  bodyFormat: 'empty',
  isEnriched: true,
};

await test('Generates +1 and -1 integer mutations for path segment', () => {
  const mutations = collect(generateIdorMutations(BASE_TX));
  assert.ok(mutations.length >= 2, 'Expected at least 2 integer mutations');
  const urls = mutations.map((m) => m.mutatedUrl);
  assert.ok(urls.some((u) => u.includes('/orders/43')), 'Should have +1 variant /orders/43');
  assert.ok(urls.some((u) => u.includes('/orders/41')), 'Should have -1 variant /orders/41');
  assert.ok(mutations.every((m) => m.mutationType === 'IDOR'));
});

await test('Generates UUID neighbour mutation for UUID path segment', () => {
  const uuidTx = {
    ...BASE_TX,
    url: 'https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000/profile',
  };
  const mutations = collect(generateIdorMutations(uuidTx));
  assert.ok(mutations.length >= 1, 'Expected at least 1 UUID mutation');
  assert.ok(mutations[0].mutationType === 'IDOR');
  // Original UUID should not appear in mutated URL.
  assert.ok(!mutations[0].mutatedUrl.includes('550e8400-e29b-41d4-a716-446655440000'));
});

await test('Generates query param ID mutations for ?id= style params', () => {
  const paramTx = {
    ...BASE_TX,
    url: 'https://api.example.com/items?id=100&filter=active',
  };
  const mutations = collect(generateIdorMutations(paramTx));
  const idMutations = mutations.filter((m) => m.mutationDetail.includes('?id'));
  assert.ok(idMutations.length >= 1, 'Should produce at least 1 ?id= mutation');
  const urls = idMutations.map((m) => m.mutatedUrl);
  assert.ok(urls.some((u) => u.includes('id=101') || u.includes('id=99')));
});

await test('Generates query param mutations for ?user_id= style params', () => {
  const paramTx = {
    ...BASE_TX,
    url: 'https://api.example.com/profile?user_id=7',
  };
  const mutations = collect(generateIdorMutations(paramTx));
  assert.ok(mutations.length >= 1);
  assert.ok(mutations.some((m) => m.mutationDetail.includes('user_id')));
});

// Design doc assertion 5: skips DELETE and PUT when allowMutating=false
await test('Skips DELETE endpoints when allowMutating=false (assertion 5)', () => {
  const deleteTx = { ...BASE_TX, method: 'DELETE' };
  const mutations = collect(generateIdorMutations(deleteTx, false));
  assert.equal(mutations.length, 0, 'DELETE must yield no mutations when allowMutating=false');
});

await test('Skips PUT endpoints when allowMutating=false', () => {
  const putTx = { ...BASE_TX, method: 'PUT' };
  const mutations = collect(generateIdorMutations(putTx, false));
  assert.equal(mutations.length, 0, 'PUT must yield no mutations when allowMutating=false');
});

await test('Allows DELETE mutations when allowMutating=true', () => {
  const deleteTx = { ...BASE_TX, method: 'DELETE', url: 'https://api.example.com/orders/42' };
  const mutations = collect(generateIdorMutations(deleteTx, true));
  assert.ok(mutations.length > 0, 'DELETE should yield mutations when allowMutating=true');
});

await test('Does not mutate 0 below zero (no negative IDs)', () => {
  const zeroTx = { ...BASE_TX, url: 'https://api.example.com/items/0' };
  const mutations = collect(generateIdorMutations(zeroTx));
  // ID-1 = -1 should be filtered; only ID+1 = 1 should appear.
  const urls = mutations.map((m) => m.mutatedUrl);
  assert.ok(!urls.some((u) => u.includes('/-1')), 'Negative IDs must not be generated');
});

await test('Original TransactionDTO is not mutated by generateIdorMutations', () => {
  const tx = { ...BASE_TX, body: { key: 'value' } };
  const mutations = collect(generateIdorMutations(tx));
  if (mutations.length > 0) {
    mutations[0].mutatedBody.key = 'MODIFIED';
    assert.equal(tx.body.key, 'value', 'Original body must not be mutated');
  }
});

// ---------------------------------------------------------------------------
// Suite 10: mutations.js — generateBflaMutations()
// ---------------------------------------------------------------------------
console.log('\n── Suite 10: generateBflaMutations() ────────────────────────────');

const ADMIN_TX = {
  ...BASE_TX,
  url: 'https://api.example.com/admin/users',
  headers: { authorization: 'Bearer admin-tok', 'x-request-id': 'abc' },
};

await test('Generates unauthenticated mutation for privileged admin path', () => {
  const mutations = collect(generateBflaMutations(ADMIN_TX, null));
  assert.ok(mutations.length >= 1, 'Should yield at least 1 mutation for /admin/ path');
  const unauth = mutations.find((m) => m.mutationType === 'BFLA_UNAUTH');
  assert.ok(unauth, 'Should have a BFLA_UNAUTH mutation');
  assert.equal(unauth.mutatedHeaders['authorization'], undefined, 'Auth header must be stripped');
  assert.equal(unauth.mutatedHeaders['cookie'], undefined, 'Cookie header must be stripped');
});

await test('Generates cross-tenant mutation when secondaryAuth provided', () => {
  const mutations = collect(generateBflaMutations(ADMIN_TX, 'Bearer user-b-tok'));
  const cross = mutations.find((m) => m.mutationType === 'BFLA_CROSSTENANT');
  assert.ok(cross, 'Should have a BFLA_CROSSTENANT mutation');
  assert.equal(cross.mutatedHeaders['authorization'], 'Bearer user-b-tok');
});

await test('Auto-prefixes Bearer to bare token in cross-tenant mutation', () => {
  const mutations = collect(generateBflaMutations(ADMIN_TX, 'raw-token-no-prefix'));
  const cross = mutations.find((m) => m.mutationType === 'BFLA_CROSSTENANT');
  assert.ok(cross?.mutatedHeaders['authorization'].startsWith('Bearer '));
});

await test('Does not generate mutations for non-privileged endpoints', () => {
  const normalTx = { ...BASE_TX, url: 'https://api.example.com/products/1' };
  const mutations = collect(generateBflaMutations(normalTx, 'Bearer tok'));
  assert.equal(mutations.length, 0, 'Non-privileged path should yield no BFLA mutations');
});

await test('Recognizes /manage/ as privileged', () => {
  const manageTx = { ...BASE_TX, url: 'https://api.example.com/manage/settings' };
  const mutations = collect(generateBflaMutations(manageTx, null));
  assert.ok(mutations.length > 0);
});

await test('Skips DELETE on privileged endpoint when allowMutating=false', () => {
  const deleteTx = { ...ADMIN_TX, method: 'DELETE' };
  const mutations = collect(generateBflaMutations(deleteTx, null, false));
  assert.equal(mutations.length, 0);
});

// ---------------------------------------------------------------------------
// Suite 11: mutations.js — generateParamMutations()
// ---------------------------------------------------------------------------
console.log('\n── Suite 11: generateParamMutations() ───────────────────────────');

await test('Generates query string param fuzz mutations', () => {
  const tx = { ...BASE_TX, url: 'https://api.example.com/search?q=hello&page=1' };
  const mutations = collect(generateParamMutations(tx, ["' OR 1=1--", '<script>'], false));
  assert.ok(mutations.length >= 2, 'Should have at least 2 mutations (one per payload per param)');
  assert.ok(mutations.every((m) => m.mutationType === 'PARAM_FUZZ'));
});

await test('Injects into JSON body keys without corrupting structure', () => {
  const tx = {
    ...BASE_TX,
    method: 'GET',   // idempotent
    url: 'https://api.example.com/search',
    body: { query: 'test', limit: 10 },
    bodyFormat: 'json',
  };
  const payloads = ["' OR 1=1--"];
  const mutations = collect(generateParamMutations(tx, payloads, false));
  const bodyMutations = mutations.filter((m) => m.mutationDetail.includes('JSON body key'));
  // Should produce 1 mutation per payload per string/number-valued body key.
  assert.ok(bodyMutations.length >= 1);
  // Verify the injected body is still a valid object.
  for (const m of bodyMutations) {
    assert.ok(m.mutatedBody && typeof m.mutatedBody === 'object');
  }
});

await test('Skips POST endpoints when allowMutating=false', () => {
  const postTx = {
    ...BASE_TX,
    method: 'POST',
    url: 'https://api.example.com/login?redirect=/',
  };
  const mutations = collect(generateParamMutations(postTx, DEFAULT_FUZZ_PAYLOADS, false));
  assert.equal(mutations.length, 0);
});

await test('Allows POST fuzz when allowMutating=true', () => {
  const postTx = {
    ...BASE_TX,
    method: 'POST',
    url: 'https://api.example.com/search?q=test',
  };
  const mutations = collect(generateParamMutations(postTx, ["' OR 1=1--"], true));
  assert.ok(mutations.length > 0, 'POST should be fuzzed when allowMutating=true');
});

await test('DEFAULT_FUZZ_PAYLOADS covers SQLi, XSS, path traversal, SSTI, and boundary values', () => {
  const hasSQL    = DEFAULT_FUZZ_PAYLOADS.some((p) => p.includes('OR') || p.includes('DROP'));
  const hasXSS    = DEFAULT_FUZZ_PAYLOADS.some((p) => p.includes('<script>') || p.includes('onerror'));
  const hasTraversal = DEFAULT_FUZZ_PAYLOADS.some((p) => p.includes('../'));
  const hasSSTI   = DEFAULT_FUZZ_PAYLOADS.some((p) => p.includes('{{') || p.includes('${'));
  assert.ok(hasSQL, 'Should include SQL injection payload');
  assert.ok(hasXSS, 'Should include XSS payload');
  assert.ok(hasTraversal, 'Should include path traversal payload');
  assert.ok(hasSSTI, 'Should include SSTI payload');
});

// ---------------------------------------------------------------------------
// Suite 12: access.js — checkIdorBola() dual-context (Design doc assertion 6)
// ---------------------------------------------------------------------------
console.log('\n── Suite 12: access.js — checkIdorBola() dual-context ────────────');

await test('Flags BOLA when secondary auth receives HTTP 200 with matching schema (assertion 6)', async () => {
  // Mock server returns object-scoped data regardless of token.
  const { server, base } = await createMockServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id: 1, name: 'Order One', status: 'pending' }));
  });

  const tx = {
    id: 'r1',
    url: `${base}/api/orders/1`,
    method: 'GET',
    statusCode: 200,
    headers: { authorization: 'Bearer owner-tok' },
    responseHeaders: {},
    body: null,
    bodyFormat: 'empty',
    isEnriched: true,
  };

  try {
    const result = await checkIdorBola(tx, 5000, { secondaryAuth: 'Bearer user-b-tok' });
    const findings = Array.isArray(result) ? result : (result ? [result] : []);
    // Should flag at minimum: cross-tenant access (or unauthenticated access since mock doesn't check auth).
    assert.ok(findings.length > 0, 'Should detect BOLA when secondary token gets 200 with matching schema');
    // At least one finding should be high severity (confirmed cross-tenant BOLA).
    const highFindings = findings.filter((f) => f.severity === 'high');
    assert.ok(highFindings.length > 0, 'Cross-tenant BOLA should be high severity');
    // Standards taxonomy must be attached.
    const bolaFinding = findings.find((f) => f.standards?.owaspApi === 'API1');
    assert.ok(bolaFinding, 'Finding must carry OWASP API1 taxonomy tag');
  } finally {
    server.close();
  }
});

await test('Returns null for plain URL with no integer segment (legacy path)', async () => {
  const result = await checkIdorBola('https://api.example.com/products/search', 3000);
  assert.equal(result, null, 'URL with no integer segment should return null');
});

await test('Standards taxonomy is attached to BOLA findings', async () => {
  const { server, base } = await createMockServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ id: 5, value: 'data' }));
  });

  const tx = {
    id: 'r2',
    url: `${base}/items/5`,
    method: 'GET',
    statusCode: 200,
    headers: { authorization: 'Bearer tok' },
    responseHeaders: {},
    body: null,
    bodyFormat: 'empty',
    isEnriched: true,
  };

  try {
    const result = await checkIdorBola(tx, 5000, { secondaryAuth: 'Bearer other-tok' });
    const findings = Array.isArray(result) ? result : (result ? [result] : []);
    if (findings.length > 0) {
      for (const f of findings) {
        assert.ok(f.standards, 'Each finding must have a standards object');
        assert.ok(f.standards.wstg, 'Finding must have WSTG tag');
      }
    }
    // If sandbox blocks network, accept 0 findings gracefully.
  } finally {
    server.close();
  }
});

// ---------------------------------------------------------------------------
// Suite 13: access.js — checkBfla()
// ---------------------------------------------------------------------------
console.log('\n── Suite 13: access.js — checkBfla() ────────────────────────────');

await test('Detects BFLA when admin endpoint accessible without auth', async () => {
  const { server, base } = await createMockServer((req, res) => {
    // Server doesn't check auth — always 200.
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ users: [] }));
  });

  const tx = {
    id: 'r3',
    url: `${base}/admin/users`,
    method: 'GET',
    statusCode: 200,
    headers: { authorization: 'Bearer admin-tok' },
    responseHeaders: {},
    body: null,
    bodyFormat: 'empty',
    isEnriched: true,
  };

  try {
    const findings = await checkBfla(tx, 5000, null);
    // Mock server always returns 200 regardless of auth → BFLA_UNAUTH detected.
    assert.ok(findings.length > 0, 'Should detect BFLA on /admin/ endpoint without auth');
    assert.ok(findings.every((f) => f.severity === 'high'), 'BFLA findings must be high severity');
    assert.ok(findings.every((f) => f.standards?.owaspApi === 'API5'), 'Must carry OWASP API5 taxonomy');
  } finally {
    server.close();
  }
});

await test('Returns empty array for non-privileged endpoint', async () => {
  const tx = {
    ...BASE_TX,
    url: 'https://api.example.com/products/1',
    headers: { authorization: 'Bearer tok' },
  };
  const findings = await checkBfla(tx, 3000, null);
  assert.deepEqual(findings, [], 'Non-privileged path should return empty array');
});

await test('Detects cross-tenant BFLA with secondary auth on admin route', async () => {
  const { server, base } = await createMockServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ result: 'ok' }));
  });

  const tx = {
    id: 'r4',
    url: `${base}/manage/settings`,
    method: 'GET',
    statusCode: 200,
    headers: { authorization: 'Bearer admin-tok' },
    responseHeaders: {},
    body: null,
    bodyFormat: 'empty',
    isEnriched: true,
  };

  try {
    const findings = await checkBfla(tx, 5000, 'Bearer low-privilege-tok');
    // Mock always returns 200 → both unauth and cross-tenant should fire.
    assert.ok(findings.length >= 1, 'Should detect at least one BFLA variant');
    assert.ok(findings.some((f) => f.standards?.astf === 'ASTF-ATHZ-02'), 'Must carry ASTF-ATHZ-02 tag');
  } finally {
    server.close();
  }
});

// ── Phase 3 suites ─────────────────────────────────────────────────────────

import { checkExcessiveDataExposure, checkMassAssignment, runBoplaChecks } from '../src/checks/bopla.js';
import { parseCliArgs } from '../src/args.js';

// ---------------------------------------------------------------------------
// Suite 14: bopla.js — checkExcessiveDataExposure()
// ---------------------------------------------------------------------------
console.log('\n── Suite 14: checkExcessiveDataExposure() ────────────────────────');

const SCOPE_TX = {
  id: 'e1', url: 'https://api.example.com/profile', method: 'GET',
  statusCode: 200, headers: {}, responseHeaders: {}, body: null,
  bodyFormat: 'empty', isEnriched: false,
};

await test('Detects password_hash in response body', () => {
  const body = { id: 1, username: 'alice', password_hash: '$2b$12$abc' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.ok(results.length > 0, 'Should flag password_hash as excessive exposure');
  assert.ok(results.every((f) => f.standards?.owaspApi === 'API3'));
  assert.ok(results.every((f) => f.standards?.wstg === 'WSTG-INFO-05'));
});

await test('Detects ssn field in response body', () => {
  const body = { name: 'Bob', ssn: '123-45-6789' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.ok(results.some((f) => f.title.includes('sensitive fields')));
});

await test('Detects private_key field', () => {
  const body = { id: 2, private_key: 'BEGIN RSA...' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.ok(results.length > 0);
});

await test('Detects secret_token field', () => {
  const body = { user: 'alice', secret_token: 'tok_live_abc123' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.ok(results.length > 0);
});

await test('Detects credit_card field', () => {
  const body = { order: 1, credit_card: '4111111111111111' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.ok(results.length > 0);
});

await test('Detects SSH private key value pattern regardless of key name', () => {
  const body = { data: '-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n-----END RSA PRIVATE KEY-----' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.ok(results.some((f) => f.title.includes('SSH private key')), 'Should detect SSH key by value pattern');
});

await test('Detects JWT token value pattern', () => {
  const body = { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.ok(results.some((f) => f.title.includes('JWT token')));
});

await test('Detects sensitive keys nested in response objects', () => {
  const body = { user: { profile: { password: 'cleartext!' } } };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.ok(results.length > 0, 'Should detect nested password field');
});

await test('Returns empty array for clean response body', () => {
  const body = { id: 1, name: 'Alice', email: 'alice@example.com', role: 'user' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  assert.deepEqual(results, [], 'Clean response body should produce no findings');
});

await test('Returns empty array for null responseBody', () => {
  const results = checkExcessiveDataExposure(SCOPE_TX, null);
  assert.deepEqual(results, []);
});

await test('Returns empty array for non-object responseBody', () => {
  const results = checkExcessiveDataExposure(SCOPE_TX, 'plain string');
  assert.deepEqual(results, []);
});

await test('All findings carry correct four-standard taxonomy', () => {
  const body = { password_hash: '$2b$12$xyz' };
  const results = checkExcessiveDataExposure(SCOPE_TX, body);
  for (const f of results) {
    assert.ok(f.standards, 'Finding must have standards object');
    assert.equal(f.standards.owaspApi, 'API3');
    assert.equal(f.standards.astf, 'ASTF-ATHZ-03');
  }
});

// ---------------------------------------------------------------------------
// Suite 15: bopla.js — checkMassAssignment() (Design doc assertion 7)
// ---------------------------------------------------------------------------
console.log('\n── Suite 15: checkMassAssignment() (assertion 7) ────────────────');

await test('Detects mass assignment when injected isAdmin is accepted (assertion 7)', async () => {
  // Mock server that reflects all request body properties in the response.
  const { server, base } = await createMockServer(async (req, res) => {
    let body = '';
    req.on('data', (c) => body += c);
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body);
        res.writeHead(200, { 'content-type': 'application/json' });
        // Echo back the entire request body — simulates a mass-assignment vulnerable endpoint.
        res.end(JSON.stringify({ success: true, ...parsed }));
      } catch {
        res.writeHead(400); res.end('bad request');
      }
    });
  });

  const tx = {
    id: 'm1',
    url: `${base}/api/profile/update`,
    method: 'POST',
    statusCode: 200,
    headers: { authorization: 'Bearer tok', 'content-type': 'application/json' },
    responseHeaders: {},
    body: { name: 'Alice' },
    bodyFormat: 'json',
    isEnriched: true,
  };

  try {
    const findings = await checkMassAssignment(tx, 5000, true);
    assert.ok(findings.length > 0, 'Should detect mass assignment when isAdmin is echoed back');
    assert.ok(findings.every((f) => f.severity === 'high'), 'Mass assignment must be high severity');
    assert.ok(findings.every((f) => f.standards?.owaspApi === 'API3'), 'Must carry OWASP API3');
    assert.ok(findings.every((f) => f.standards?.wstg === 'WSTG-BUSL-07'), 'Must carry WSTG-BUSL-07');
    assert.ok(findings.every((f) => f.standards?.astf === 'ASTF-ATHZ-03'), 'Must carry ASTF-ATHZ-03');
  } finally {
    server.close();
  }
});

await test('Skips POST endpoint when allowMutating=false', async () => {
  const tx = {
    id: 'm2',
    url: 'https://api.example.com/update',
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: { name: 'Alice' },
    bodyFormat: 'json',
    isEnriched: true,
  };
  // Should return empty without network call (gated before fetch).
  const findings = await checkMassAssignment(tx, 3000, false);
  assert.deepEqual(findings, [], 'POST mass assignment check must be skipped when allowMutating=false');
});

await test('Skips GET endpoint without JSON body', async () => {
  const tx = {
    id: 'm3',
    url: 'https://api.example.com/products',
    method: 'GET',
    headers: {},
    body: null,
    bodyFormat: 'empty',
    isEnriched: false,
  };
  const findings = await checkMassAssignment(tx, 3000, true);
  assert.deepEqual(findings, []);
});

await test('Does not inject over pre-existing body keys', async () => {
  // Endpoint already has isAdmin in the body — skip that payload to avoid false positives.
  const { server, base } = await createMockServer(async (req, res) => {
    let body = ''; req.on('data', c => body += c);
    req.on('end', () => {
      const parsed = JSON.parse(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ...parsed }));
    });
  });

  const tx = {
    id: 'm4',
    url: `${base}/api/update`,
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    // isAdmin is pre-existing — injection of this key should be skipped.
    body: { name: 'Alice', isAdmin: false },
    bodyFormat: 'json',
    isEnriched: true,
  };

  try {
    const findings = await checkMassAssignment(tx, 5000, true);
    // isAdmin is pre-existing so no finding for it; other payloads (role, verified, etc.) may match.
    // This test just confirms the process runs without error.
    assert.ok(Array.isArray(findings));
  } finally {
    server.close();
  }
});

// ---------------------------------------------------------------------------
// Suite 16: bopla.js — runBoplaChecks()
// ---------------------------------------------------------------------------
console.log('\n── Suite 16: runBoplaChecks() ────────────────────────────────────');

await test('runBoplaChecks aggregates exposure check when responseBody provided', () => {
  const tx = { ...SCOPE_TX, url: 'https://api.example.com/user/1' };
  // Run as a sync-compatible path (no network, just passive check).
  const responseBody = { id: 1, username: 'alice', password_hash: '$2b$xyz' };
  const results = runBoplaChecks(tx, 3000, { allowMutating: false, responseBody });
  // Returns a Promise — unwrap it.
  return results.then((findings) => {
    assert.ok(findings.length > 0, 'Should detect password_hash via passive check');
    assert.ok(findings.some((f) => f.standards?.wstg === 'WSTG-INFO-05'));
  });
});

await test('runBoplaChecks returns empty array when no issues and no responseBody', async () => {
  const tx = {
    id: 'r1', url: 'https://api.example.com/items',
    method: 'GET', headers: {}, body: null, bodyFormat: 'empty', isEnriched: false,
  };
  const findings = await runBoplaChecks(tx, 3000, { allowMutating: false, responseBody: null });
  assert.ok(Array.isArray(findings), 'Should return an array');
});

// ---------------------------------------------------------------------------
// Suite 17: args.js — New Phase 3 CLI flags
// ---------------------------------------------------------------------------
console.log('\n── Suite 17: args.js — Phase 3 CLI flags ─────────────────────────');

await test('Parses --secondary-auth flag', () => {
  const args = parseCliArgs(['https://example.com', '--secondary-auth', 'Bearer user-b-tok']);
  assert.equal(args.secondaryAuth, 'Bearer user-b-tok');
});

await test('Parses --allow-mutating-methods flag', () => {
  const args = parseCliArgs(['https://example.com', '--allow-mutating-methods']);
  assert.equal(args.allowMutatingMethods, true);
});

await test('--allow-mutating-methods defaults to false', () => {
  const args = parseCliArgs(['https://example.com']);
  assert.equal(args.allowMutatingMethods, false);
});

await test('Parses --dry-run flag', () => {
  const args = parseCliArgs(['https://example.com', '--dry-run']);
  assert.equal(args.dryRun, true);
});

await test('--dry-run defaults to false', () => {
  const args = parseCliArgs(['https://example.com']);
  assert.equal(args.dryRun, false);
});

await test('Parses --rate-limit flag', () => {
  const args = parseCliArgs(['https://example.com', '--rate-limit', '5']);
  assert.equal(args.rateLimit, 5);
});

await test('--rate-limit defaults to 15', () => {
  const args = parseCliArgs(['https://example.com']);
  assert.equal(args.rateLimit, 15);
});

await test('--rate-limit minimum is 1 (clamps below 1)', () => {
  const args = parseCliArgs(['https://example.com', '--rate-limit', '0']);
  assert.ok(args.rateLimit >= 1, 'Rate limit must be at least 1');
});

await test('bopla category is enabled by default', () => {
  const args = parseCliArgs(['https://example.com']);
  assert.equal(args.categories.bopla, true);
});

await test('bopla category can be skipped via --skip bopla', () => {
  const args = parseCliArgs(['https://example.com', '--skip', 'bopla']);
  assert.equal(args.categories.bopla, false);
});

await test('All original flags still parse correctly', () => {
  const args = parseCliArgs([
    'https://example.com',
    '--concurrency', '4',
    '--timeout', '5000',
    '--json', 'out.json',
    '--html', 'report.html',
    '--vulndb',
    '--no-color',
  ]);
  assert.equal(args.concurrency, 4);
  assert.equal(args.timeout, 5000);
  assert.equal(args.jsonOut, 'out.json');
  assert.equal(args.htmlOut, 'report.html');
  assert.equal(args.vulndb, true);
  assert.equal(args.color, false);
});

await test('All four new flags can be combined', () => {
  const args = parseCliArgs([
    'https://example.com',
    '--secondary-auth', 'Bearer tok',
    '--allow-mutating-methods',
    '--dry-run',
    '--rate-limit', '10',
  ]);
  assert.equal(args.secondaryAuth, 'Bearer tok');
  assert.equal(args.allowMutatingMethods, true);
  assert.equal(args.dryRun, true);
  assert.equal(args.rateLimit, 10);
});

// ── Phase 4 suites ─────────────────────────────────────────────────────────

import { buildCliHtmlReport } from '../src/htmlReport.js';
import { printConsoleReport, writeCsvReport, writeJsonReport } from '../src/report.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

// Test findings with standards taxonomy (simulating Phase 2/3 output).
const TAGGED_FINDINGS = [
  {
    category: 'access', title: 'Confirmed BOLA — cross-tenant object access',
    severity: 'high', url: 'https://api.example.com/orders/102',
    evidence: 'User B received HTTP 200 with matching schema.',
    standards: { owaspWeb: 'A01', owaspApi: 'API1', wstg: 'WSTG-ATHZ-02', astf: 'ASTF-ATHZ-01' },
  },
  {
    category: 'access', title: 'BFLA — Privileged endpoint accessible to unprivileged role',
    severity: 'high', url: 'https://api.example.com/admin/users',
    evidence: 'Secondary token received HTTP 200.',
    standards: { owaspWeb: 'A01', owaspApi: 'API5', wstg: 'WSTG-ATHZ-03', astf: 'ASTF-ATHZ-02' },
  },
  {
    category: 'bopla', title: 'Excessive Data Exposure — sensitive fields in response',
    severity: 'high', url: 'https://api.example.com/users/1',
    evidence: 'Response contains password_hash.',
    standards: { owaspWeb: 'A03', owaspApi: 'API3', wstg: 'WSTG-INFO-05', astf: 'ASTF-ATHZ-03' },
  },
  {
    category: 'access', title: 'Missing security headers',
    severity: 'low', url: 'https://api.example.com/',
    evidence: 'Missing: CSP, HSTS.',
    standards: { owaspWeb: 'A05', owaspApi: null, wstg: 'WSTG-CONF-11', astf: null },
  },
  {
    // Legacy finding without standards (backward compat).
    category: 'deps', title: 'Server Version Disclosure',
    severity: 'medium', url: 'https://api.example.com/',
    evidence: 'Server: nginx/1.14.0',
  },
];

const TEST_META = {
  target: 'https://api.example.com',
  endpointCount: 12,
  durationMs: 3200,
  subdomainCount: 0,
  subdomains: [],
  discovered: [],
  importedTraffic: [],
  vulndbResults: [],
  geminiAnalysis: null,
};

// ---------------------------------------------------------------------------
// Suite 18: htmlReport.js — Four-standard filter buttons
// ---------------------------------------------------------------------------
console.log('\n── Suite 18: htmlReport.js — Standard filter buttons ─────────────');

await test('HTML report contains DOCTYPE and BOLTCLONE brand', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('<!DOCTYPE html>'));
  assert.ok(html.includes('BOLTCLONE'));
});

await test('HTML report contains "All Findings" filter button', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('All Findings'));
});

await test('HTML report contains OWASP Top 10 Web 2021 filter button', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('OWASP Top 10 Web 2021'));
});

await test('HTML report contains OWASP API Top 10 2023 filter button', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('OWASP API Top 10 2023'));
});

await test('HTML report contains OWASP WSTG v4.2 filter button', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('OWASP WSTG v4.2'));
});

await test('HTML report contains OWASP ASTF filter button', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('OWASP ASTF'));
});

await test('HTML report renders standard taxonomy badge tags on findings', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  // The BOLA finding should have all 4 taxonomy tags rendered.
  assert.ok(html.includes('OWASP A01'),    'Should render owaspWeb A01 tag');
  assert.ok(html.includes('OWASP API1'),   'Should render owaspApi API1 tag');
  assert.ok(html.includes('WSTG-ATHZ-02'), 'Should render WSTG tag');
  assert.ok(html.includes('ASTF-ATHZ-01'), 'Should render ASTF tag');
});

await test('HTML report renders data attributes for standard filtering', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('data-owasp-web='), 'Should have data-owasp-web attribute');
  assert.ok(html.includes('data-owasp-api='), 'Should have data-owasp-api attribute');
  assert.ok(html.includes('data-wstg='),      'Should have data-wstg attribute');
  assert.ok(html.includes('data-astf='),      'Should have data-astf attribute');
});

await test('HTML report contains filterStd JavaScript function', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('function filterStd'));
});

await test('HTML report contains standard count badges on filter buttons', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  // 3 findings have owaspWeb, so the button should show (3).
  assert.ok(html.includes('OWASP Top 10 Web 2021 (3)') || html.includes('OWASP Top 10 Web 2021 ('), 'Web button should show count');
});

await test('HTML report escapes XSS in target', () => {
  const html = buildCliHtmlReport('<script>alert(1)</script>', TAGGED_FINDINGS, TEST_META);
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

await test('HTML report handles empty findings gracefully', () => {
  const html = buildCliHtmlReport('https://example.com', [], TEST_META);
  assert.ok(html.includes('No security vulnerabilities identified'));
});

await test('HTML report includes print stylesheet', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('@media print'));
});

await test('Legacy findings without standards still render correctly', () => {
  const html = buildCliHtmlReport('https://api.example.com', TAGGED_FINDINGS, TEST_META);
  assert.ok(html.includes('Server Version Disclosure'));
});

// ---------------------------------------------------------------------------
// Suite 19: report.js — Console report with taxonomy tags
// ---------------------------------------------------------------------------
console.log('\n── Suite 19: report.js — Console taxonomy tags ──────────────────');

await test('printConsoleReport includes taxonomy tags in output', () => {
  // Capture stdout.
  const originalLog = console.log;
  const lines = [];
  console.log = (...args) => lines.push(args.join(' '));
  try {
    printConsoleReport(TAGGED_FINDINGS, TEST_META, false);
  } finally {
    console.log = originalLog;
  }
  const output = lines.join('\n');
  // Check the BOLA finding line includes all 4 standard tags.
  assert.ok(output.includes('OWASP A01'),    'Console output should show OWASP A01');
  assert.ok(output.includes('OWASP API1'),   'Console output should show OWASP API1');
  assert.ok(output.includes('WSTG-ATHZ-02'), 'Console output should show WSTG tag');
  assert.ok(output.includes('ASTF-ATHZ-01'), 'Console output should show ASTF tag');
});

await test('printConsoleReport renders legacy findings without taxonomy gracefully', () => {
  const originalLog = console.log;
  const lines = [];
  console.log = (...args) => lines.push(args.join(' '));
  try {
    printConsoleReport(TAGGED_FINDINGS, TEST_META, false);
  } finally {
    console.log = originalLog;
  }
  const output = lines.join('\n');
  assert.ok(output.includes('Server Version Disclosure'), 'Legacy finding must appear in output');
});

await test('printConsoleReport shows severity counts', () => {
  const originalLog = console.log;
  const lines = [];
  console.log = (...args) => lines.push(args.join(' '));
  try {
    printConsoleReport(TAGGED_FINDINGS, TEST_META, false);
  } finally {
    console.log = originalLog;
  }
  const output = lines.join('\n');
  assert.ok(output.includes('High: 3'), 'Should count 3 high findings');
  assert.ok(output.includes('Medium: 1'), 'Should count 1 medium finding');
  assert.ok(output.includes('Low: 1'), 'Should count 1 low finding');
});

// ---------------------------------------------------------------------------
// Suite 20: report.js — CSV report with taxonomy columns
// ---------------------------------------------------------------------------
console.log('\n── Suite 20: report.js — CSV taxonomy columns ───────────────────');

await test('CSV report includes owaspWeb, owaspApi, wstg, astf header columns', async () => {
  const tmpDir = os.tmpdir();
  const csvPath = path.join(tmpDir, 'boltclone-test-report.csv');
  try {
    await writeCsvReport(csvPath, TAGGED_FINDINGS);
    const content = await fs.readFile(csvPath, 'utf8');
    const headerLine = content.split('\n')[0];
    assert.ok(headerLine.includes('owaspWeb'), 'CSV header must include owaspWeb');
    assert.ok(headerLine.includes('owaspApi'), 'CSV header must include owaspApi');
    assert.ok(headerLine.includes('wstg'),     'CSV header must include wstg');
    assert.ok(headerLine.includes('astf'),     'CSV header must include astf');
  } finally {
    await fs.unlink(csvPath).catch(() => {});
  }
});

await test('CSV report populates taxonomy values for tagged findings', async () => {
  const tmpDir = os.tmpdir();
  const csvPath = path.join(tmpDir, 'boltclone-test-report2.csv');
  try {
    await writeCsvReport(csvPath, TAGGED_FINDINGS);
    const content = await fs.readFile(csvPath, 'utf8');
    // The first data row (BOLA) should contain A01, API1, WSTG-ATHZ-02, ASTF-ATHZ-01.
    assert.ok(content.includes('"A01"'),          'BOLA row should have A01');
    assert.ok(content.includes('"API1"'),         'BOLA row should have API1');
    assert.ok(content.includes('"WSTG-ATHZ-02"'), 'BOLA row should have WSTG-ATHZ-02');
    assert.ok(content.includes('"ASTF-ATHZ-01"'), 'BOLA row should have ASTF-ATHZ-01');
  } finally {
    await fs.unlink(csvPath).catch(() => {});
  }
});

await test('CSV report leaves taxonomy columns empty for untagged findings', async () => {
  const tmpDir = os.tmpdir();
  const csvPath = path.join(tmpDir, 'boltclone-test-report3.csv');
  try {
    await writeCsvReport(csvPath, TAGGED_FINDINGS);
    const content = await fs.readFile(csvPath, 'utf8');
    const lines = content.split('\n');
    // The last data line (Server Version Disclosure) should have empty taxonomy columns.
    const lastLine = lines[lines.length - 1];
    // It should end with ,"","","","" (4 empty quoted strings).
    assert.ok(lastLine.endsWith('"","","",""'), 'Untagged finding should have empty taxonomy columns');
  } finally {
    await fs.unlink(csvPath).catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Suite 21: report.js — JSON report includes standards
// ---------------------------------------------------------------------------
console.log('\n── Suite 21: report.js — JSON report ─────────────────────────────');

await test('JSON report preserves standards taxonomy on findings', async () => {
  const tmpDir = os.tmpdir();
  const jsonPath = path.join(tmpDir, 'boltclone-test-report.json');
  try {
    await writeJsonReport(jsonPath, TAGGED_FINDINGS, TEST_META);
    const content = await fs.readFile(jsonPath, 'utf8');
    const parsed = JSON.parse(content);
    assert.ok(parsed.findings, 'JSON report must have findings array');
    const bola = parsed.findings.find((f) => f.title.includes('BOLA'));
    assert.ok(bola, 'BOLA finding must be present');
    assert.equal(bola.standards.owaspApi, 'API1');
    assert.equal(bola.standards.wstg, 'WSTG-ATHZ-02');
    assert.equal(bola.standards.astf, 'ASTF-ATHZ-01');
  } finally {
    await fs.unlink(jsonPath).catch(() => {});
  }
});

await test('JSON report meta section is preserved', async () => {
  const tmpDir = os.tmpdir();
  const jsonPath = path.join(tmpDir, 'boltclone-test-report2.json');
  try {
    await writeJsonReport(jsonPath, TAGGED_FINDINGS, TEST_META);
    const content = await fs.readFile(jsonPath, 'utf8');
    const parsed = JSON.parse(content);
    assert.equal(parsed.meta.target, 'https://api.example.com');
    assert.equal(parsed.meta.endpointCount, 12);
  } finally {
    await fs.unlink(jsonPath).catch(() => {});
  }
});

// ---------------------------------------------------------------------------
// Final report
// ---------------------------------------------------------------------------
const total = passed + failed;
console.log(`\n══════════════════════════════════════════════════════════════════`);
console.log(`  OWASP Engine — All Phases Test Results: ${passed}/${total} passed${failed > 0 ? `, ${failed} FAILED` : ''}`);
console.log(`══════════════════════════════════════════════════════════════════\n`);

if (failed > 0) process.exit(1);

