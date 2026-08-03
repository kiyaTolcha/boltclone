function inferSchema(val) {
  if (val === null || val === undefined) return { type: 'string', nullable: true };
  if (typeof val === 'boolean') return { type: 'boolean' };
  if (typeof val === 'number') return Number.isInteger(val) ? { type: 'integer' } : { type: 'number' };
  if (typeof val === 'string') return { type: 'string', example: val };
  if (Array.isArray(val)) {
    const itemSchema = val.length > 0 ? inferSchema(val[0]) : { type: 'string' };
    return { type: 'array', items: itemSchema };
  }
  if (typeof val === 'object') {
    const properties = {};
    for (const [k, v] of Object.entries(val)) {
      properties[k] = inferSchema(v);
    }
    return { type: 'object', properties };
  }
  return { type: 'string' };
}

function normalizePath(pathname) {
  const clean = pathname.replace(/\/+/g, '/');
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const segments = clean.split('/').filter(Boolean);
  const pathParams = [];

  const normalizedSegments = segments.map((seg, idx) => {
    if (/^\d+$/.test(seg)) {
      const name = idx > 0 ? `${segments[idx - 1].replace(/s$/, '')}Id` : 'id';
      pathParams.push({ name, in: 'path', required: true, schema: { type: 'integer' } });
      return `{${name}}`;
    }
    if (uuidRegex.test(seg)) {
      const name = idx > 0 ? `${segments[idx - 1].replace(/s$/, '')}Uuid` : 'uuid';
      pathParams.push({ name, in: 'path', required: true, schema: { type: 'string', format: 'uuid' } });
      return `{${name}}`;
    }
    return seg;
  });

  return {
    path: '/' + normalizedSegments.join('/'),
    pathParams
  };
}

function buildOpenApi(logs) {
  const paths = {};
  const securitySchemes = {};
  const hasSecurity = { bearer: false, basic: false, apiKey: false };

  logs.forEach((entry) => {
    if (!entry.url || !entry.method) return;

    try {
      const url = new URL(entry.url);
      const { path: route, pathParams } = normalizePath(url.pathname);
      const query = Array.from(url.searchParams.entries());
      const method = entry.method.toLowerCase();

      paths[route] = paths[route] || {};
      paths[route][method] = paths[route][method] || {
        summary: `Captured ${entry.method} ${route}`,
        parameters: [],
        responses: {}
      };

      const op = paths[route][method];

      // Add path parameters
      pathParams.forEach((pp) => {
        if (!op.parameters.some((p) => p.name === pp.name && p.in === 'path')) {
          op.parameters.push(pp);
        }
      });

      // Add query parameters
      query.forEach(([name, value]) => {
        if (!op.parameters.some((p) => p.name === name && p.in === 'query')) {
          const type = /^\d+$/.test(value) ? 'integer' : (value === 'true' || value === 'false') ? 'boolean' : 'string';
          op.parameters.push({ name, in: 'query', required: false, schema: { type }, example: value });
        }
      });

      // Request security detection
      if (entry.requestHeaders) {
        entry.requestHeaders.forEach((h) => {
          const nameLower = h.name.toLowerCase();
          if (nameLower === 'authorization') {
            if (/^bearer /i.test(h.value)) {
              hasSecurity.bearer = true;
              op.security = op.security || [];
              if (!op.security.some((s) => s.bearerAuth)) op.security.push({ bearerAuth: [] });
            } else if (/^basic /i.test(h.value)) {
              hasSecurity.basic = true;
              op.security = op.security || [];
              if (!op.security.some((s) => s.basicAuth)) op.security.push({ basicAuth: [] });
            }
          } else if (nameLower === 'x-api-key' || nameLower === 'api-key') {
            hasSecurity.apiKey = true;
            op.security = op.security || [];
            if (!op.security.some((s) => s.apiKeyAuth)) op.security.push({ apiKeyAuth: [] });
          }
        });
      }

      // Request Body
      if (entry.requestBody && entry.requestBody.raw && entry.requestBody.raw.length) {
        try {
          const rawText = new TextDecoder().decode(entry.requestBody.raw[0].bytes || new Uint8Array());
          const parsed = JSON.parse(rawText);
          op.requestBody = {
            content: {
              'application/json': {
                schema: inferSchema(parsed),
                example: parsed
              }
            }
          };
        } catch {
          // Non-JSON or plain text request body
        }
      }

      // Response
      const status = entry.statusCode || 'default';
      op.responses[status] = op.responses[status] || { description: `Response code ${status}`, headers: {} };
      if (entry.responseHeaders) {
        entry.responseHeaders.forEach((h) => {
          if (h.name && !op.responses[status].headers[h.name]) {
            op.responses[status].headers[h.name] = { schema: { type: 'string' } };
          }
        });
      }

    } catch (e) {
      console.warn('OpenAPI mapping skip', e);
    }
  });

  if (hasSecurity.bearer) securitySchemes.bearerAuth = { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' };
  if (hasSecurity.basic) securitySchemes.basicAuth = { type: 'http', scheme: 'basic' };
  if (hasSecurity.apiKey) securitySchemes.apiKeyAuth = { type: 'apiKey', in: 'header', name: 'X-API-Key' };

  const openapi = {
    openapi: '3.0.0',
    info: { title: 'BOLTCLONE API Inventory', version: '1.0.0' },
    paths
  };

  if (Object.keys(securitySchemes).length > 0) {
    openapi.components = { securitySchemes };
  }

  return openapi;
}

if (typeof self !== 'undefined') {
  self.buildOpenApi = buildOpenApi;
} else if (typeof window !== 'undefined') {
  window.buildOpenApi = buildOpenApi;
}
if (typeof globalThis !== 'undefined') {
  globalThis.buildOpenApi = buildOpenApi;
}
