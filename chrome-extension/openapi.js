function buildOpenApi(logs) {
  const paths = {};

  logs.forEach((entry) => {
    if (!entry.url || !entry.method) return;

    try {
      const url = new URL(entry.url);
      const route = url.pathname.replace(/\/+/g, '/');
      const query = Array.from(url.searchParams.entries());

      paths[route] = paths[route] || {};
      paths[route][entry.method.toLowerCase()] = paths[route][entry.method.toLowerCase()] || {
        summary: `Captured ${entry.method} ${route}`,
        parameters: [],
        responses: {},
      };

      const op = paths[route][entry.method.toLowerCase()];

      query.forEach(([name, value]) => {
        if (!op.parameters.some((p) => p.name === name && p.in === 'query')) {
          op.parameters.push({ name, in: 'query', required: false, schema: { type: 'string' }, example: value });
        }
      });

      if (entry.requestBody && entry.requestBody.raw && entry.requestBody.raw.length) {
        op.requestBody = {
          content: {
            'application/json': {
              schema: { type: 'object' },
              example: JSON.parse(new TextDecoder().decode(entry.requestBody.raw[0].bytes || new Uint8Array()))
            }
          }
        };
      }

      const status = entry.statusCode || 'default';
      op.responses[status] = op.responses[status] || { description: 'Captured response', headers: {} };
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

  const openapi = {
    openapi: '3.0.0',
    info: { title: 'BOLTCLONE API Inventory', version: '1.0.0' },
    paths
  };

  return openapi;
}

if (typeof self !== 'undefined') {
  self.buildOpenApi = buildOpenApi;
} else if (typeof window !== 'undefined') {
  window.buildOpenApi = buildOpenApi;
}
