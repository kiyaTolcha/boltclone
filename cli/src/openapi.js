function inferType(val) {
  if (val === null || val === undefined) return { type: 'string', nullable: true };
  if (typeof val === 'boolean') return { type: 'boolean' };
  if (typeof val === 'number') return Number.isInteger(val) ? { type: 'integer' } : { type: 'number' };
  if (typeof val === 'string') return { type: 'string', example: val };
  if (Array.isArray(val)) {
    const itemSchema = val.length > 0 ? inferType(val[0]) : { type: 'string' };
    return { type: 'array', items: itemSchema };
  }
  if (typeof val === 'object') {
    const properties = {};
    for (const [k, v] of Object.entries(val)) {
      properties[k] = inferType(v);
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

export function buildCliOpenApi(discoveredUrls, trafficLogs = []) {
  const paths = {};

  // Process traffic logs if available
  trafficLogs.forEach((entry) => {
    const rawUrl = entry.url || entry;
    if (typeof rawUrl !== 'string') return;
    try {
      const u = new URL(rawUrl);
      const { path: route, pathParams } = normalizePath(u.pathname);
      const method = (entry.method || 'GET').toLowerCase();

      paths[route] = paths[route] || {};
      paths[route][method] = paths[route][method] || {
        summary: `${method.toUpperCase()} ${route}`,
        parameters: [],
        responses: { '200': { description: 'Successful response' } }
      };

      const op = paths[route][method];

      pathParams.forEach((pp) => {
        if (!op.parameters.some((p) => p.name === pp.name && p.in === 'path')) {
          op.parameters.push(pp);
        }
      });

      Array.from(u.searchParams.entries()).forEach(([k, v]) => {
        if (!op.parameters.some((p) => p.name === k && p.in === 'query')) {
          op.parameters.push({ name: k, in: 'query', required: false, schema: { type: 'string' }, example: v });
        }
      });
    } catch {
      // skip invalid URLs
    }
  });

  // Process discovered endpoints
  discoveredUrls.forEach((endpoint) => {
    const rawUrl = typeof endpoint === 'string' ? endpoint : endpoint.url;
    if (!rawUrl) return;
    try {
      const u = new URL(rawUrl);
      const { path: route, pathParams } = normalizePath(u.pathname);
      const method = (endpoint.method || 'GET').toLowerCase();

      paths[route] = paths[route] || {};
      if (!paths[route][method]) {
        paths[route][method] = {
          summary: `${method.toUpperCase()} ${route}`,
          parameters: pathParams,
          responses: { '200': { description: 'Discovered endpoint' } }
        };
      }
    } catch {
      // skip invalid URLs
    }
  });

  return {
    openapi: '3.0.0',
    info: {
      title: 'BOLTCLONE Discovered API Inventory',
      version: '1.0.0'
    },
    paths
  };
}
