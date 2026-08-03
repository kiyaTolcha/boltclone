function buildPostmanCollection(logs) {
  const items = [];
  const seenMap = new Map();

  logs.forEach((entry) => {
    if (!entry.url || !entry.method) return;

    const method = entry.method.toUpperCase();
    const key = `${method} ${entry.url}`;
    if (seenMap.has(key)) return;
    seenMap.set(key, true);

    try {
      const urlObj = new URL(entry.url);
      const hostParts = urlObj.hostname.split('.').filter(Boolean);
      const pathParts = urlObj.pathname.split('/').filter(Boolean);
      const queryParams = Array.from(urlObj.searchParams.entries()).map(([k, v]) => ({
        key: k,
        value: v
      }));

      const headers = (entry.requestHeaders || []).map((h) => ({
        key: h.name,
        value: h.value
      }));

      const request = {
        method: method,
        header: headers,
        url: {
          raw: entry.url,
          protocol: urlObj.protocol.replace(':', ''),
          host: hostParts,
          path: pathParts,
          query: queryParams
        }
      };

      if (entry.requestBody && entry.requestBody.raw && entry.requestBody.raw.length) {
        try {
          const rawText = new TextDecoder().decode(entry.requestBody.raw[0].bytes || new Uint8Array());
          request.body = {
            mode: 'raw',
            raw: rawText,
            options: {
              raw: {
                language: 'json'
              }
            }
          };
        } catch {
          // ignore parsing error
        }
      }

      items.push({
        name: `${method} ${urlObj.pathname}`,
        request: request
      });
    } catch (e) {
      console.warn('Postman mapping skip', e);
    }
  });

  return {
    info: {
      name: 'BOLTCLONE Captured Collection',
      description: 'Exported from BOLTCLONE API Security Extension',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
    },
    item: items
  };
}

if (typeof self !== 'undefined') {
  self.buildPostmanCollection = buildPostmanCollection;
} else if (typeof window !== 'undefined') {
  window.buildPostmanCollection = buildPostmanCollection;
}
if (typeof globalThis !== 'undefined') {
  globalThis.buildPostmanCollection = buildPostmanCollection;
}
