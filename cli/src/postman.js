export function buildCliPostman(discoveredUrls, trafficLogs = []) {
  const items = [];
  const seenMap = new Map();

  const entries = [...trafficLogs, ...discoveredUrls];

  entries.forEach((entry) => {
    const rawUrl = typeof entry === 'string' ? entry : (entry.url || '');
    if (!rawUrl) return;

    const method = (typeof entry === 'object' && entry.method ? entry.method : 'GET').toUpperCase();
    const key = `${method} ${rawUrl}`;
    if (seenMap.has(key)) return;
    seenMap.set(key, true);

    try {
      const urlObj = new URL(rawUrl);
      const hostParts = urlObj.hostname.split('.').filter(Boolean);
      const pathParts = urlObj.pathname.split('/').filter(Boolean);
      const queryParams = Array.from(urlObj.searchParams.entries()).map(([k, v]) => ({
        key: k,
        value: v
      }));

      items.push({
        name: `${method} ${urlObj.pathname}`,
        request: {
          method: method,
          header: [],
          url: {
            raw: rawUrl,
            protocol: urlObj.protocol.replace(':', ''),
            host: hostParts,
            path: pathParts,
            query: queryParams
          }
        }
      });
    } catch {
      // skip invalid URLs
    }
  });

  return {
    info: {
      name: 'BOLTCLONE Discovered Collection',
      description: 'Exported from BOLTCLONE CLI Security Tool',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
    },
    item: items
  };
}
