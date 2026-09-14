import { safeFetch } from '../http.js';

const GRAPHQL_PATHS = [
  '/graphql', '/api/graphql', '/gql', '/query',
  '/graphql/v1', '/v1/graphql', '/api/v1/graphql'
];

/**
 * Probe common GraphQL paths and return the first live endpoint, or null.
 */
async function findGraphqlEndpoint(baseUrl, timeout) {
  for (const path of GRAPHQL_PATHS) {
    let url;
    try { url = new URL(path, baseUrl).toString(); } catch { continue; }
    const resp = await safeFetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: '{ __typename }' })
    }, timeout);
    if (resp && resp.status < 500) {
      const data = await resp.json().catch(() => null);
      if (data?.data || data?.errors) return url;
    }
  }
  return null;
}

/**
 * Check 1: Introspection enabled — full schema disclosure.
 */
export async function checkGraphqlIntrospection(endpoint, timeout) {
  const resp = await safeFetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: '{ __schema { types { name } } }' })
  }, timeout);
  if (!resp) return null;
  const data = await resp.json().catch(() => null);
  if (data?.data?.__schema) {
    const typeCount = data.data.__schema.types?.length ?? 0;
    return {
      category: 'graphql',
      title: 'GraphQL introspection enabled',
      severity: 'medium',
      url: endpoint,
      evidence: `Schema exposes ${typeCount} types. Disable introspection in production to prevent full schema reconnaissance.`
    };
  }
  return null;
}

/**
 * Check 2: Query batching — enables DoS amplification.
 */
export async function checkGraphqlBatching(endpoint, timeout) {
  const batch = Array.from({ length: 10 }, () => ({ query: '{ __typename }' }));
  const resp = await safeFetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(batch)
  }, timeout);
  if (!resp) return null;
  const data = await resp.json().catch(() => null);
  if (Array.isArray(data) && data.length >= 2) {
    return {
      category: 'graphql',
      title: 'GraphQL query batching enabled',
      severity: 'medium',
      url: endpoint,
      evidence: `Server responded to a batch of 10 queries. Batching enables DoS amplification and rate-limit bypass.`
    };
  }
  return null;
}

/**
 * Check 3: Field suggestions in errors — aids schema enumeration without introspection.
 */
export async function checkGraphqlFieldSuggestions(endpoint, timeout) {
  const resp = await safeFetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: '{ __typ }' }) // intentional typo
  }, timeout);
  if (!resp) return null;
  const data = await resp.json().catch(() => null);
  const errorStr = JSON.stringify(data?.errors ?? '');
  if (/did you mean/i.test(errorStr)) {
    return {
      category: 'graphql',
      title: 'GraphQL field suggestions enabled',
      severity: 'low',
      url: endpoint,
      evidence: 'Error messages reveal "Did you mean?" suggestions, aiding schema reconnaissance without full introspection.'
    };
  }
  return null;
}

/**
 * Run all GraphQL checks. Skips silently if no GraphQL endpoint is found.
 */
export async function runGraphqlChecks(baseUrl, timeout) {
  const endpoint = await findGraphqlEndpoint(baseUrl, timeout);
  if (!endpoint) return [];

  const [introspection, batching, suggestions] = await Promise.all([
    checkGraphqlIntrospection(endpoint, timeout),
    checkGraphqlBatching(endpoint, timeout),
    checkGraphqlFieldSuggestions(endpoint, timeout)
  ]);

  return [introspection, batching, suggestions].filter(Boolean);
}
