export function timeoutFetch(url, opts = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(url, { ...opts, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}

export async function safeFetch(url, opts = {}, timeoutMs = 8000) {
  try {
    return await timeoutFetch(url, opts, timeoutMs);
  } catch {
    return null;
  }
}

// Bounded-concurrency pool: runs `worker` over `items` with at most `limit` in flight at once.
export async function pool(items, limit, worker) {
  const results = new Array(items.length);
  let next = 0;

  async function runner() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  }

  const runners = Array.from({ length: Math.min(limit, items.length) }, runner);
  await Promise.all(runners);
  return results;
}
