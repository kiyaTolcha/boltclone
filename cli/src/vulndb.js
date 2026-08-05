export async function queryOsvDb(packageName, version, ecosystem = 'npm') {
  if (!packageName) return [];
  try {
    const payload = {
      package: { name: packageName, ecosystem: ecosystem }
    };
    if (version) payload.version = version;

    const res = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (!res.ok) return [];
    const data = await res.json();
    const vulns = data.vulns || [];

    return vulns.map((v) => ({
      id: v.id,
      summary: v.summary || v.details?.slice(0, 150) || 'Security vulnerability reported in package',
      aliases: v.aliases || [],
      cve: (v.aliases || []).find((a) => a.startsWith('CVE-')) || v.id,
      published: v.published,
      references: (v.references || []).map((r) => r.url).slice(0, 2)
    }));
  } catch (err) {
    return [];
  }
}

export async function lookupSoftwareVulns(serverHeader) {
  if (!serverHeader || typeof serverHeader !== 'string') return [];
  const matches = serverHeader.match(/([a-zA-Z0-9_-]+)\/([0-9]+\.[0-9]+(?:\.[0-9]+)?)/g);
  if (!matches) return [];

  const results = [];
  for (const match of matches) {
    const [name, version] = match.split('/');
    if (name && version) {
      const pypiRes = await queryOsvDb(name.toLowerCase(), version, 'PyPI');
      const npmRes = await queryOsvDb(name.toLowerCase(), version, 'npm');
      const combined = [...pypiRes, ...npmRes];
      if (combined.length > 0) {
        results.push({
          software: name,
          version: version,
          vulns: combined.slice(0, 5)
        });
      }
    }
  }
  return results;
}
