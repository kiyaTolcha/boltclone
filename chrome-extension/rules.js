function analyzeTraffic(logEntries) {
  const findings = [];

  const oauthPaths = logEntries.filter((e) => e.url.includes('/users/') || e.url.includes('/orders/') || e.url.includes('/api/'));

  oauthPaths.forEach((entry) => {
    if (entry.url.includes('/api/') && entry.method === 'GET' && entry.statusCode >= 200 && entry.statusCode < 300) {
      const parts = new URL(entry.url).pathname.split('/').filter(Boolean);
      const idSegments = parts.filter((p) => /^\d+$/.test(p));
      if (idSegments.length) {
        findings.push({
          type: 'BOLA',
          severity: 'high',
          message: `Potential object enumeration via ID path in ${entry.method} ${entry.url}`,
          entry
        });
      }
    }
  });

  logEntries.forEach((entry) => {
    if (entry.requestHeaders?.some((h) => h.name.toLowerCase() === 'authorization')) {
      const role = entry.requestHeaders.find((h) => h.name.toLowerCase() === 'x-user-role');
      if (!role) {
        findings.push({ type: 'RBAC', severity: 'medium', message: `Missing role header when accessing ${entry.url}`, entry });
      }
    }
  });

  const massAssignCandidates = logEntries.filter((entry) => entry.method === 'POST' && entry.requestBody?.formData);
  massAssignCandidates.forEach((entry) => {
    const fields = Object.keys(entry.requestBody.formData || {});
    const dangerous = ['isAdmin', 'role', 'userType', 'permissions'];
    if (fields.some((f) => dangerous.includes(f))) {
      findings.push({ type: 'MassAssignment', severity: 'high', message: `Potential mass assignment fields in request to ${entry.url}: ${fields.join(', ')}`, entry });
    }
  });

  return findings;
}

if (typeof self !== 'undefined') {
  self.analyzeTraffic = analyzeTraffic;
} else if (typeof window !== 'undefined') {
  window.analyzeTraffic = analyzeTraffic;
}
