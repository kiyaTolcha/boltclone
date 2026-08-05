import fs from 'node:fs/promises';
import { pool } from './http.js';
import { discoverEndpoints, enumerateSubdomains } from './discovery.js';
import { runInjectionChecks } from './checks/injection.js';
import { runAccessChecks } from './checks/access.js';
import { runTlsChecks } from './checks/tls.js';
import { runDependencyChecks } from './checks/deps.js';
import { runAuthChecks } from './checks/auth.js';
import { lookupSoftwareVulns } from './vulndb.js';
import { analyzeWithGemini } from './gemini.js';

export function normalizeTarget(value) {
  const withScheme = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  return new URL(withScheme).toString().replace(/\/$/, '');
}

export async function runScan({ target, concurrency, timeout, categories, credsFile, importSession, vulndb, geminiKey, onProgress }) {
  const startTime = Date.now();
  const baseUrl = normalizeTarget(target);
  const hostname = new URL(baseUrl).hostname;
  const findings = [];
  let importedTraffic = [];
  let geminiAnalysis = null;
  let vulndbResults = [];

  if (importSession) {
    try {
      onProgress?.(`Importing session file ${importSession} ...`);
      const raw = await fs.readFile(importSession, 'utf8');
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        importedTraffic = parsed;
      } else if (parsed.boltcloneTraffic && Array.isArray(parsed.boltcloneTraffic)) {
        importedTraffic = parsed.boltcloneTraffic;
      } else if (parsed.analysis && Array.isArray(parsed.analysis)) {
        importedTraffic = parsed.analysis;
      }
      onProgress?.(`Imported ${importedTraffic.length} entry/entries from session file.`);
    } catch (err) {
      onProgress?.(`Warning: Failed to parse session file: ${err.message}`);
    }
  }

  onProgress?.(`Discovering endpoints on ${baseUrl} ...`);
  const discovered = await discoverEndpoints(baseUrl, { concurrency, timeout });
  onProgress?.(`Found ${discovered.length} endpoint(s).`);

  let subdomains = [];
  if (categories.subdomains) {
    onProgress?.(`Enumerating subdomains for ${hostname} via crt.sh ...`);
    subdomains = await enumerateSubdomains(hostname, { timeout });
    onProgress?.(`Found ${subdomains.length} subdomain(s).`);
  }

  const importedUrls = importedTraffic
    .map((e) => (typeof e === 'string' ? e : e.url))
    .filter(Boolean);

  const scanTargets = Array.from(new Set([baseUrl, ...discovered.map((d) => d.url), ...importedUrls]));

  if (categories.injection || categories.access) {
    onProgress?.(`Running injection/access checks against ${scanTargets.length} endpoint(s) ...`);
    await pool(scanTargets, concurrency, async (url) => {
      if (categories.injection) findings.push(...await runInjectionChecks(url, timeout));
      if (categories.access) findings.push(...await runAccessChecks(url, timeout));
    });
  }

  const sideTasks = [];
  if (categories.tls) {
    sideTasks.push((async () => {
      onProgress?.('Running TLS/certificate checks ...');
      findings.push(...await runTlsChecks(hostname, timeout));
    })());
  }
  if (categories.deps) {
    sideTasks.push((async () => {
      onProgress?.('Fingerprinting dependencies and checking OSV.dev ...');
      findings.push(...await runDependencyChecks(baseUrl, timeout));
    })());
  }
  await Promise.all(sideTasks);

  if (categories.auth) {
    onProgress?.('Running opt-in auth checks (only against targets you are authorized to test) ...');
    findings.push(...await runAuthChecks(baseUrl, discovered, timeout, credsFile));
  }

  if (vulndb) {
    onProgress?.('Querying Vulnerability Databases (OSV.dev / NVD) for server technologies ...');
    const depFinding = findings.find((f) => f.category === 'deps' && f.evidence?.includes('Server:'));
    if (depFinding) {
      vulndbResults = await lookupSoftwareVulns(depFinding.evidence);
      if (vulndbResults.length > 0) {
        vulndbResults.forEach((res) => {
          res.vulns.forEach((v) => {
            findings.push({
              category: 'vulndb',
              title: `Vulnerability in ${res.software} ${res.version}: ${v.cve}`,
              severity: 'high',
              url: baseUrl,
              evidence: `CVE ID: ${v.cve} | Summary: ${v.summary}`
            });
          });
        });
      }
    }
  }

  if (geminiKey) {
    try {
      onProgress?.('Synthesizing threat analysis & remediation guidance via Google Gemini AI ...');
      geminiAnalysis = await analyzeWithGemini(geminiKey, findings, { target: baseUrl, endpointCount: scanTargets.length });
    } catch (err) {
      onProgress?.(`Warning: Gemini AI analysis failed: ${err.message}`);
    }
  }

  return {
    findings,
    meta: {
      target: baseUrl,
      endpointCount: scanTargets.length,
      subdomainCount: subdomains.length,
      subdomains,
      discovered,
      importedTraffic,
      vulndbResults,
      geminiAnalysis,
      durationMs: Date.now() - startTime
    }
  };
}
