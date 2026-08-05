import { generateHtmlReport } from '../../chrome-extension/htmlReport.js';

export function buildCliHtmlReport(target, findings, meta = {}) {
  return generateHtmlReport({
    target,
    findings,
    meta,
    discovered: meta.discovered || [],
    traffic: meta.importedTraffic || []
  });
}
