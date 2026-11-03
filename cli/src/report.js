import { writeFile } from 'node:fs/promises';
import { buildCliHtmlReport } from './htmlReport.js';

const COLORS = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', yellow: '\x1b[33m', blue: '\x1b[34m', cyan: '\x1b[36m', green: '\x1b[32m', gray: '\x1b[90m'
};

const SEVERITY_COLOR = { high: 'red', medium: 'yellow', low: 'blue', info: 'gray' };
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

function paint(text, color, enabled) {
  if (!enabled) return text;
  return `${COLORS[color]}${text}${COLORS.reset}`;
}

/**
 * Builds a parenthesized taxonomy tag string from the four-standard `standards`
 * object attached to a finding by Phase 2/3 checks.
 *
 * Example output: "(OWASP API1 | WSTG-ATHZ-02 | ASTF-ATHZ-01)"
 *
 * Returns an empty string if no standards object exists (backward compat with
 * findings generated before the OWASP engine was added).
 *
 * @param {object|null} standards  { owaspWeb, owaspApi, wstg, astf }
 * @returns {string}
 */
function formatStandardsTags(standards) {
  if (!standards) return '';
  const parts = [];
  if (standards.owaspWeb) parts.push(`OWASP ${standards.owaspWeb}`);
  if (standards.owaspApi) parts.push(`OWASP ${standards.owaspApi}`);
  if (standards.wstg)     parts.push(standards.wstg);
  if (standards.astf)     parts.push(standards.astf);
  return parts.length > 0 ? ` (${parts.join(' | ')})` : '';
}

export function printConsoleReport(findings, meta, color) {
  const sorted = [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((f) => counts[f.severity]++);

  console.log('');
  console.log(paint(`BOLTCLONE vulnerability assessment: ${meta.target}`, 'bold', color));
  console.log(paint(`Endpoints scanned: ${meta.endpointCount}  |  Duration: ${meta.durationMs}ms`, 'dim', color));
  console.log(paint(`High: ${counts.high}  Medium: ${counts.medium}  Low: ${counts.low}  Info: ${counts.info}`, 'dim', color));
  console.log('');

  if (sorted.length === 0) {
    console.log(paint('No findings.', 'green', color));
    return;
  }

  sorted.forEach((f) => {
    const sevTag = paint(`[${f.severity.toUpperCase()}]`, SEVERITY_COLOR[f.severity], color);
    const tags = formatStandardsTags(f.standards);
    const tagsColored = tags ? paint(tags, 'cyan', color) : '';
    console.log(`${sevTag} ${paint(f.title, 'bold', color)}${tagsColored}`);
    console.log(`  ${paint('category:', 'dim', color)} ${f.category}  ${paint('url:', 'dim', color)} ${f.url}`);
    console.log(`  ${paint('evidence:', 'dim', color)} ${f.evidence}`);
    console.log('');
  });
}

export async function writeJsonReport(path, findings, meta) {
  await writeFile(path, JSON.stringify({ meta, findings }, null, 2), 'utf8');
}

function csvEscape(value) {
  if (value == null) return '';
  return `"${String(value).replace(/"/g, '""')}"`;
}

export async function writeCsvReport(path, findings) {
  const headers = ['category', 'title', 'severity', 'url', 'evidence', 'owaspWeb', 'owaspApi', 'wstg', 'astf'];
  const lines = [headers.join(',')];
  findings.forEach((f) => {
    const std = f.standards || {};
    lines.push([
      csvEscape(f.category),
      csvEscape(f.title),
      csvEscape(f.severity),
      csvEscape(f.url),
      csvEscape(f.evidence),
      csvEscape(std.owaspWeb || ''),
      csvEscape(std.owaspApi || ''),
      csvEscape(std.wstg || ''),
      csvEscape(std.astf || ''),
    ].join(','));
  });
  await writeFile(path, lines.join('\n'), 'utf8');
}

export async function writeHtmlReport(path, target, findings, meta) {
  const html = buildCliHtmlReport(target, findings, meta);
  await writeFile(path, html, 'utf8');
}
