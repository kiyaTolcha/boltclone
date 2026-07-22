import { writeFile } from 'node:fs/promises';

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
    console.log(`${sevTag} ${paint(f.title, 'bold', color)}`);
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
  const headers = ['category', 'title', 'severity', 'url', 'evidence'];
  const lines = [headers.join(',')];
  findings.forEach((f) => {
    lines.push(headers.map((h) => csvEscape(f[h])).join(','));
  });
  await writeFile(path, lines.join('\n'), 'utf8');
}
