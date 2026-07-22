import { parseArgs } from 'node:util';

const HELP = `
BOLTCLONE CLI - web app / API vulnerability assessment

Usage:
  boltclone <target-url> [options]

Options:
  -c, --concurrency <n>   Max concurrent requests (default: 8)
  -t, --timeout <ms>      Per-request timeout in ms (default: 8000)
      --skip <list>       Comma-separated categories to skip: injection,access,tls,deps
      --auth-test         Enable opt-in auth/brute-force checks (only against targets you own or are authorized to test)
      --creds <file>      Path to a JSON file of {username,password} pairs for --auth-test (default: small built-in list)
      --subdomains        Enable opt-in subdomain enumeration via crt.sh (queries a third-party service with the target domain)
      --json <file>       Write full results as JSON to <file>
      --csv <file>        Write findings as CSV to <file>
      --no-color          Disable colored output
  -h, --help              Show this help

Examples:
  boltclone https://example.com
  boltclone https://example.com --skip tls,deps --json report.json
  boltclone https://example.com --auth-test --subdomains
`;

export function parseCliArgs(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      concurrency: { type: 'string', short: 'c', default: '8' },
      timeout: { type: 'string', short: 't', default: '8000' },
      skip: { type: 'string', default: '' },
      'auth-test': { type: 'boolean', default: false },
      creds: { type: 'string' },
      subdomains: { type: 'boolean', default: false },
      json: { type: 'string' },
      csv: { type: 'string' },
      'no-color': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false }
    }
  });

  if (values.help || positionals.length === 0) {
    return { help: true, helpText: HELP };
  }

  const skip = new Set(values.skip.split(',').map((s) => s.trim()).filter(Boolean));

  return {
    help: false,
    target: positionals[0],
    concurrency: Math.max(1, parseInt(values.concurrency, 10) || 8),
    timeout: Math.max(1000, parseInt(values.timeout, 10) || 8000),
    categories: {
      injection: !skip.has('injection'),
      access: !skip.has('access'),
      tls: !skip.has('tls'),
      deps: !skip.has('deps'),
      auth: values['auth-test'],
      subdomains: values.subdomains
    },
    credsFile: values.creds || null,
    jsonOut: values.json || null,
    csvOut: values.csv || null,
    color: !values['no-color']
  };
}
