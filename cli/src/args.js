import { parseArgs } from 'node:util';

const HELP = `
BOLTCLONE CLI - web app / API vulnerability assessment

Usage:
  boltclone <target-url> [options]

Options:
  -c, --concurrency <n>   Max concurrent requests (default: 8)
  -t, --timeout <ms>      Per-request timeout in ms (default: 8000)
      --skip <list>       Comma-separated categories to skip:
                            injection,access,tls,deps,cookies,graphql,exposure,bopla
      --import-session <file>
                          Path to JSON traffic session exported from Chrome extension
      --secondary-auth <token>
                          Auth token for User B (e.g. "Bearer eyJ...") to power
                          dual-context BOLA (WSTG-ATHZ-02 / ASTF-ATHZ-01) and
                          BFLA (WSTG-ATHZ-03 / ASTF-ATHZ-02) verification
      --allow-mutating-methods
                          Opt-in to replay and fuzz POST, PUT, PATCH, DELETE
                          endpoints. Default: only GET, HEAD, OPTIONS are mutated.
                          WARNING: may cause state changes on the target system.
      --dry-run           Print all planned mutated requests to stdout without
                          dispatching any network packets
      --rate-limit <rps>  Maximum requests per second dispatched to the target
                          (default: 15, minimum: 1)
      --openapi <file>    Generate and write OpenAPI 3.0 specification JSON to <file>
      --postman <file>    Generate and write Postman Collection v2.1 JSON to <file>
      --html <file>       Generate and write self-contained executive HTML report to <file>
      --gemini-key <key>  Google Gemini API Key for AI threat modeling & fix synthesis
                          (or set GEMINI_API_KEY env var)
      --vulndb            Enable live Vulnerability Database lookup (OSV.dev / NVD)
                          for detected server technologies
      --auth-test         Enable opt-in auth / brute-force checks
                          (only against targets you own or are authorized to test)
      --creds <file>      Path to a JSON file of {username,password} pairs for
                          --auth-test (default: small built-in list)
      --subdomains        Enable opt-in subdomain enumeration via crt.sh
                          (queries a third-party service with the target domain)
      --json <file>       Write full results as JSON to <file>
      --csv <file>        Write findings as CSV to <file>
      --no-color          Disable colored output
  -h, --help              Show this help

OWASP Standard Coverage:
  Default scan:   OWASP Top 10 Web (2021), OWASP API Security Top 10 (2023)
  With session:   + WSTG v4.2 procedural tests, ASTF systematic API verification
  Dual-context:   Pass --secondary-auth to enable BOLA/BFLA three-probe oracle

Examples:
  boltclone https://example.com --vulndb
  boltclone https://example.com --gemini-key AIzaSy... --html report.html
  boltclone https://example.com --import-session traffic.json --rate-limit 10
  boltclone https://example.com --import-session traffic.json \\
    --secondary-auth "Bearer eyJhbGc..." --allow-mutating-methods --html report.html
  boltclone https://example.com --import-session traffic.json --dry-run
`;

export function parseCliArgs(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      concurrency:             { type: 'string',  short: 'c', default: '8' },
      timeout:                 { type: 'string',  short: 't', default: '8000' },
      skip:                    { type: 'string',  default: '' },
      'import-session':        { type: 'string' },
      'secondary-auth':        { type: 'string' },
      'allow-mutating-methods':{ type: 'boolean', default: false },
      'dry-run':               { type: 'boolean', default: false },
      'rate-limit':            { type: 'string',  default: '15' },
      openapi:                 { type: 'string' },
      postman:                 { type: 'string' },
      html:                    { type: 'string' },
      'gemini-key':            { type: 'string' },
      vulndb:                  { type: 'boolean', default: false },
      'auth-test':             { type: 'boolean', default: false },
      creds:                   { type: 'string' },
      subdomains:              { type: 'boolean', default: false },
      json:                    { type: 'string' },
      csv:                     { type: 'string' },
      'no-color':              { type: 'boolean', default: false },
      help:                    { type: 'boolean', short: 'h', default: false },
    },
  });

  if (values.help || positionals.length === 0) {
    return { help: true, helpText: HELP };
  }

  const skip = new Set(values.skip.split(',').map((s) => s.trim()).filter(Boolean));

  const rateLimit = Math.max(1, parseInt(values['rate-limit'], 10) || 15);

  return {
    help: false,
    target:               positionals[0],
    concurrency:          Math.max(1, parseInt(values.concurrency, 10) || 8),
    timeout:              Math.max(1000, parseInt(values.timeout, 10) || 8000),
    importSession:        values['import-session'] || null,
    secondaryAuth:        values['secondary-auth'] || null,
    allowMutatingMethods: values['allow-mutating-methods'],
    dryRun:               values['dry-run'],
    rateLimit,
    openapiOut:           values.openapi || null,
    postmanOut:           values.postman || null,
    htmlOut:              values.html || null,
    geminiKey:            values['gemini-key'] || process.env.GEMINI_API_KEY || null,
    vulndb:               values.vulndb,
    categories: {
      injection: !skip.has('injection'),
      access:    !skip.has('access'),
      bopla:     !skip.has('bopla'),
      tls:       !skip.has('tls'),
      deps:      !skip.has('deps'),
      cookies:   !skip.has('cookies'),
      graphql:   !skip.has('graphql'),
      exposure:  !skip.has('exposure'),
      auth:      values['auth-test'],
      subdomains: values.subdomains,
    },
    credsFile: values.creds || null,
    jsonOut:   values.json || null,
    csvOut:    values.csv || null,
    color:     !values['no-color'],
  };
}
