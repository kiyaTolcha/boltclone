#!/usr/bin/env node
import { parseCliArgs } from '../src/args.js';
import { runScan } from '../src/scan.js';
import { printConsoleReport, writeJsonReport, writeCsvReport } from '../src/report.js';

async function main() {
  const opts = parseCliArgs(process.argv.slice(2));

  if (opts.help) {
    console.log(opts.helpText);
    return;
  }

  if (opts.categories.auth) {
    console.error('\x1b[33mWARNING: --auth-test is enabled. Only run this against targets you own or are explicitly authorized to test.\x1b[0m\n');
  }

  const onProgress = (msg) => console.error(`\x1b[2m${msg}\x1b[0m`);

  let result;
  try {
    result = await runScan({
      target: opts.target,
      concurrency: opts.concurrency,
      timeout: opts.timeout,
      categories: opts.categories,
      credsFile: opts.credsFile,
      onProgress
    });
  } catch (err) {
    console.error(`Scan failed: ${err.message || err}`);
    process.exitCode = 1;
    return;
  }

  printConsoleReport(result.findings, result.meta, opts.color);

  if (opts.jsonOut) {
    await writeJsonReport(opts.jsonOut, result.findings, result.meta);
    console.error(`\nJSON report written to ${opts.jsonOut}`);
  }
  if (opts.csvOut) {
    await writeCsvReport(opts.csvOut, result.findings);
    console.error(`CSV report written to ${opts.csvOut}`);
  }

  const hasHigh = result.findings.some((f) => f.severity === 'high');
  process.exitCode = hasHigh ? 2 : 0;
}

main();
