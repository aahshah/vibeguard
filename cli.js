#!/usr/bin/env node

const path = require('path');
const { scan } = require('./scanner');
const { formatFindings, formatJSON } = require('./formatter');
const { SEVERITY } = require('./rules');

const VERSION = '0.1.0';

// Parse args
const args = process.argv.slice(2);
const flags = {
  json: args.includes('--json'),
  help: args.includes('--help') || args.includes('-h'),
  version: args.includes('--version') || args.includes('-v'),
  severity: 'LOW',
};

const sevIdx = args.indexOf('--severity');
if (sevIdx !== -1 && args[sevIdx + 1]) {
  flags.severity = args[sevIdx + 1].toUpperCase();
}

const targetDir = args.find(a => !a.startsWith('-')) || '.';

if (flags.version) {
  console.log(`vibeguard v${VERSION}`);
  process.exit(0);
}

if (flags.help) {
  console.log(`
  \x1b[1m\x1b[36mvibeguard\x1b[0m — Security scanner for AI-generated code

  \x1b[1mUSAGE\x1b[0m
    vibeguard [directory] [options]

  \x1b[1mARGUMENTS\x1b[0m
    directory          Path to scan (default: current directory)

  \x1b[1mOPTIONS\x1b[0m
    --json             Output results as JSON
    --severity LEVEL   Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)
    -v, --version      Show version
    -h, --help         Show this help

  \x1b[1mEXAMPLES\x1b[0m
    vibeguard .                        Scan current directory
    vibeguard ./my-app                 Scan specific directory
    vibeguard . --json                 JSON output (for CI/CD)
    vibeguard . --severity HIGH        Only HIGH and CRITICAL
    npx vibeguard .                    Run without installing

  \x1b[1mWHAT IT CATCHES\x1b[0m
    Hardcoded secrets, SQL injection, eval/pickle, missing auth,
    CORS wildcards, Supabase/Firebase misconfigs, exposed frontend
    keys, missing rate limiting, and more AI-generated code patterns.
`);
  process.exit(0);
}

try {
  const resolvedDir = path.resolve(targetDir);
  const { findings, stats } = scan(resolvedDir);

  const severityOrder = [SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.MEDIUM, SEVERITY.LOW];
  const minSeverityIdx = severityOrder.indexOf(flags.severity);
  const filteredFindings = minSeverityIdx >= 0
    ? findings.filter(f => severityOrder.indexOf(f.severity) <= minSeverityIdx)
    : findings;

  if (flags.json) {
    console.log(formatJSON(filteredFindings, stats));
  } else {
    console.log(formatFindings(filteredFindings, stats, resolvedDir));
  }

  const hasCritical = filteredFindings.some(f => f.severity === SEVERITY.CRITICAL || f.severity === SEVERITY.HIGH);
  process.exit(hasCritical ? 1 : 0);
} catch (err) {
  console.error(`\x1b[31mError: ${err.message}\x1b[0m`);
  process.exit(2);
}
