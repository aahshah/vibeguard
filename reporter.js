const SEVERITY_COLORS = {
  critical: '\x1b[41m\x1b[37m',  // white on red bg
  high: '\x1b[31m',               // red
  medium: '\x1b[33m',             // yellow
  low: '\x1b[36m',                // cyan
};

const SEVERITY_ICONS = {
  critical: '🚨',
  high: '🔴',
  medium: '🟡',
  low: '🔵',
};

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

function formatReport(results, opts = {}) {
  const { findings, summary } = results;

  if (findings.length === 0) {
    console.log('  \x1b[32m✓ No security issues found!\x1b[0m');
    console.log(`  ${DIM}Scanned ${summary.filesScanned} files in ${summary.elapsed}ms${RESET}`);
    console.log('');
    return;
  }

  // Group by severity
  const grouped = { critical: [], high: [], medium: [], low: [] };
  for (const f of findings) {
    if (grouped[f.severity]) {
      grouped[f.severity].push(f);
    }
  }

  for (const severity of ['critical', 'high', 'medium', 'low']) {
    const items = grouped[severity];
    if (items.length === 0) continue;

    const color = SEVERITY_COLORS[severity];
    const icon = SEVERITY_ICONS[severity];

    console.log(`  ${color}${BOLD}${icon} ${severity.toUpperCase()} (${items.length})${RESET}`);
    console.log('');

    for (const finding of items) {
      console.log(`  ${color}  ▸ ${finding.rule}${RESET}`);
      console.log(`    ${DIM}${finding.file}${finding.line ? `:${finding.line}` : ''}${RESET}`);
      console.log(`    ${finding.message}`);

      if (opts.showFix !== false && finding.fix) {
        console.log(`    ${DIM}💡 Fix: ${finding.fix}${RESET}`);
      }

      console.log('');
    }
  }

  // Summary bar
  console.log('  ─────────────────────────────────────────');
  const parts = [];
  if (summary.critical > 0) parts.push(`\x1b[31m${summary.critical} critical${RESET}`);
  if (summary.high > 0) parts.push(`\x1b[31m${summary.high} high${RESET}`);
  if (summary.medium > 0) parts.push(`\x1b[33m${summary.medium} medium${RESET}`);
  if (summary.low > 0) parts.push(`\x1b[36m${summary.low} low${RESET}`);

  console.log(`  ${BOLD}${summary.totalFindings} issues${RESET} found: ${parts.join(', ')}`);
  console.log(`  ${DIM}Scanned ${summary.filesScanned} files in ${summary.elapsed}ms${RESET}`);
  console.log('');

  if (summary.critical > 0 || summary.high > 0) {
    console.log(`  \x1b[31m${BOLD}⚠ Fix critical and high severity issues before deploying!${RESET}`);
    console.log('');
  }
}

module.exports = { formatReport };
