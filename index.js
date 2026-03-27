const fs = require('fs');
const path = require('path');

const { scanSecrets } = require('./scanners/secrets');
const { scanDangerousDefaults } = require('./scanners/dangerous-defaults');
const { scanExposedFrontend } = require('./scanners/exposed-frontend');
const { scanMissingGitignore } = require('./scanners/gitignore');
const { scanDangerousFunctions } = require('./scanners/dangerous-functions');
const { scanPermissiveConfigs } = require('./scanners/permissive-configs');
const { scanDependencies } = require('./scanners/dependencies');

const IGNORE_DIRS = new Set([
  'node_modules', '.git', '.next', '__pycache__', '.venv', 'venv',
  'env', '.env', 'dist', 'build', '.cache', 'coverage', '.nyc_output',
  '.pytest_cache', 'egg-info', '.tox', '.mypy_cache',
]);

const SCAN_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.pyw',
  '.json', '.yaml', '.yml', '.toml',
  '.env', '.env.local', '.env.production', '.env.development',
  '.html', '.htm', '.vue', '.svelte',
]);

function shouldScanFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const basename = path.basename(filePath);

  // Always scan dotenv files
  if (basename.startsWith('.env')) return true;
  // Always scan config files
  if (['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
       'firestore.rules', 'database.rules.json', 'storage.rules',
       'firebase.json'].includes(basename)) return true;

  return SCAN_EXTENSIONS.has(ext);
}

function walkDir(dir, ignore = []) {
  const files = [];

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      const relativePath = path.relative(dir, fullPath);

      if (entry.isDirectory()) {
        if (IGNORE_DIRS.has(entry.name)) continue;
        if (ignore.some((pattern) => relativePath.includes(pattern))) continue;
        walk(fullPath);
      } else if (entry.isFile()) {
        if (shouldScanFile(fullPath)) {
          files.push(fullPath);
        }
      }
    }
  }

  walk(dir);
  return files;
}

async function scanDirectory(dir, opts = {}) {
  const startTime = Date.now();

  if (!fs.existsSync(dir)) {
    throw new Error(`Directory not found: ${dir}`);
  }

  const files = walkDir(dir, opts.ignore || []);
  const findings = [];
  let filesScanned = 0;

  // Per-file scanners
  for (const filePath of files) {
    let content;
    try {
      const stat = fs.statSync(filePath);
      // Skip files > 1MB
      if (stat.size > 1_000_000) continue;
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    filesScanned++;
    const relativePath = path.relative(dir, filePath);
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);

    const ctx = { filePath, relativePath, content, ext, basename };

    findings.push(...scanSecrets(ctx));
    findings.push(...scanDangerousDefaults(ctx));
    findings.push(...scanExposedFrontend(ctx));
    findings.push(...scanDangerousFunctions(ctx));
    findings.push(...scanPermissiveConfigs(ctx));
  }

  // Project-level scanners
  findings.push(...scanMissingGitignore(dir));
  findings.push(...(await scanDependencies(dir)));

  // Filter by severity
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const minSeverity = severityOrder[opts.severity || 'low'] || 1;
  const filtered = findings.filter(
    (f) => (severityOrder[f.severity] || 0) >= minSeverity
  );

  const elapsed = Date.now() - startTime;

  return {
    findings: filtered,
    summary: {
      filesScanned,
      totalFindings: filtered.length,
      critical: filtered.filter((f) => f.severity === 'critical').length,
      high: filtered.filter((f) => f.severity === 'high').length,
      medium: filtered.filter((f) => f.severity === 'medium').length,
      low: filtered.filter((f) => f.severity === 'low').length,
      elapsed,
    },
  };
}

module.exports = { scanDirectory };
