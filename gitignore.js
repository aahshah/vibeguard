const fs = require('fs');
const path = require('path');

function scanMissingGitignore(dir) {
  const findings = [];
  const gitignorePath = path.join(dir, '.gitignore');

  // Check if .gitignore exists
  if (!fs.existsSync(gitignorePath)) {
    // Only flag if there are files that should be ignored
    const hasEnv = fs.existsSync(path.join(dir, '.env'));
    const hasNodeModules = fs.existsSync(path.join(dir, 'node_modules'));

    if (hasEnv || hasNodeModules) {
      findings.push({
        rule: 'config/no-gitignore',
        severity: 'high',
        file: '.gitignore',
        line: null,
        message: 'No .gitignore file found but .env or node_modules exist. Secrets and dependencies may be committed to git.',
        fix: 'Create a .gitignore file. At minimum add: .env, node_modules/, __pycache__/, .venv/',
      });
    }
    return findings;
  }

  const content = fs.readFileSync(gitignorePath, 'utf-8');
  const lines = content.split('\n').map((l) => l.trim());

  // Check for .env exclusion
  const envPatterns = ['.env', '.env.*', '.env.local', '*.env'];
  const hasEnvIgnore = lines.some((line) => {
    if (line.startsWith('#')) return false;
    return envPatterns.some(
      (p) => line === p || line === `/${p}` || line.includes('.env')
    );
  });

  if (!hasEnvIgnore) {
    // Check if .env files actually exist
    const envFiles = [];
    try {
      const entries = fs.readdirSync(dir);
      for (const e of entries) {
        if (e.startsWith('.env') && e !== '.env.example' && e !== '.env.sample') {
          envFiles.push(e);
        }
      }
    } catch {}

    if (envFiles.length > 0) {
      findings.push({
        rule: 'config/env-not-gitignored',
        severity: 'critical',
        file: '.gitignore',
        line: null,
        message: `.env files found (${envFiles.join(', ')}) but .env is not in .gitignore. Your secrets WILL be committed to git.`,
        fix: 'Add .env to your .gitignore immediately. If already committed, rotate all secrets — git history preserves them.',
      });
    }
  }

  // Check for common AI-generated files that should be ignored
  const shouldIgnore = [
    { pattern: '.env.local', file: '.env.local' },
    { pattern: '.env.production', file: '.env.production' },
  ];

  for (const { pattern, file } of shouldIgnore) {
    if (
      fs.existsSync(path.join(dir, file)) &&
      !lines.some((l) => !l.startsWith('#') && l.includes(pattern))
    ) {
      findings.push({
        rule: 'config/env-variant-not-gitignored',
        severity: 'high',
        file: '.gitignore',
        line: null,
        message: `${file} exists but is not in .gitignore. This file likely contains environment-specific secrets.`,
        fix: `Add ${file} to .gitignore.`,
      });
    }
  }

  return findings;
}

module.exports = { scanMissingGitignore };
