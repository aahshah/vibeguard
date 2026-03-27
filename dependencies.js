const fs = require('fs');
const path = require('path');

// Known vulnerable or dangerous packages that AI tools commonly suggest
const DANGEROUS_PACKAGES_JS = {
  // Packages with known security issues AI still recommends
  'event-stream': { severity: 'critical', reason: 'Compromised package — contained malicious code targeting cryptocurrency wallets.' },
  'flatmap-stream': { severity: 'critical', reason: 'Malicious package used in the event-stream attack.' },
  'ua-parser-js': { severity: 'high', reason: 'Was compromised in 2021. Ensure you\'re on a patched version.' },
  'colors': { severity: 'medium', reason: 'Maintainer intentionally corrupted v1.4.1+. Pin to 1.4.0.' },
  'faker': { severity: 'medium', reason: 'Maintainer intentionally corrupted v6.6.6+. Use @faker-js/faker instead.' },
  'request': { severity: 'low', reason: 'Deprecated since 2020. AI tools still suggest it. Use node-fetch, axios, or undici.' },
  'node-uuid': { severity: 'low', reason: 'Renamed to uuid years ago. AI tools reference the old name.' },
  'crypto': { severity: 'low', reason: 'Node.js built-in. If listed as an npm dependency, it\'s a potentially malicious package.' },
  'http': { severity: 'medium', reason: 'Node.js built-in. npm package is suspicious — possible typosquat.' },
  'fs': { severity: 'medium', reason: 'Node.js built-in. npm package is suspicious — possible typosquat.' },
};

const DANGEROUS_PACKAGES_PY = {
  'python-dotenv': { severity: 'low', reason: 'Safe package but AI often hardcodes secrets instead of using it. If present, good sign.' },
  'pyyaml': { severity: 'medium', reason: 'Use yaml.safe_load() not yaml.load(). AI tools always use the unsafe version.' },
  'django': { severity: 'low', reason: 'Ensure DEBUG=False in production. AI always sets DEBUG=True.' },
  'flask': { severity: 'low', reason: 'Ensure debug mode is off in production.' },
  'pickle5': { severity: 'high', reason: 'Pickle is unsafe for untrusted data. AI uses pickle for data exchange instead of JSON.' },
  'jinja2': { severity: 'medium', reason: 'If using |safe filter with user input, XSS is likely. Check templates.' },
};

async function scanDependencies(dir) {
  const findings = [];

  // Check package.json
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };

      for (const [name, version] of Object.entries(allDeps)) {
        if (DANGEROUS_PACKAGES_JS[name]) {
          const info = DANGEROUS_PACKAGES_JS[name];
          findings.push({
            rule: `deps/dangerous-package-${name}`,
            severity: info.severity,
            file: 'package.json',
            line: null,
            message: `Package "${name}" flagged: ${info.reason}`,
            fix: `Review whether "${name}" is necessary and check for alternatives.`,
          });
        }

        // Check for wildcard versions
        if (version === '*' || version === 'latest') {
          findings.push({
            rule: `deps/unpinned-version`,
            severity: 'medium',
            file: 'package.json',
            line: null,
            message: `Package "${name}" has unpinned version "${version}". AI tools often use * or latest, which can pull in breaking changes or compromised versions.`,
            fix: `Pin to a specific version: npm install ${name}@latest --save-exact`,
          });
        }
      }

      // Check for missing security-related dependencies in a server project
      if (allDeps['express'] || allDeps['fastify'] || allDeps['koa']) {
        const missingSecurity = [];
        if (!allDeps['helmet'] && !allDeps['fastify-helmet']) missingSecurity.push('helmet (security headers)');
        if (!allDeps['express-rate-limit'] && !allDeps['@fastify/rate-limit'] && !allDeps['koa-ratelimit']) {
          missingSecurity.push('rate limiting');
        }

        if (missingSecurity.length > 0) {
          findings.push({
            rule: 'deps/missing-security-packages',
            severity: 'medium',
            file: 'package.json',
            line: null,
            message: `Server project missing security packages: ${missingSecurity.join(', ')}. AI-generated servers rarely include security middleware.`,
            fix: `Install missing packages: npm install ${missingSecurity.includes('helmet') ? 'helmet ' : ''}${missingSecurity.includes('rate limiting') ? 'express-rate-limit' : ''}`,
          });
        }
      }

    } catch (e) {
      // Invalid JSON — could be an issue itself
    }
  }

  // Check requirements.txt
  const reqPath = path.join(dir, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const content = fs.readFileSync(reqPath, 'utf-8');
      const lines = content.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const match = trimmed.match(/^([a-zA-Z0-9_-]+)/);
        if (!match) continue;

        const pkgName = match[1].toLowerCase();

        if (DANGEROUS_PACKAGES_PY[pkgName]) {
          const info = DANGEROUS_PACKAGES_PY[pkgName];
          findings.push({
            rule: `deps/dangerous-package-${pkgName}`,
            severity: info.severity,
            file: 'requirements.txt',
            line: null,
            message: `Package "${pkgName}" flagged: ${info.reason}`,
            fix: `Review usage of "${pkgName}" for security implications.`,
          });
        }

        // Unpinned Python packages
        if (!trimmed.includes('==') && !trimmed.includes('>=') && !trimmed.includes('~=')) {
          findings.push({
            rule: 'deps/unpinned-python-package',
            severity: 'low',
            file: 'requirements.txt',
            line: null,
            message: `Package "${pkgName}" has no version pin. Could install a compromised future version.`,
            fix: `Pin version: ${pkgName}==<version>. Use pip freeze to get current versions.`,
          });
        }
      }

    } catch (e) {
      // Can't read file
    }
  }

  // Check pyproject.toml
  const pyprojectPath = path.join(dir, 'pyproject.toml');
  if (fs.existsSync(pyprojectPath)) {
    try {
      const content = fs.readFileSync(pyprojectPath, 'utf-8');

      for (const [pkgName, info] of Object.entries(DANGEROUS_PACKAGES_PY)) {
        if (content.includes(pkgName)) {
          findings.push({
            rule: `deps/dangerous-package-${pkgName}`,
            severity: info.severity,
            file: 'pyproject.toml',
            line: null,
            message: `Package "${pkgName}" flagged: ${info.reason}`,
            fix: `Review usage of "${pkgName}" for security implications.`,
          });
        }
      }
    } catch (e) {}
  }

  return findings;
}

module.exports = { scanDependencies };
