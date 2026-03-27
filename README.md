# ⚡ vibeguard

**Security scanner built for AI-generated code. Catches what traditional scanners miss.**

[![npm version](https://img.shields.io/npm/v/vibeguard.svg)](https://www.npmjs.com/package/vibeguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

Vibe coding is fast. But 45% of AI-generated code ships with known vulnerabilities. The Moltbook breach, the pickle exploits, the hardcoded Supabase keys — all caused by patterns that traditional scanners weren't designed to catch.

**vibeguard** scans your codebase for the security mistakes that AI coding tools (Cursor, Claude Code, Copilot, Lovable, Bolt, Replit) introduce most often.

## Quick Start

```bash
npx vibeguard .
```

That's it. No config, no account, no API key.

## What It Catches

| Category | Examples | Severity |
|----------|----------|----------|
| **Hardcoded Secrets** | API keys, DB connection strings, JWTs, private keys inline in code | Critical |
| **Frontend-Exposed Secrets** | Stripe secret keys, service role tokens, DB URLs in client-side code | Critical |
| **Dangerous Functions** | `pickle.loads()`, `eval()` with user input, SQL injection via f-strings/template literals | Critical |
| **Missing Auth** | Express/Flask/FastAPI servers with no authentication middleware | High |
| **Permissive Configs** | `cors(*)`, `debug=True`, Firebase rules `allow: if true`, Supabase without RLS | High |
| **No Rate Limiting** | HTTP servers without rate limiting middleware | High |
| **Dangerous Dependencies** | Compromised packages (event-stream, faker), deprecated libs AI still suggests | Medium |
| **Missing .gitignore** | `.env` files not gitignored, secrets about to be committed | Critical |
| **Docker Misconfigs** | Running as root, copying `.env` into images, exposed DB ports | Medium-High |

## Supported Languages

- **JavaScript / TypeScript** — Express, Fastify, Next.js, React, Vue, Svelte
- **Python** — Flask, FastAPI, Django

## Usage

```bash
# Scan current directory
vibeguard .

# Scan a specific project
vibeguard ./my-app

# Only show high and critical issues
vibeguard . --severity=high

# Output as JSON (for CI/CD)
vibeguard . --json

# Hide fix suggestions
vibeguard . --no-fix

# Ignore specific directories
vibeguard . --ignore=tests,scripts
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  vibeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npx vibeguard . --severity=high
```

vibeguard exits with code 1 if critical or high severity issues are found, making it easy to block deploys.

### Pre-commit Hook

```bash
# .husky/pre-commit
npx vibeguard . --severity=high
```

## Example Output

```
  ⚡ vibeguard v0.1.0
  Security scanner for AI-generated code

  Scanning: /Users/dev/my-vibe-app

  🚨 CRITICAL (3)

    ▸ secret/openai-api-key
      src/api/chat.ts:5
      Hardcoded OpenAI API Key detected. AI tools commonly inline
      credentials — this is a top cause of breaches in vibe-coded apps.
      💡 Fix: Move to environment variable OPENAI_API_KEY.

    ▸ frontend/stripe-secret-key-in-client
      src/components/Checkout.tsx:12
      Stripe Secret Key in Client found in client-side code. This will
      be visible to anyone who opens browser DevTools.
      💡 Fix: Stripe secret keys must NEVER be in frontend code.

    ▸ dangerous/pickle-deserialization
      api/data.py:23
      pickle.load() allows arbitrary code execution when deserializing
      untrusted data.
      💡 Fix: Use json.loads() for data exchange.

  🔴 HIGH (2)

    ▸ defaults/no-rate-limiting
      src/api/server.ts
      No rate limiting detected on HTTP server.
      💡 Fix: Add express-rate-limit.

    ▸ defaults/permissive-cors
      src/api/server.ts:8
      CORS is set to allow all origins (*).
      💡 Fix: Set specific origin: cors({ origin: 'https://yourdomain.com' })

  ─────────────────────────────────────────
  5 issues found: 3 critical, 2 high
  Scanned 24 files in 12ms

  ⚠ Fix critical and high severity issues before deploying!
```

## Why Not Just Use Snyk / Semgrep / SonarQube?

Those tools are great for traditional code. But they weren't designed for AI-generated code patterns:

- **Snyk** focuses on dependency vulnerabilities, not hardcoded secrets or missing middleware
- **Semgrep** requires writing custom rules — vibeguard ships with AI-specific patterns out of the box
- **SonarQube** is enterprise-heavy and takes hours to configure

vibeguard is opinionated, zero-config, and runs in milliseconds. It's built specifically for the patterns that Cursor, Claude Code, Copilot, Lovable, and Bolt introduce.

## How It Works

vibeguard uses pattern matching (regex + structural analysis) against a curated ruleset of AI-specific vulnerability patterns. No AI, no API calls, no data leaves your machine. It runs entirely locally.

The ruleset is based on real-world breaches and academic research:
- The Moltbook breach (Supabase misconfiguration)
- Tenzai's 2025 study (69 vulnerabilities across 5 AI coding tools)
- Escape.tech's scan of 5,600 vibe-coded apps
- Georgia Tech's Vibe Security Radar (tracking AI-generated CVEs)

## Contributing

Contributions welcome. If you've found a vulnerability pattern that AI tools commonly introduce, open a PR to add it to the scanner.

```
src/scanners/
  secrets.js           # Hardcoded API keys, tokens, connection strings
  dangerous-defaults.js # Missing auth, rate limiting, CORS, headers
  dangerous-functions.js # eval, pickle, SQL injection, XSS
  exposed-frontend.js   # Server secrets in client-side code
  permissive-configs.js  # Supabase, Firebase, Docker misconfigs
  dependencies.js       # Compromised/deprecated packages
  gitignore.js          # Missing .gitignore entries
```

## License

MIT
