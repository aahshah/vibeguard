// AI tools frequently put server-side secrets in frontend/client code
// This scanner detects secrets in files that will be shipped to the browser

function isClientFile(relativePath, ext) {
  const clientPatterns = [
    /^src\/(?:pages|components|views|app|routes)\//i,
    /^(?:pages|components|views|app)\//i,
    /^public\//i,
    /^static\//i,
    /^client\//i,
    /^frontend\//i,
    /^web\//i,
  ];

  // React/Next/Vue/Svelte component files
  if (['.jsx', '.tsx', '.vue', '.svelte'].includes(ext)) return true;

  // HTML files
  if (['.html', '.htm'].includes(ext)) return true;

  return clientPatterns.some((p) => p.test(relativePath));
}

const BACKEND_ONLY_PATTERNS = [
  {
    name: 'Supabase Service Role Key',
    regex: /(?:supabase|SUPABASE)[\s_]*(?:SERVICE[\s_]*ROLE|service[\s_]*role)[\s_]*(?:KEY|key)?\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
    severity: 'critical',
    fix: 'The service_role key bypasses Row Level Security. It must NEVER be in client-side code. Use it only on the server.',
  },
  {
    name: 'Supabase Service Role JWT in Client',
    regex: /(?:supabaseKey|supabase_key|SUPABASE_KEY)\s*[:=]\s*['"`](eyJ[^'"`]{50,})['"`]/gi,
    severity: 'critical',
    check: (match, content) => {
      // Check if the JWT payload contains "role":"service_role"
      try {
        const parts = match.split('.');
        if (parts.length === 3) {
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
          return payload.role === 'service_role';
        }
      } catch {}
      return false;
    },
    fix: 'This appears to be a Supabase service_role JWT. Use the anon key for client-side code instead.',
  },
  {
    name: 'Database URL in Client Code',
    regex: /(?:mongodb|postgres(?:ql)?|mysql|redis):\/\/[^\s'"`,}{)]+/gi,
    severity: 'critical',
    fix: 'Database connection strings must never be in client-side code. Move to server-side only.',
  },
  {
    name: 'Server Secret in Client',
    regex: /(?:SECRET_KEY|JWT_SECRET|API_SECRET|AUTH_SECRET|SESSION_SECRET)\s*[:=]\s*['"`]([^'"`]{4,})['"`]/gi,
    severity: 'critical',
    fix: 'Server secrets in client code are visible to anyone. Move to server-side environment variables.',
  },
  {
    name: 'Stripe Secret Key in Client',
    regex: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
    fix: 'Stripe secret keys must NEVER be in frontend code. Only the publishable key (pk_) belongs client-side.',
  },
  {
    name: 'AWS Credentials in Client',
    regex: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    severity: 'critical',
    fix: 'AWS access keys in frontend code give anyone access to your AWS account. Use presigned URLs or a backend proxy.',
  },
  {
    name: 'OpenAI/Anthropic Key in Client',
    regex: /(?:sk-(?:proj-)?[a-zA-Z0-9_-]{20,}|sk-ant-[a-zA-Z0-9_-]{20,})/g,
    severity: 'critical',
    fix: 'AI API keys in frontend code let anyone use your account. Proxy requests through your backend.',
  },
];

function scanExposedFrontend(ctx) {
  const { content, relativePath, ext } = ctx;
  const findings = [];

  if (!isClientFile(relativePath, ext)) return findings;

  const lines = content.split('\n');

  for (const pattern of BACKEND_ONLY_PATTERNS) {
    pattern.regex.lastIndex = 0;
    let match;

    while ((match = pattern.regex.exec(content)) !== null) {
      // Skip if env var reference
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;
      const line = lines[lineNum - 1] || '';

      if (/process\.env|import\.meta\.env|NEXT_PUBLIC|VITE_|REACT_APP_/i.test(line)) {
        // It's using an env var — but check if it's a server secret env var name
        if (/SERVICE_ROLE|SECRET|PRIVATE/i.test(line) && /NEXT_PUBLIC|VITE_|REACT_APP_/i.test(line)) {
          findings.push({
            rule: `frontend/server-secret-in-public-env`,
            severity: 'critical',
            file: relativePath,
            line: lineNum,
            message: 'Server secret exposed via public environment variable (NEXT_PUBLIC_/VITE_/REACT_APP_). These are embedded in the client bundle at build time.',
            fix: 'Remove the NEXT_PUBLIC_/VITE_/REACT_APP_ prefix. Access this secret only on the server side.',
          });
        }
        continue;
      }

      if (pattern.check && !pattern.check(match[0], content)) continue;

      // Skip examples/placeholders
      if (/example|placeholder|your|xxx|test|dummy|fake|sample/i.test(match[0])) continue;

      findings.push({
        rule: `frontend/${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
        severity: pattern.severity,
        file: relativePath,
        line: lineNum,
        message: `${pattern.name} found in client-side code. This will be visible to anyone who opens browser DevTools.`,
        fix: pattern.fix,
      });

      break;
    }
  }

  return findings;
}

module.exports = { scanExposedFrontend };
