// Patterns specifically tuned for AI-generated code leaks
// AI tools commonly inline credentials instead of using env vars

const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key',
    regex: /(?:AKIA|ASIA)[0-9A-Z]{16}/g,
    severity: 'critical',
    fix: 'Move to environment variable AWS_ACCESS_KEY_ID and use aws-sdk credential provider.',
  },
  {
    name: 'AWS Secret Key',
    regex: /(?:aws)?(?:_?secret)?(?:_?access)?(?:_?key)\s*[:=]\s*['"`]([A-Za-z0-9/+=]{40})['"`]/gi,
    severity: 'critical',
    fix: 'Move to environment variable AWS_SECRET_ACCESS_KEY. Never hardcode AWS secrets.',
  },
  {
    name: 'Stripe Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
    fix: 'Move to environment variable STRIPE_SECRET_KEY. This key can charge real cards.',
  },
  {
    name: 'Stripe Publishable Key in Backend',
    regex: /pk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'medium',
    backendOnly: true,
    fix: 'Publishable keys are safe in frontend, but check this isn\'t a backend file leaking keys.',
  },
  {
    name: 'OpenAI API Key',
    regex: /sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/g,
    severity: 'critical',
    fix: 'Move to environment variable OPENAI_API_KEY.',
  },
  {
    name: 'OpenAI API Key (new format)',
    regex: /sk-(?:proj-)?[a-zA-Z0-9_-]{40,}/g,
    severity: 'critical',
    fix: 'Move to environment variable OPENAI_API_KEY.',
  },
  {
    name: 'Anthropic API Key',
    regex: /sk-ant-[a-zA-Z0-9_-]{40,}/g,
    severity: 'critical',
    fix: 'Move to environment variable ANTHROPIC_API_KEY.',
  },
  {
    name: 'Supabase Service Role Key',
    regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    severity: 'critical',
    jwtCheck: true,
    fix: 'Supabase service_role key bypasses RLS. Never expose in client code. Use SUPABASE_SERVICE_ROLE_KEY env var server-side only.',
  },
  {
    name: 'Generic JWT Token',
    regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    severity: 'high',
    fix: 'Hardcoded JWTs should be fetched at runtime, not embedded in source code.',
  },
  {
    name: 'GitHub Token',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/g,
    severity: 'critical',
    fix: 'Move to environment variable GITHUB_TOKEN.',
  },
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'high',
    fix: 'Move to environment variable and restrict the key in Google Cloud Console.',
  },
  {
    name: 'Slack Token',
    regex: /xox[bpors]-[0-9]{10,}-[0-9a-zA-Z]{10,}/g,
    severity: 'critical',
    fix: 'Move to environment variable SLACK_TOKEN.',
  },
  {
    name: 'Discord Bot Token',
    regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
    severity: 'critical',
    fix: 'Move to environment variable DISCORD_BOT_TOKEN.',
  },
  {
    name: 'SendGrid API Key',
    regex: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'critical',
    fix: 'Move to environment variable SENDGRID_API_KEY.',
  },
  {
    name: 'Twilio Auth Token',
    regex: /(?:twilio)?(?:_?auth)?(?:_?token)\s*[:=]\s*['"`]([a-f0-9]{32})['"`]/gi,
    severity: 'critical',
    fix: 'Move to environment variable TWILIO_AUTH_TOKEN.',
  },
  {
    name: 'Database Connection String',
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\/[^\s'"`,}{)]+/gi,
    severity: 'critical',
    fix: 'Move connection string to DATABASE_URL environment variable. Never hardcode credentials.',
  },
  {
    name: 'Hardcoded Password Assignment',
    regex: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"`](?!.*\b(?:process\.env|os\.environ|getenv)\b)[^'"` \n]{4,}['"`]/gi,
    severity: 'high',
    fix: 'Use environment variables for passwords. AI tools commonly inline these for convenience.',
  },
  {
    name: 'Private Key Block',
    regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
    severity: 'critical',
    fix: 'Never commit private keys. Store in a secrets manager or environment variable.',
  },
  {
    name: 'Firebase Config with API Key',
    regex: /(?:firebase|firebaseConfig)\s*(?:=|:)\s*\{[^}]*apiKey\s*:\s*['"`][^'"`]+['"`]/gs,
    severity: 'medium',
    fix: 'Firebase config with API key is safe in frontend, but ensure Firestore/RTDB rules are locked down.',
  },
];

function scanSecrets(ctx) {
  const { content, relativePath, ext } = ctx;
  const findings = [];

  // Skip .env files for secret scanning — those are supposed to have secrets
  if (ctx.basename.startsWith('.env')) return findings;
  // Skip lock files
  if (ctx.basename === 'package-lock.json' || ctx.basename === 'yarn.lock') return findings;

  const isBackend = /(?:server|api|backend|routes|controllers|middleware|lib|utils)/i.test(relativePath);
  const lines = content.split('\n');

  for (const pattern of SECRET_PATTERNS) {
    // Reset regex
    pattern.regex.lastIndex = 0;

    let match;
    while ((match = pattern.regex.exec(content)) !== null) {
      // Find line number
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;
      const line = lines[lineNum - 1] || '';

      // Skip if it's in a comment
      const trimmedLine = line.trim();
      if (trimmedLine.startsWith('//') || trimmedLine.startsWith('#') || trimmedLine.startsWith('*')) {
        // Still flag it — commented out secrets are still in git history
      }

      // Skip if it's referencing an env var
      if (/process\.env|os\.environ|os\.getenv|ENV\[|getenv/i.test(line)) continue;

      // Skip example/placeholder values
      const matchStr = match[0].toLowerCase();
      if (/example|placeholder|your[_-]?key|xxx|test|dummy|fake|sample/i.test(matchStr)) continue;
      if (/example|placeholder|your[_-]?key|xxx|test|dummy|fake|sample/i.test(line)) continue;

      findings.push({
        rule: `secret/${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
        severity: pattern.severity,
        file: relativePath,
        line: lineNum,
        message: `Hardcoded ${pattern.name} detected. AI tools commonly inline credentials — this is a top cause of breaches in vibe-coded apps.`,
        fix: pattern.fix,
        snippet: line.trim().substring(0, 120),
      });

      // Only report first match per pattern per file
      break;
    }
  }

  return findings;
}

module.exports = { scanSecrets };
