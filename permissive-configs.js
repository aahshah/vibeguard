// AI tools frequently scaffold permissive database and infra configs
// These are the configs that caused the Moltbook breach

function scanPermissiveConfigs(ctx) {
  const { content, relativePath, ext, basename } = ctx;
  const findings = [];

  // === Supabase checks ===

  // Detect Supabase client initialized without RLS awareness
  if (['.js', '.ts', '.jsx', '.tsx'].includes(ext)) {
    // Using supabase with service_role key in client code
    const supabaseInit = content.match(
      /createClient\s*\(\s*[^,]+,\s*(?:process\.env\.)?(?:NEXT_PUBLIC_)?SUPABASE_(?:SERVICE_ROLE|ANON)_KEY/i
    );

    // Check for direct table access without auth checks
    const directTableAccess = content.match(
      /supabase\s*\.from\s*\(\s*['"`]\w+['"`]\s*\)\s*\.(?:select|insert|update|delete|upsert)\s*\(/gi
    );

    if (directTableAccess && directTableAccess.length > 3) {
      // If lots of direct table access without any auth/RLS mentions
      if (!/rls|row.?level|policy|policies|auth\.uid|auth\.role/i.test(content)) {
        findings.push({
          rule: 'config/supabase-no-rls-awareness',
          severity: 'high',
          file: relativePath,
          line: null,
          message: 'Multiple direct Supabase table operations found with no mention of RLS policies. The Moltbook breach happened because RLS was not configured — data was publicly readable and writable.',
          fix: 'Enable RLS on all tables in Supabase dashboard and create appropriate policies. Test with anon key to verify restrictions.',
        });
      }
    }
  }

  // === Firebase rules check ===
  if (
    basename === 'firestore.rules' ||
    basename === 'database.rules.json' ||
    basename === 'storage.rules' ||
    basename === 'firebase.json'
  ) {
    // Check for allow read, write: if true
    const permissiveRegex = /allow\s+(?:read|write|get|list|create|update|delete)\s*(?:,\s*(?:read|write|get|list|create|update|delete)\s*)*\s*:\s*if\s+true/gi;
    const permissiveRule = permissiveRegex.exec(content);
    if (permissiveRule) {
      const lineNum = content.substring(0, permissiveRule.index).split('\n').length;
      findings.push({
        rule: 'config/firebase-permissive-rules',
        severity: 'critical',
        file: relativePath,
        line: lineNum,
        message: 'Firebase rules allow unrestricted access (if true). Anyone can read and write your database.',
        fix: 'Restrict rules to authenticated users: allow read, write: if request.auth != null; Add granular per-collection rules.',
      });
    }

    // Check for wide-open rules
    if (/['"]\s*\.read['"]\s*:\s*true|['"]\s*\.write['"]\s*:\s*true/i.test(content)) {
      findings.push({
        rule: 'config/firebase-rtdb-open',
        severity: 'critical',
        file: relativePath,
        line: null,
        message: 'Firebase Realtime Database rules set to public read/write.',
        fix: 'Set ".read" and ".write" to "auth != null" at minimum.',
      });
    }
  }

  // === Docker checks ===
  if (basename === 'Dockerfile') {
    // Running as root
    if (!/USER\s+(?!root)/i.test(content)) {
      findings.push({
        rule: 'config/docker-running-as-root',
        severity: 'medium',
        file: relativePath,
        line: null,
        message: 'Dockerfile does not set a non-root USER. Container will run as root, increasing blast radius of any exploit.',
        fix: 'Add USER directive: RUN addgroup -S app && adduser -S app -G app\\nUSER app',
      });
    }

    // Copying .env into image
    if (/COPY\s+.*\.env/i.test(content)) {
      const match = content.match(/COPY\s+.*\.env/i);
      const lineNum = content.substring(0, match.index).split('\n').length;
      findings.push({
        rule: 'config/docker-copies-env',
        severity: 'critical',
        file: relativePath,
        line: lineNum,
        message: '.env file copied into Docker image. Secrets will be baked into the image layer and visible to anyone with access.',
        fix: 'Use Docker secrets, --env-file at runtime, or environment variables in docker-compose.yml instead.',
      });
    }

    // Using latest tag
    if (/FROM\s+\w+:latest/i.test(content)) {
      findings.push({
        rule: 'config/docker-latest-tag',
        severity: 'low',
        file: relativePath,
        line: null,
        message: 'Using :latest tag in Dockerfile. Builds are not reproducible and may introduce unexpected changes.',
        fix: 'Pin to a specific version: FROM node:20-alpine instead of FROM node:latest',
      });
    }
  }

  // === docker-compose checks ===
  if (basename === 'docker-compose.yml' || basename === 'docker-compose.yaml') {
    // Exposed database ports
    const dbPortMatch = content.match(
      /ports:\s*\n\s*-\s*['"]?(?:0\.0\.0\.0:)?(\d+):(?:5432|3306|27017|6379|9200)/m
    );
    if (dbPortMatch) {
      const lineNum = content.substring(0, dbPortMatch.index).split('\n').length;
      findings.push({
        rule: 'config/docker-exposed-db-port',
        severity: 'high',
        file: relativePath,
        line: lineNum,
        message: 'Database port exposed to host. AI tools always expose DB ports for convenience. In production, databases should only be accessible within the Docker network.',
        fix: 'Remove the ports mapping for databases, or bind to localhost: "127.0.0.1:5432:5432"',
      });
    }

    // Hardcoded passwords in compose
    const composePassMatch = content.match(
      /(?:POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*['"]?([^'"\s\n]+)/i
    );
    if (composePassMatch) {
      const lineNum = content.substring(0, composePassMatch.index).split('\n').length;
      findings.push({
        rule: 'config/docker-hardcoded-password',
        severity: 'high',
        file: relativePath,
        line: lineNum,
        message: 'Database password hardcoded in docker-compose. AI tools always set simple passwords like "password" or "postgres".',
        fix: 'Use environment variables: POSTGRES_PASSWORD=${DB_PASSWORD} and set in .env file.',
      });
    }
  }

  return findings;
}

module.exports = { scanPermissiveConfigs };
