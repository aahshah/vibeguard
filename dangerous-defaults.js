// AI-generated code frequently ships without basic security middleware
// These checks catch the most common omissions

function scanDangerousDefaults(ctx) {
  const { content, relativePath, ext, basename } = ctx;
  const findings = [];

  const isJS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext);
  const isPy = ['.py', '.pyw'].includes(ext);
  const isServerFile = /(?:server|app|index|main|api)\.(js|ts|py)$/i.test(basename) ||
    /(?:server|api|backend|routes)/i.test(relativePath);

  if (!isServerFile) return findings;

  // === Express / Node.js checks ===
  if (isJS) {
    const hasExpress = /require\s*\(\s*['"]express['"]\s*\)|from\s+['"]express['"]/i.test(content);
    const hasFastify = /require\s*\(\s*['"]fastify['"]\s*\)|from\s+['"]fastify['"]/i.test(content);
    const hasKoa = /require\s*\(\s*['"]koa['"]\s*\)|from\s+['"]koa['"]/i.test(content);
    const isHttpServer = hasExpress || hasFastify || hasKoa;

    if (isHttpServer) {
      // No rate limiting
      if (!/rate.?limit|express-rate-limit|@fastify\/rate-limit|bottleneck|express-slow-down/i.test(content)) {
        findings.push({
          rule: 'defaults/no-rate-limiting',
          severity: 'high',
          file: relativePath,
          line: null,
          message: 'No rate limiting detected on HTTP server. AI-generated servers almost never include rate limiting, making them vulnerable to brute force and DDoS.',
          fix: 'Add express-rate-limit: app.use(rateLimit({ windowMs: 15*60*1000, max: 100 }))',
        });
      }

      // No helmet / security headers
      if (!/helmet|security.?headers|x-content-type|x-frame-options|strict-transport/i.test(content)) {
        findings.push({
          rule: 'defaults/no-security-headers',
          severity: 'medium',
          file: relativePath,
          line: null,
          message: 'No security headers middleware (helmet) detected. Missing headers like X-Frame-Options, CSP, HSTS.',
          fix: 'Add helmet: app.use(helmet()). Install with npm install helmet.',
        });
      }

      // Permissive CORS
      const corsMatch = content.match(/cors\(\s*\{?\s*origin\s*:\s*['"`]\*['"`]|cors\(\s*\)/);
      if (corsMatch) {
        const lineNum = content.substring(0, corsMatch.index).split('\n').length;
        findings.push({
          rule: 'defaults/permissive-cors',
          severity: 'high',
          file: relativePath,
          line: lineNum,
          message: 'CORS is set to allow all origins (*). AI tools default to permissive CORS. Restrict to your actual frontend domain.',
          fix: "Set specific origin: cors({ origin: 'https://yourdomain.com' })",
        });
      }

      // No input validation
      if (!/zod|joi|yup|express-validator|class-validator|ajv|superstruct/i.test(content)) {
        // Check if there are POST/PUT route handlers
        if (/\.(post|put|patch)\s*\(/i.test(content)) {
          findings.push({
            rule: 'defaults/no-input-validation',
            severity: 'medium',
            file: relativePath,
            line: null,
            message: 'No input validation library detected but POST/PUT handlers exist. AI-generated APIs rarely validate input, enabling injection attacks.',
            fix: 'Add zod or joi for request body validation on all mutation endpoints.',
          });
        }
      }

      // No auth middleware
      if (/\.(get|post|put|patch|delete)\s*\(/i.test(content)) {
        if (!/auth|jwt|passport|clerk|supabase.*auth|next-auth|lucia|session|bearer/i.test(content)) {
          findings.push({
            rule: 'defaults/no-auth-middleware',
            severity: 'high',
            file: relativePath,
            line: null,
            message: 'Route handlers detected but no authentication middleware found. AI tools frequently skip auth, leaving all endpoints publicly accessible.',
            fix: 'Add authentication middleware to protected routes. Use passport, clerk, or JWT verification.',
          });
        }
      }
    }
  }

  // === Python / Flask / FastAPI / Django checks ===
  if (isPy) {
    const hasFlask = /from\s+flask\s+import|import\s+flask/i.test(content);
    const hasFastAPI = /from\s+fastapi\s+import|import\s+fastapi/i.test(content);
    const hasDjango = /from\s+django/i.test(content);
    const isPyServer = hasFlask || hasFastAPI || hasDjango;

    if (isPyServer) {
      // Debug mode in production
      const debugMatch = content.match(/debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True/i);
      if (debugMatch) {
        const lineNum = content.substring(0, debugMatch.index).split('\n').length;
        findings.push({
          rule: 'defaults/debug-mode-enabled',
          severity: 'critical',
          file: relativePath,
          line: lineNum,
          message: 'Debug mode enabled. AI tools always set debug=True. This exposes stack traces, allows code execution (Flask debugger), and leaks secrets in production.',
          fix: 'Set debug=False or use environment variable: debug=os.environ.get("DEBUG", "False") == "True"',
        });
      }

      // Flask secret key hardcoded
      const secretKeyMatch = content.match(/(?:secret_key|SECRET_KEY)\s*=\s*['"`]([^'"`]{1,100})['"`]/i);
      if (secretKeyMatch) {
        const lineNum = content.substring(0, secretKeyMatch.index).split('\n').length;
        const key = secretKeyMatch[1];
        if (!/os\.environ|os\.getenv|environ/i.test(content.split('\n')[lineNum - 1] || '')) {
          findings.push({
            rule: 'defaults/hardcoded-secret-key',
            severity: 'critical',
            file: relativePath,
            line: lineNum,
            message: 'Hardcoded SECRET_KEY. AI tools generate a static secret key. This compromises session security and CSRF protection.',
            fix: "Use os.environ.get('SECRET_KEY') with a randomly generated value.",
          });
        }
      }

      // No CORS restriction (FastAPI)
      if (hasFastAPI) {
        const corsAll = content.match(/allow_origins\s*=\s*\[\s*['"`]\*['"`]\s*\]/);
        if (corsAll) {
          const lineNum = content.substring(0, corsAll.index).split('\n').length;
          findings.push({
            rule: 'defaults/permissive-cors',
            severity: 'high',
            file: relativePath,
            line: lineNum,
            message: 'FastAPI CORS allows all origins. Restrict to your frontend domain.',
            fix: "Set allow_origins=['https://yourdomain.com']",
          });
        }
      }

      // No rate limiting
      if (!/slowapi|flask.?limiter|ratelimit|throttle/i.test(content)) {
        if (/@app\.(?:route|get|post|put|delete)|@router\./i.test(content)) {
          findings.push({
            rule: 'defaults/no-rate-limiting',
            severity: 'high',
            file: relativePath,
            line: null,
            message: 'No rate limiting on Python server. Add slowapi (FastAPI) or flask-limiter (Flask).',
            fix: 'Install and configure rate limiting: pip install slowapi',
          });
        }
      }
    }
  }

  return findings;
}

module.exports = { scanDangerousDefaults };
