// AI tools commonly use dangerous functions that "work" but are insecure
// These are the exact patterns found in real AI-generated vulnerabilities

const JS_DANGEROUS = [
  {
    regex: /eval\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|data|user)/gi,
    name: 'eval() with user input',
    severity: 'critical',
    message: 'eval() called with user-controlled input. This allows arbitrary code execution.',
    fix: 'Never use eval() with user input. Use JSON.parse() for data or a sandboxed interpreter.',
  },
  {
    regex: /new\s+Function\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|input|data|user)/gi,
    name: 'new Function() with user input',
    severity: 'critical',
    message: 'new Function() with user input is equivalent to eval() — allows code execution.',
    fix: 'Avoid dynamic function creation with user input entirely.',
  },
  {
    regex: /child_process.*exec\s*\(\s*[`'"].*\$\{/gi,
    name: 'Command injection via template literal',
    severity: 'critical',
    message: 'Shell command built with string interpolation. This enables command injection.',
    fix: 'Use execFile() with an array of arguments instead of exec() with string interpolation.',
  },
  {
    regex: /\.(?:query|execute)\s*\(\s*[`'"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\$\{/gi,
    name: 'SQL injection via template literal',
    severity: 'critical',
    message: 'SQL query built with string interpolation. AI tools frequently build queries this way instead of using parameterized queries.',
    fix: 'Use parameterized queries: db.query("SELECT * FROM users WHERE id = $1", [userId])',
  },
  {
    regex: /\.(?:query|execute)\s*\(\s*['"`](?:SELECT|INSERT|UPDATE|DELETE)\s+.*['"]\s*\+/gi,
    name: 'SQL injection via string concatenation',
    severity: 'critical',
    message: 'SQL query built with string concatenation. This is a classic SQL injection vector.',
    fix: 'Use parameterized queries instead of string concatenation.',
  },
  {
    regex: /innerHTML\s*=\s*(?:(?!['"`]<).)*(?:req\.|request\.|params\.|query\.|body\.|input|data|user|\$\{)/gi,
    name: 'XSS via innerHTML',
    severity: 'high',
    message: 'User-controlled data assigned to innerHTML. This enables Cross-Site Scripting (XSS).',
    fix: 'Use textContent instead of innerHTML, or sanitize with DOMPurify.',
  },
  {
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!.*(?:sanitize|purify|DOMPurify))/gi,
    name: 'React dangerouslySetInnerHTML',
    severity: 'high',
    message: 'dangerouslySetInnerHTML used without sanitization. AI tools use this when they can\'t figure out proper rendering.',
    fix: 'Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML.',
  },
  {
    regex: /document\.write\s*\(/g,
    name: 'document.write()',
    severity: 'medium',
    message: 'document.write() can enable XSS and breaks streaming parsers.',
    fix: 'Use DOM manipulation methods (createElement, appendChild) instead.',
  },
];

const PY_DANGEROUS = [
  {
    regex: /pickle\.(?:loads?|Unpickler)\s*\(/g,
    name: 'pickle deserialization',
    severity: 'critical',
    message: 'pickle.load() allows arbitrary code execution when deserializing untrusted data. This is the exact vulnerability found in AI-generated multiplayer game code.',
    fix: 'Use json.loads() for data exchange. Never unpickle data from untrusted sources.',
  },
  {
    regex: /yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/g,
    name: 'Unsafe YAML loading',
    severity: 'high',
    message: 'yaml.load() without SafeLoader allows arbitrary code execution.',
    fix: 'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).',
  },
  {
    regex: /eval\s*\(\s*(?:request\.|input\(|data|user|form)/gi,
    name: 'eval() with user input',
    severity: 'critical',
    message: 'eval() with user-controlled input allows arbitrary Python code execution.',
    fix: 'Use ast.literal_eval() for safe evaluation of data, or avoid eval entirely.',
  },
  {
    regex: /exec\s*\(\s*(?:request\.|input\(|data|user|form)/gi,
    name: 'exec() with user input',
    severity: 'critical',
    message: 'exec() with user input allows arbitrary code execution.',
    fix: 'Remove exec() entirely. Find a safe alternative for the specific operation.',
  },
  {
    regex: /os\.system\s*\(\s*(?:f['"`]|['"`].*(?:\+|%|\.format))/gi,
    name: 'Command injection via os.system',
    severity: 'critical',
    message: 'os.system() with string formatting enables command injection.',
    fix: 'Use subprocess.run() with a list of arguments: subprocess.run(["cmd", arg], shell=False)',
  },
  {
    regex: /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/gi,
    name: 'subprocess with shell=True',
    severity: 'high',
    message: 'subprocess with shell=True enables command injection when combined with user input.',
    fix: 'Use shell=False (default) and pass arguments as a list.',
  },
  {
    regex: /(?:cursor|db|conn)\.execute\s*\(\s*(?:f['"`]|['"`].*(?:%s|%d|\+|\.format|\{))/gi,
    name: 'SQL injection in Python',
    severity: 'critical',
    message: 'SQL query built with string formatting. Use parameterized queries.',
    fix: 'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
  },
  {
    regex: /marshal\.loads?\s*\(/g,
    name: 'marshal deserialization',
    severity: 'high',
    message: 'marshal.loads() can execute arbitrary code. Similar risk to pickle.',
    fix: 'Use json.loads() for data serialization.',
  },
  {
    regex: /shelve\.open\s*\(/g,
    name: 'shelve (uses pickle internally)',
    severity: 'high',
    message: 'shelve uses pickle internally — same arbitrary code execution risk.',
    fix: 'Use a proper database (SQLite, PostgreSQL) or JSON files instead.',
  },
];

function scanDangerousFunctions(ctx) {
  const { content, relativePath, ext } = ctx;
  const findings = [];
  const lines = content.split('\n');

  const isJS = ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'].includes(ext);
  const isPy = ['.py', '.pyw'].includes(ext);

  const patterns = isJS ? JS_DANGEROUS : isPy ? PY_DANGEROUS : [];

  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    let match;

    while ((match = pattern.regex.exec(content)) !== null) {
      const upToMatch = content.substring(0, match.index);
      const lineNum = upToMatch.split('\n').length;
      const line = lines[lineNum - 1] || '';
      const trimmedLine = line.trim();

      // Skip comments
      if (trimmedLine.startsWith('//') || trimmedLine.startsWith('#') || trimmedLine.startsWith('*')) {
        continue;
      }

      findings.push({
        rule: `dangerous/${pattern.name.toLowerCase().replace(/[\s()]+/g, '-')}`,
        severity: pattern.severity,
        file: relativePath,
        line: lineNum,
        message: pattern.message,
        fix: pattern.fix,
        snippet: trimmedLine.substring(0, 120),
      });

      // One match per pattern per file
      break;
    }
  }

  return findings;
}

module.exports = { scanDangerousFunctions };
