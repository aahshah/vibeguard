const fs = require('fs');
const path = require('path');
const { scanDirectory } = require('../src/index');

const FIXTURES_DIR = path.join(__dirname, 'fixtures');

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    console.log(`  \x1b[32m✓\x1b[0m ${msg}`);
    passed++;
  } else {
    console.log(`  \x1b[31m✗\x1b[0m ${msg}`);
    failed++;
  }
}

function findFinding(findings, ruleSubstring) {
  return findings.find((f) => f.rule.includes(ruleSubstring));
}

async function runTests() {
  console.log('\n\x1b[1mvibeguard test suite\x1b[0m\n');

  // === Test 1: Secrets Scanner ===
  console.log('\x1b[1mSecrets Scanner\x1b[0m');

  // Create fixture with secrets
  const secretsDir = path.join(FIXTURES_DIR, 'secrets-test');
  fs.mkdirSync(secretsDir, { recursive: true });
  fs.writeFileSync(
    path.join(secretsDir, 'server.js'),
    `
const OPENAI_KEY = 'sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234';
const DB = 'postgresql://admin:pass@host:5432/db';
const stripe = 'sk_live_51ABC123DEF456GHI789JKL012MN';
const github = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef123456';
`
  );

  let result = await scanDirectory(secretsDir);
  assert(findFinding(result.findings, 'secret/openai'), 'Detects OpenAI API key');
  assert(findFinding(result.findings, 'secret/database-connection'), 'Detects database connection string');
  assert(findFinding(result.findings, 'secret/stripe-secret'), 'Detects Stripe secret key');
  assert(findFinding(result.findings, 'secret/github-token'), 'Detects GitHub token');

  // Test: env var references should NOT be flagged
  fs.writeFileSync(
    path.join(secretsDir, 'safe.js'),
    `
const key = process.env.OPENAI_API_KEY;
const db = process.env.DATABASE_URL;
`
  );
  result = await scanDirectory(secretsDir);
  const safeFindings = result.findings.filter((f) => f.file === 'safe.js');
  assert(safeFindings.length === 0, 'Does NOT flag env var references');

  // === Test 2: Dangerous Functions ===
  console.log('\n\x1b[1mDangerous Functions Scanner\x1b[0m');

  const dangerousDir = path.join(FIXTURES_DIR, 'dangerous-test');
  fs.mkdirSync(dangerousDir, { recursive: true });

  fs.writeFileSync(
    path.join(dangerousDir, 'bad.js'),
    `
const result = eval(req.body.code);
db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
element.innerHTML = req.body.html;
`
  );
  fs.writeFileSync(
    path.join(dangerousDir, 'bad.py'),
    `
import pickle
data = pickle.loads(request.get_data())
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
result = eval(request.json['code'])
`
  );

  result = await scanDirectory(dangerousDir);
  assert(findFinding(result.findings, 'dangerous/eval'), 'Detects eval() with user input (JS)');
  assert(findFinding(result.findings, 'dangerous/sql-injection'), 'Detects SQL injection via template literal (JS)');
  assert(findFinding(result.findings, 'dangerous/pickle'), 'Detects pickle deserialization (Python)');
  assert(findFinding(result.findings, 'dangerous/sql-injection-in-python'), 'Detects SQL injection in Python');

  // === Test 3: Dangerous Defaults ===
  console.log('\n\x1b[1mDangerous Defaults Scanner\x1b[0m');

  const defaultsDir = path.join(FIXTURES_DIR, 'defaults-test');
  fs.mkdirSync(defaultsDir, { recursive: true });

  fs.writeFileSync(
    path.join(defaultsDir, 'server.js'),
    `
const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.get('/api/users', (req, res) => res.json([]));
app.post('/api/data', (req, res) => res.json({}));
app.listen(3000);
`
  );

  result = await scanDirectory(defaultsDir);
  assert(findFinding(result.findings, 'defaults/no-rate-limiting'), 'Detects missing rate limiting');
  assert(findFinding(result.findings, 'defaults/permissive-cors'), 'Detects permissive CORS');
  assert(findFinding(result.findings, 'defaults/no-auth'), 'Detects missing auth middleware');
  assert(findFinding(result.findings, 'defaults/no-security-headers'), 'Detects missing helmet/security headers');

  fs.writeFileSync(
    path.join(defaultsDir, 'app.py'),
    `
from flask import Flask
app = Flask(__name__)
app.secret_key = 'mysecretkey123'

@app.route('/api/data')
def get_data():
    return 'ok'

if __name__ == '__main__':
    app.run(debug=True)
`
  );

  result = await scanDirectory(defaultsDir);
  assert(findFinding(result.findings, 'defaults/debug-mode'), 'Detects Flask debug=True');
  assert(findFinding(result.findings, 'defaults/hardcoded-secret-key'), 'Detects hardcoded SECRET_KEY');

  // === Test 4: Frontend Exposure ===
  console.log('\n\x1b[1mFrontend Exposure Scanner\x1b[0m');

  const frontendDir = path.join(FIXTURES_DIR, 'frontend-test');
  fs.mkdirSync(path.join(frontendDir, 'src', 'components'), { recursive: true });

  fs.writeFileSync(
    path.join(frontendDir, 'src', 'components', 'App.jsx'),
    `
const STRIPE_KEY = 'sk_live_51ABC123DEF456GHI789JKL012MN';
const DB = 'postgresql://admin:pass@host:5432/db';
`
  );

  result = await scanDirectory(frontendDir);
  assert(findFinding(result.findings, 'frontend/stripe'), 'Detects Stripe key in frontend');
  assert(findFinding(result.findings, 'frontend/database-url'), 'Detects DB URL in frontend');

  // === Test 5: Gitignore ===
  console.log('\n\x1b[1mGitignore Scanner\x1b[0m');

  const gitDir = path.join(FIXTURES_DIR, 'gitignore-test');
  fs.mkdirSync(gitDir, { recursive: true });
  fs.writeFileSync(path.join(gitDir, '.env'), 'SECRET=value');
  // No .gitignore

  result = await scanDirectory(gitDir);
  assert(findFinding(result.findings, 'config/no-gitignore'), 'Detects missing .gitignore when .env exists');

  // Now add gitignore without .env
  fs.writeFileSync(path.join(gitDir, '.gitignore'), 'node_modules/\n');
  result = await scanDirectory(gitDir);
  assert(findFinding(result.findings, 'config/env-not-gitignored'), 'Detects .env not in .gitignore');

  // === Test 6: Dependencies ===
  console.log('\n\x1b[1mDependencies Scanner\x1b[0m');

  const depsDir = path.join(FIXTURES_DIR, 'deps-test');
  fs.mkdirSync(depsDir, { recursive: true });
  fs.writeFileSync(
    path.join(depsDir, 'package.json'),
    JSON.stringify({
      dependencies: {
        express: '^4.18.0',
        faker: '^6.6.6',
        request: '^2.88.0',
        cors: '*',
      },
    })
  );

  result = await scanDirectory(depsDir);
  assert(findFinding(result.findings, 'deps/dangerous-package-faker'), 'Detects corrupted faker package');
  assert(findFinding(result.findings, 'deps/dangerous-package-request'), 'Detects deprecated request package');
  assert(findFinding(result.findings, 'deps/unpinned-version'), 'Detects wildcard version');
  assert(findFinding(result.findings, 'deps/missing-security-packages'), 'Detects missing security packages in server project');

  // === Test 7: Permissive Configs ===
  console.log('\n\x1b[1mPermissive Configs Scanner\x1b[0m');

  const configDir = path.join(FIXTURES_DIR, 'config-test');
  fs.mkdirSync(configDir, { recursive: true });

  fs.writeFileSync(
    path.join(configDir, 'firestore.rules'),
    `
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}
`
  );

  fs.writeFileSync(
    path.join(configDir, 'Dockerfile'),
    `
FROM node:latest
COPY .env .
COPY . .
RUN npm install
CMD ["node", "server.js"]
`
  );

  result = await scanDirectory(configDir);
  assert(findFinding(result.findings, 'config/firebase-permissive'), 'Detects permissive Firebase rules');
  assert(findFinding(result.findings, 'config/docker-copies-env'), 'Detects .env copied into Docker image');
  assert(findFinding(result.findings, 'config/docker-running-as-root'), 'Detects Docker running as root');
  assert(findFinding(result.findings, 'config/docker-latest-tag'), 'Detects Docker :latest tag');

  // === Test 8: Performance ===
  console.log('\n\x1b[1mPerformance\x1b[0m');
  assert(result.summary.elapsed < 1000, `Scan completed in ${result.summary.elapsed}ms (< 1s)`);

  // === Cleanup ===
  fs.rmSync(FIXTURES_DIR, { recursive: true, force: true });

  // Summary
  console.log('\n─────────────────────────────────────────');
  console.log(`\x1b[1m${passed + failed} tests\x1b[0m: \x1b[32m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m\n`);

  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch((err) => {
  console.error(err);
  process.exit(2);
});
