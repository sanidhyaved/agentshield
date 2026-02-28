/**
 * AgentShield v2 API - Context-Aware Static Security Scanner
 *
 * v2 Improvements:
 *  1. File classification layer (dev vs runtime context)
 *  2. Variable-interpolation–aware rule engine (exec template literals vs static strings)
 *  3. Path-sensitive file access detection (only flag ~/.ssh, /etc, .aws - not generic readFile)
 *  4. Sensitive env-var filtering (AWS_SECRET, not HUSKY)
 *  5. Correlation engine (credential read + network call = exfiltration finding)
 *  6. Calibrated confidence formula with context multipliers
 *  7. Revised risk score: Σ(weight × confidence/100), capped at 100
 */

import express from 'express';
import cors from 'cors';

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(process.cwd()));

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 1 - FILE CLASSIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

const DEV_TOP_DIRS = new Set([
  'scripts', 'script', 'test', 'tests', '__tests__', '__mocks__',
  'spec', 'specs', '.github', 'docs', 'documentation', 'examples',
  'example', 'build', 'dist', 'out', 'config', 'configs', 'fixtures',
  'mocks', 'e2e', 'bench', 'benchmark', 'tools', 'tooling', 'ci'
]);

const RUNTIME_TOP_DIRS = new Set(['src', 'lib', 'source', 'core', 'server', 'app', 'api', 'main']);

/** Returns a context label and a confidence multiplier (0–1) for a file path. */
function classifyFile(filePath) {
  const lower = filePath.toLowerCase().replace(/\\/g, '/');
  const parts = lower.split('/');
  const topDir = parts[0];
  const name = parts[parts.length - 1];

  // Test/spec files take the deepest penalty regardless of directory
  if (/\.(test|spec)\.(js|ts|mjs|jsx|tsx|py)$/.test(name) || name.includes('.test.') || name.includes('.spec.')) {
    return { context: 'test', multiplier: 0.15 };
  }

  // package.json - config but needs postinstall check
  if (name === 'package.json') {
    return { context: 'config', multiplier: 1.0 };
  }

  // Development directories
  if (DEV_TOP_DIRS.has(topDir)) {
    return { context: 'dev', multiplier: 0.30 };
  }

  // Known runtime source directories
  if (RUNTIME_TOP_DIRS.has(topDir)) {
    return { context: 'runtime', multiplier: 1.0 };
  }

  // Root-level files (index.js, main.js, cli.js, etc.)
  if (parts.length === 1) {
    return { context: 'runtime', multiplier: 0.90 };
  }

  // Fallback - unknown structure, moderate confidence
  return { context: 'unknown', multiplier: 0.65 };
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 2 - HELPER UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/** Return array of { lineNum, content } matching a regex across file lines. */
function matchLines(lines, regex) {
  return lines
    .map((content, i) => ({ lineNum: i + 1, content }))
    .filter(({ content }) => regex.test(content));
}

/** Return true if the line contains what looks like dynamic/variable input (not a plain string literal). */
function hasDynamicInput(line) {
  if (/`[^`]*\$\{/.test(line)) return true;
  if (/["'][^"']*["']\s*\+\s*[a-zA-Z_$]/.test(line) || /[a-zA-Z_$]\w*\s*\+\s*["']/.test(line)) return true;
  if (/(?:exec|spawn)\s*\(\s*[a-zA-Z_$][\w$]*\s*[,)]/.test(line)) return true;
  return false;
}

/**
 * Import-aware child_process exec line finder.
 * ONLY returns lines where exec/spawn/execSync is called AND the file
 * actually imports those identifiers from 'child_process'.
 * Prevents false positives from RegExp.exec(), String.prototype.exec(), etc.
 */
function getChildProcessLines(content, lines) {
  // Does this file import from child_process at all?
  const hasImport = /require\s*\(\s*['"](child_process)['"]\s*\)|from\s+['"]child_process['"]/.test(content);
  if (!hasImport) {
    // No import - only flag explicit namespaced calls: child_process.exec(...) / cp.exec(...)
    return matchLines(lines, /(?:child_process|childProcess|cp)\s*\.\s*(?:exec|spawn|execSync|spawnSync|execFile|execFileSync)\s*\(/);
  }

  // Extract destructured names: const { exec, spawn } = require('child_process')
  const destructureCJS = content.match(/(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\s*\(\s*['"](child_process)['"]\s*\)/);
  const destructureESM = content.match(/import\s+\{([^}]+)\}\s+from\s+['"]child_process['"]/i);
  const importAll = content.match(/import\s+(\w+)\s+from\s+['"]child_process['"]/i) ||
    content.match(/(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['"]child_process['"]\s*\)/);

  const CP_FNS = ['exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'];
  let watchNames = new Set(CP_FNS); // default: all standard names

  if (destructureCJS || destructureESM) {
    const raw = (destructureCJS || destructureESM)[1];
    // Parse: exec, spawn as spawnAlias → collect both original and alias
    const imported = raw.split(',').flatMap(s => {
      const [orig, alias] = s.trim().split(/\s+as\s+/);
      const names = [orig.trim()];
      if (alias) names.push(alias.trim());
      return names.filter(n => CP_FNS.includes(n) || (alias && CP_FNS.includes(orig.trim())));
    });
    if (imported.length > 0) watchNames = new Set(imported);
  } else if (importAll) {
    // e.g. const cp = require('child_process') - flag cp.exec(...)
    const ns = importAll[1];
    return matchLines(lines, new RegExp(`\\b${ns}\\s*\.\\s*(?:${CP_FNS.join('|')})\\s*\\(`));
  }

  // Build a regex that ONLY matches the imported names as standalone function calls
  // Uses word boundary + negative lookbehind for dot (to skip obj.exec())
  const pattern = new RegExp(
    `(?<![\\w$.\'\"\`])(?:${[...watchNames].join('|')})\\s*\\(`
  );
  return matchLines(lines, pattern);
}

// Sensitive path regex - ONLY real filesystem credential paths, not keywords like 'key' or 'decrypt'
// Requires an actual path string that maps to a known credential location
const SENSITIVE_PATH_RX = /(?:['"`](?:~\/\.ssh\/|~\/\.aws\/)|(?:readFile|readFileSync|createReadStream)\s*\([^)]*(?:\.ssh\/id_(?:rsa|dsa|ecdsa|ed25519)|(?:\/|\\)\.aws(?:\/|\\)credentials|\/etc\/passwd|\/etc\/shadow|\/etc\/sudoers|keychain\/login\.keychain))/i;

// Sensitive env var patterns - credentials, not dev tooling
const SENSITIVE_ENV_RX = /process\.env\.(?:AWS_SECRET|AWS_ACCESS_KEY|AZURE_CLIENT_SECRET|GCP_KEY|GITHUB_TOKEN|GITLAB_TOKEN|NPM_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SECRET_KEY|PRIVATE_KEY|API_SECRET|DB_PASSWORD|DATABASE_URL|JWT_SECRET|AUTH_TOKEN|BEARER_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|STRIPE_SECRET|TWILIO_AUTH)/i;

// Safe env vars to explicitly ignore in general env scanning
const SAFE_ENV_RX = /process\.env\.(?:NODE_ENV|PORT|HOST|PATH|HOME|USER|PWD|npm_|HUSKY|GIT_PARAMS|GIT_AUTHOR|GIT_COMMITTER|DEBUG|LOG_LEVEL|CI|TZ|LANG|TERM|SHELL|COLORTERM|FORCE_COLOR)/i;

// Network call (any outbound HTTP/WS)
const NETWORK_RX = /\bfetch\s*\(|\baxios\s*\.|https?\.request\s*\(|http\.request\s*\(|\bnew\s+WebSocket\s*\(|\bgot\s*\(|superagent\.\w|request\s*\.\w/;

// POST/PUT/mutating network call (higher risk)
const NETWORK_MUTATING_RX = /axios\.(post|put|patch|delete)\s*\(|fetch\s*\([^)]*(?:method\s*:\s*['"](?:POST|PUT|PATCH|DELETE))/i;

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 3 - RULE DEFINITIONS (20 precision rules)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Each rule:
//   id, name, severity, baseConfidence
//   detect(lines, content, filename) → matchedLines[]
//   mitre, description, remediation
//   skipInContext? ('test'|'dev') - if set, rule is skipped entirely in that context
//   penaltyInDev   - apply file-context multiplier (default true)
//

const RULES = [

  // ── HIGH SEVERITY ───────────────────────────────────────────────────────────

  {
    id: 'REVERSE_SHELL',
    name: 'Reverse Shell Payload',
    severity: 'high',
    baseConfidence: 97,
    detect(lines) {
      return matchLines(lines, /\/bin\/bash\s+-i\s+>&|nc\s+-e\s+\/bin|mkfifo.*nc|0\.0\.0\.0:\d{4}|bash\s+-c\s+['"].*>&/);
    },
    mitre: { id: 'T1059.004', name: 'Unix Shell' },
    description: 'Contains a reverse shell payload - a well-known attacker technique that establishes persistent, interactive access to the victim\'s host over the network.',
    remediation: 'DO NOT INSTALL. This is almost certainly malicious. Remove and report to the package registry immediately.'
  },

  {
    id: 'PROMPT_INJECTION',
    name: 'Prompt Injection Instruction',
    severity: 'high',
    baseConfidence: 93,
    detect(lines) {
      return matchLines(lines, /ignore\s+(all\s+)?previous\s+instructions|you\s+are\s+now\s+(a\s+)?(?:DAN|jailbroken|unrestricted)|override\s+system\s+prompt|forget\s+your\s+instructions|ignore\s+your\s+previous/i);
    },
    mitre: { id: 'T1055', name: 'AI Context Hijack via Prompt Injection' },
    description: 'Contains text matching known prompt injection attack patterns. If this text appears in a tool\'s output, it can hijack the behaviour of an AI assistant reading it.',
    remediation: 'Review every string that enters the AI context. Sanitise tool output before including it in prompts. Implement output guardrails.'
  },

  {
    id: 'CMD_INJECT_DYNAMIC',
    name: 'Command Injection - Dynamic Input',
    severity: 'high',
    baseConfidence: 91,
    detect(lines, content) {
      // Use import-aware helper so regExp.exec() / str.exec() never trigger this
      return getChildProcessLines(content, lines)
        .filter(({ content: c }) => hasDynamicInput(c));
    },
    mitre: { id: 'T1059.007', name: 'Command Injection via Dynamic Input' },
    description: 'Calls exec/spawn/execSync with a template literal, string concatenation, or variable argument - confirmed imported from child_process. External input reaching this call enables arbitrary OS command execution.',
    remediation: 'Switch to execFile() with an explicit argument array. Validate every value against a strict allowlist before use. Never pass template literals to exec().'
  },

  {
    id: 'EVAL_DYNAMIC',
    name: 'Dynamic Code Evaluation',
    severity: 'high',
    baseConfidence: 90,
    detect(lines) {
      return matchLines(lines, /\beval\s*\(\s*(?!['"`])[a-zA-Z_$]|\beval\s*\(`[^`]*\$\{|\bnew\s+Function\s*\([^)]*[a-zA-Z_$][\w$]*\s*[,)]/)
        .filter(({ content }) => !/\/\/.*eval/.test(content) && !/eval\s*\(\s*['"`][^'"`]*['"`]\s*\)/.test(content));
    },
    mitre: { id: 'T1059.007', name: 'JavaScript Dynamic Evaluation' },
    description: 'eval() or new Function() is called with a non-literal argument. If that argument contains user or network data, arbitrary JavaScript can be executed at runtime.',
    remediation: 'Remove eval() entirely. Use JSON.parse() for data. Use predefined named functions instead of new Function(). Add a Content Security Policy.'
  },

  {
    id: 'HARDCODED_SECRET',
    name: 'Hardcoded Credential / API Key',
    severity: 'high',
    baseConfidence: 88,
    skipInContext: 'test',
    detect(lines) {
      return matchLines(lines,
        /AKIA[0-9A-Z]{16}|(?:secret|password|api_?key|private_?key|auth_?token)\s*[:=]\s*['"][^'"]{12,}['"]/i
      ).filter(({ content }) => !/placeholder|example|your[-_]?key|replace|changeme|xxx|test|demo|fake/i.test(content));
    },
    mitre: { id: 'T1552.004', name: 'Private Keys / Hardcoded Credentials' },
    description: 'A credential, API key, or private key is hardcoded in source. Any user who installs this package has access to that credential, and it is exposed in version control.',
    remediation: 'Rotate the exposed credential immediately. Move all secrets to environment variables or a secrets manager. Add a pre-commit secret scanner to CI/CD.'
  },

  {
    id: 'SENSITIVE_PATH_READ',
    name: 'Reads Sensitive System Credential Path',
    severity: 'high',
    baseConfidence: 85,
    detect(lines) {
      return matchLines(lines, SENSITIVE_PATH_RX);
    },
    mitre: { id: 'T1552.001', name: 'Unsecured Credentials in Files' },
    description: 'Reads from a known sensitive path: SSH private keys, AWS credentials, TLS certificates, or OS credential stores. This is a high-signal credential access pattern.',
    remediation: 'Review why access to this path is needed. If it is required (e.g. SSH agent tools), document it clearly. If unexpected, treat as credential-harvesting behaviour.'
  },

  {
    id: 'OBFUSCATED_EXEC',
    name: 'Obfuscated Payload Decoded and Executed',
    severity: 'high',
    baseConfidence: 87,
    detect(lines, content) {
      // Only fire if BOTH base64 decode AND exec/eval exist in same file
      const hasB64 = /Buffer\.from\([^)]{20,},\s*['"]base64['"]|atob\s*\(/.test(content);
      const hasExec = /\beval\s*\(|\bexec\s*\(|new Function/.test(content);
      if (!hasB64 || !hasExec) return [];
      return matchLines(lines, /Buffer\.from.*base64|atob\s*\(/);
    },
    mitre: { id: 'T1027', name: 'Obfuscated Files or Information' },
    description: 'The file both decodes a base64 payload AND executes dynamic code. This is a classic technique for hiding malicious payloads from source-level review.',
    remediation: 'Decode and inspect all base64 strings manually before use. Never eval() decoded data. Audit any package using this pattern extremely carefully.'
  },

  {
    id: 'POSTINSTALL_EXEC',
    name: 'Postinstall Script Executes Command',
    severity: 'high',
    baseConfidence: 85,
    detect(lines, content, filename) {
      if (filename !== 'package.json') return [];
      // Flag only if the postinstall value itself runs a shell command (not just a node script)
      const postInstallMatch = content.match(/"postinstall"\s*:\s*"([^"]+)"/);
      if (!postInstallMatch) return [];
      const cmd = postInstallMatch[1];
      if (/node\s+\S+\.js/.test(cmd) && !/&&|;|\||curl|wget|bash|sh\s+/.test(cmd)) {
        // Just running a node script - medium concern (handled by POSTINSTALL rule)
        return [];
      }
      return matchLines(lines, /"postinstall"\s*:/);
    },
    mitre: { id: 'T1195.002', name: 'Supply Chain Compromise: Malicious Dependency' },
    description: 'The postinstall script executes a shell command automatically on `npm install`. Commands like curl, bash, or chained shell ops in postinstall are a primary supply-chain attack vector.',
    remediation: 'Remove the postinstall shell command. If essential, document it clearly. Users can install with `npm install --ignore-scripts` as a precaution.'
  },

  // ── MEDIUM SEVERITY ──────────────────────────────────────────────────────────

  {
    id: 'CREDENTIAL_EXFIL',
    name: 'Sensitive Credential Access + Outbound Network Call',
    severity: 'medium',
    baseConfidence: 82,
    // Fired by correlation engine - not by per-file pattern matching
    synthetic: true,
    detect() { return []; },
    mitre: { id: 'T1020', name: 'Automated Exfiltration' },
    description: 'This file both reads a sensitive credential or secret and makes an outbound network request. While each alone may be legitimate, their co-occurrence is a strong indicator of credential exfiltration.',
    remediation: 'Review the exact data flow between the credential read and the network call. Ensure no secret values are transmitted externally, even as headers or query parameters.'
  },

  {
    id: 'CMD_EXEC_STATIC',
    name: 'Shell Command Execution (Static Arguments)',
    severity: 'low',
    baseConfidence: 55,
    detect(lines, content) {
      // Also requires confirmed child_process import - prevents regExp.exec() matches
      return getChildProcessLines(content, lines)
        .filter(({ content: c }) => !hasDynamicInput(c));
    },
    mitre: { id: 'T1059.007', name: 'Command Execution via child_process' },
    description: 'Executes OS commands with static string arguments - confirmed imported from child_process. While static strings reduce injection risk directly, this should be reviewed to confirm no runtime data paths lead here.',
    remediation: 'Confirm the command string is always hardcoded and never influenced by external input. Prefer execFile() with explicit arg arrays as a defensive measure.'
  },

  {
    id: 'ENV_SENSITIVE_READ',
    name: 'Sensitive Environment Variable Access',
    severity: 'medium',
    baseConfidence: 78,
    detect(lines) {
      return matchLines(lines, SENSITIVE_ENV_RX)
        .filter(({ content }) => !SAFE_ENV_RX.test(content));
    },
    mitre: { id: 'T1552.007', name: 'Credentials: Environment Variables' },
    description: 'Reads an environment variable that likely contains a credential (API key, secret token, database password). This is expected in some tools, but should be reviewed alongside any network calls.',
    remediation: 'Verify that this value is used only for its stated purpose and is never logged, serialised into responses, or transmitted to unexpected endpoints.'
  },

  {
    id: 'NETWORK_MUTATING',
    name: 'HTTP POST/PUT to Variable Endpoint',
    severity: 'medium',
    baseConfidence: 65,
    skipInContext: 'test',
    detect(lines) {
      return matchLines(lines, NETWORK_MUTATING_RX);
    },
    mitre: { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
    description: 'Makes a mutating HTTP request (POST/PUT/PATCH). If this call transmits sensitive data or credentials, it is a data exfiltration risk. Severity increases if the target URL is dynamic.',
    remediation: 'Document all outbound POST calls and verify the destination is a known, legitimate service. Ensure no secret env vars or file contents are included in request bodies.'
  },

  {
    id: 'HARDCODED_IP',
    name: 'Non-Local Hardcoded IP Address',
    severity: 'medium',
    baseConfidence: 72,
    detect(lines) {
      return matchLines(lines, /['"]\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['"]/)
        .filter(({ content }) => !/127\.0\.0\.1|0\.0\.0\.0|::1|192\.168\.|10\.\d+\.\d|172\.(?:1[6-9]|2\d|3[01])\.\d/.test(content));
    },
    mitre: { id: 'T1071.001', name: 'Application Layer Protocol' },
    description: 'A non-local IP address is hardcoded. Public IPs in source code can indicate undisclosed C2 servers, data collection endpoints, or infrastructure used only during attack phases.',
    remediation: 'Replace hardcoded IPs with configurable, named service endpoints. Verify each IP is a known, legitimate service. Prefer domain names for auditability.'
  },

  {
    id: 'POSTINSTALL',
    name: 'Automatic Postinstall Script',
    severity: 'medium',
    baseConfidence: 80,
    detect(lines, content, filename) {
      if (filename !== 'package.json') return [];
      const postInstallMatch = content.match(/"postinstall"\s*:\s*"([^"]+)"/);
      if (!postInstallMatch) return [];
      const cmd = postInstallMatch[1];
      // Skip if already caught as HIGH by POSTINSTALL_EXEC
      if (/&&|;|\||curl|wget|bash\s|sh\s+/.test(cmd)) return [];
      return matchLines(lines, /"postinstall"\s*:/);
    },
    mitre: { id: 'T1195.002', name: 'Supply Chain Compromise' },
    description: 'package.json defines a postinstall script that runs automatically after `npm install`. Even node-based postinstall scripts can perform harmful operations such as file modification or network calls.',
    remediation: 'Review the postinstall script content carefully. Users can suppress automatic script execution with `npm install --ignore-scripts`.'
  },

  {
    id: 'FS_USER_PATH',
    name: 'File Read with Dynamic Path',
    severity: 'medium',
    baseConfidence: 62,
    detect(lines) {
      return matchLines(lines, /(?:readFile|readFileSync|createReadStream)\s*\(/)
        .filter(({ content }) => hasDynamicInput(content));
    },
    mitre: { id: 'T1005', name: 'Data from Local System - Dynamic Path' },
    description: 'Reads a file using a dynamic or variable path. If path construction is influenced by external input, this can allow path traversal attacks or reading of arbitrary sensitive files.',
    remediation: 'Canonicalise and validate all file paths against an allowed base directory. Never construct file paths from user-supplied strings without strict sanitisation.'
  },

  {
    id: 'DYNAMIC_REQUIRE',
    name: 'Dynamic Module Loading',
    severity: 'medium',
    baseConfidence: 52,
    detect(lines) {
      return matchLines(lines, /require\s*\(\s*(?!['"`])[a-zA-Z_$][\w$]/)
        .filter(({ content }) => !/\/\//.test(content.trim().substring(0, 3)));
    },
    mitre: { id: 'T1027.010', name: 'Command Obfuscation: Dynamic Loading' },
    description: 'Loads a module dynamically using a variable name. This can be used to conditionally load different (potentially malicious) modules based on runtime conditions, evading static analysis.',
    remediation: 'Prefer static imports. If dynamic loading is required, validate the module name against an explicit allowlist before requiring.'
  },

  // ── LOW SEVERITY (informational) ────────────────────────────────────────────

  {
    id: 'NETWORK_GET',
    name: 'Outbound HTTP GET Request',
    severity: 'low',
    baseConfidence: 40,
    skipInContext: 'test',
    detect(lines, content) {
      if (NETWORK_MUTATING_RX.test(content)) return []; // Already caught as medium
      return matchLines(lines, /\bfetch\s*\(|\baxios\.get\s*\(|https?\.get\s*\(|\bgot\.get\s*\(|\bgot\s*\(/);
    },
    mitre: { id: 'T1071.001', name: 'Web Protocol - Outbound GET' },
    description: 'Makes an outbound HTTP GET request. This is normal for many packages (e.g. fetching schemas or specs), but is worth noting alongside any credential or file access patterns.',
    remediation: 'Verify the destination URL is a documented, expected endpoint. Ensure no sensitive headers or tokens are attached to these requests unnecessarily.'
  },

  {
    id: 'FS_LOCAL_READ',
    name: 'Local Filesystem Read',
    severity: 'low',
    baseConfidence: 35,
    skipInContext: 'test',
    detect(lines, content) {
      // Skip if already caught by SENSITIVE_PATH_READ or FS_USER_PATH
      if (SENSITIVE_PATH_RX.test(content)) return [];
      return matchLines(lines, /(?:readFile|readFileSync|createReadStream)\s*\(\s*['"`]/)
        .filter(({ content: c }) => !hasDynamicInput(c));
    },
    mitre: { id: 'T1005', name: 'Local Data Access' },
    description: 'Reads from the local filesystem using a static, hardcoded path. For most tools this is entirely expected. Risk increases if combined with outbound network activity.',
    remediation: 'No immediate action needed unless this file also makes network requests. Verify the files being read are within the project directory and not system paths.'
  },

  {
    id: 'LARGE_BASE64',
    name: 'Large Base64–Encoded String',
    severity: 'low',
    baseConfidence: 38,
    detect(lines, content) {
      // Only flag if no exec/eval alongside it (otherwise OBFUSCATED_EXEC fires instead)
      if (/\beval\s*\(|\bexec\s*\(/.test(content)) return [];
      return matchLines(lines, /[A-Za-z0-9+/]{80,}={0,2}/).slice(0, 1);
    },
    mitre: { id: 'T1027', name: 'Obfuscated Files or Information' },
    description: 'Contains a large base64-encoded string, possibly representing embedded binary data, certificates, or bundled assets. Without dynamic execution, this is low risk but merits inspection.',
    remediation: 'Decode and inspect large base64 strings to confirm they represent benign data (certs, images, bundled assets). Document their purpose in comments.'
  },

  {
    id: 'ENV_CHECK',
    name: 'Environment Variable Read',
    severity: 'low',
    baseConfidence: 20,
    skipInContext: 'test',
    detect(lines, content) {
      // Only flag if not caught by ENV_SENSITIVE_READ
      if (SENSITIVE_ENV_RX.test(content)) return [];
      return matchLines(lines, /process\.env\.[A-Z_]{3,}/)
        .filter(({ content: c }) => !SAFE_ENV_RX.test(c))
        .slice(0, 2); // cap at 2 per file
    },
    mitre: { id: 'T1082', name: 'System Information Discovery' },
    description: 'Accesses environment variables. This is normal for configuration, but is noted here for completeness. Review if any sensitive variables are read and whether they stay local.',
    remediation: 'No action needed unless the variable contains credentials. Ensure sensitive env vars are not logged or transmitted.'
  }
];

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 4 - PER-FILE SCANNER
// ═══════════════════════════════════════════════════════════════════════════════

function scanFile(file, targetName = '') {
  const { path: filePath, content } = file;
  const lines = content.split('\n');
  const { context, multiplier } = classifyFile(filePath);
  const findings = [];

  for (const rule of RULES) {
    if (rule.synthetic) continue; // correlation-only rules
    if (rule.skipInContext === context) continue;

    try {
      const matched = rule.detect(lines, content, filePath);
      if (!matched || matched.length === 0) continue;

      // Calculate confidence
      let confidence = rule.baseConfidence;

      // Apply context multiplier
      confidence = confidence * multiplier;

      // Multiple matches = slightly higher confidence
      if (matched.length >= 3) confidence = Math.min(confidence + 8, rule.baseConfidence);
      else if (matched.length >= 2) confidence = Math.min(confidence + 4, rule.baseConfidence);

      // Skip findings whose confidence has dropped below a meaningful threshold
      confidence = Math.round(Math.max(10, Math.min(98, confidence)));
      if (confidence < 20) continue;

      let finalSeverity = rule.severity;
      let findingName = rule.name;
      let exploitability = 'Unconfirmed';

      const extInputSources = [
        'req\\.body', 'req\\.query', 'req\\.params',
        'process\\.argv', 'process\\.env\\.(?!NODE_ENV|PORT)',
        'JSON\\.parse\\(req'
      ];
      const hasExternalInput = new RegExp(extInputSources.join('|'), 'i').test(content);
      const isDynamicRule = ['CMD_INJECT_DYNAMIC', 'EVAL_DYNAMIC', 'FS_USER_PATH', 'NETWORK_MUTATING'].includes(rule.id);

      // 1. Exploitability State Machine
      if (isDynamicRule) {
        if (hasExternalInput) {
          exploitability = 'Confirmed';
        } else if (confidence >= 80) {
          exploitability = 'Likely';
        } else if (confidence >= 50) {
          exploitability = 'Possible';
        } else {
          exploitability = 'Unconfirmed';
        }
      }

      if (hasExternalInput && isDynamicRule) {
        if (finalSeverity !== 'high') finalSeverity = 'high';
      }

      // 1b. Special Evaluation of EVAL_DYNAMIC for Internal Runtime Contexts
      if (rule.id === 'EVAL_DYNAMIC' && !hasExternalInput) {
        if (targetName.toLowerCase().includes('node') || targetName.toLowerCase().includes('linux') || filePath.replace(/\\/g, '/').includes('lib/internal/') || filePath.replace(/\\/g, '/').includes('bootstrap/')) {
          finalSeverity = 'low';
          exploitability = 'Unconfirmed';
        }
      }

      if (rule.id === 'CMD_INJECT_DYNAMIC' || rule.id === 'CMD_EXEC_STATIC') {
        const snippet = matched[0].content;
        if (/\b(?:exec|execSync)\s*\(/.test(snippet)) {
          finalSeverity = 'high';
          findingName = 'High-Risk Command Primitive via exec/execSync';
        } else if (/\bexecFile\s*\(/.test(snippet)) {
          finalSeverity = hasExternalInput ? 'high' : 'medium';
          findingName = 'Command Execution via execFile';
        } else if (/\bspawn\s*\(/.test(snippet)) {
          if (/shell\s*:\s*true/.test(content)) {
            finalSeverity = 'high';
            findingName = 'High-Risk Command Primitive via spawn (shell: true)';
          } else {
            finalSeverity = hasExternalInput ? 'medium' : 'low';
            findingName = 'Command Execution via spawn';
          }
        }
      }

      // 2. Folder-Aware Severity Downgrade
      // Dev scripts and examples are much lower risk natively
      if (context === 'dev' || context === 'test') {
        if (finalSeverity === 'high') finalSeverity = 'medium';
        else if (finalSeverity === 'medium') finalSeverity = 'low';

        if (exploitability === 'Likely') exploitability = 'Possible';
      }

      // 3. Safe Core Pattern Recognition
      if (filePath.replace(/\\/g, '/').includes('lib/internal/')) {
        if (finalSeverity === 'high') finalSeverity = 'medium';
        else if (finalSeverity === 'medium') finalSeverity = 'low';
      }

      // 4. Tie Severity to Confidence Threshold
      if (confidence < 40) {
        // < 40% confidence -> never High or Medium, force to Low
        finalSeverity = 'low';
      } else if (confidence < 80 && finalSeverity === 'high') {
        // < 80% confidence -> never High (max Medium)
        // Only >= 80% allows a HIGH severity finding
        finalSeverity = 'medium';
      }

      // 5. Exploitability Confidence Cap
      if (confidence < 50) {
        if (['Likely', 'Possible', 'Confirmed'].includes(exploitability)) {
          exploitability = 'Unconfirmed';
        }
      }

      // 6. Dynamic Require Rule Improvement
      if (rule.id === 'DYNAMIC_REQUIRE') {
        if (!hasExternalInput) {
          finalSeverity = 'low';
        }
      }

      const firstMatch = matched[0];

      findings.push({
        ruleId: rule.id,
        name: findingName,
        severity: finalSeverity,
        confidence,
        exploitability,
        fileContext: context,
        mitre: rule.mitre,
        description: rule.description,
        remediation: rule.remediation,
        file: filePath,
        line: firstMatch.lineNum,
        snippet: firstMatch.content.trim().substring(0, 160),
        occurrences: matched.length
      });
    } catch { /* skip broken rule */ }
  }

  return { findings, context, hasNetworkCall: NETWORK_RX.test(content), hasSensitivePath: SENSITIVE_PATH_RX.test(content), hasSensitiveEnv: SENSITIVE_ENV_RX.test(content) };
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 5 - CORRELATION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

function runCorrelation(fileResults) {
  const syntheticFindings = [];

  for (const { findings, hasNetworkCall, hasSensitivePath, hasSensitiveEnv, file } of fileResults) {
    // Pattern: sensitive credential path read + outbound network call → Exfiltration signal
    if (hasSensitivePath && hasNetworkCall) {
      const credRule = RULES.find(r => r.id === 'CREDENTIAL_EXFIL');
      const pathFinding = findings.find(f => f.ruleId === 'SENSITIVE_PATH_READ');
      const netFinding = findings.find(f => ['NETWORK_MUTATING', 'NETWORK_GET'].includes(f.ruleId));

      syntheticFindings.push({
        ruleId: 'CREDENTIAL_EXFIL',
        name: credRule.name,
        severity: 'high',
        confidence: Math.round(Math.min(90, ((pathFinding?.confidence ?? 70) + (netFinding?.confidence ?? 50)) / 2 + 15)),
        exploitability: 'Confirmed',
        fileContext: 'correlation',
        mitre: credRule.mitre,
        description: credRule.description,
        remediation: credRule.remediation,
        file: pathFinding?.file || file,
        line: pathFinding?.line || 1,
        snippet: `Correlated: sensitive path read + outbound HTTP in same file`,
        occurrences: 1,
        synthetic: true
      });
    }

    // Pattern: sensitive env var + outbound network → potential env credential exfil
    if (hasSensitiveEnv && hasNetworkCall && !hasSensitivePath) {
      const envFinding = findings.find(f => f.ruleId === 'ENV_SENSITIVE_READ');
      const netFinding = findings.find(f => ['NETWORK_MUTATING', 'NETWORK_GET'].includes(f.ruleId));
      if (envFinding && netFinding) {
        envFinding.severity = 'high';
        envFinding.confidence = Math.min(88, envFinding.confidence + 18);
        envFinding.name = 'Sensitive Env Var Access + Outbound Network';
        envFinding.description = 'Reads a sensitive credential from environment variables AND makes an outbound network request in the same file. This co-occurrence is a strong indicator of credential exfiltration behaviour.';
      }
    }
  }

  return syntheticFindings;
}

// ═══════════════════════════════════════════════════════════════════════════════
// LAYER 6 - RISK SCORING
// ═══════════════════════════════════════════════════════════════════════════════

function calculateRiskScore(findings) {
  if (!findings.length) return 0;
  const W = { high: 15, medium: 7, low: 3 };
  let score = 0;
  for (const f of findings) {
    score += (W[f.severity] ?? 3) * (f.confidence / 100);
  }
  return Math.min(100, Math.round(score));
}

function riskLevel(score) {
  if (score >= 75) return 'Critical';
  if (score >= 50) return 'High';
  if (score >= 25) return 'Medium';
  return 'Low';
}

// ═══════════════════════════════════════════════════════════════════════════════
// FETCHERS (unchanged from v1 - logic here is solid)
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_GITHUB_TOKEN = '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';

function parseGitHubURL(url) {
  // Support: github.com/owner/repo, https://github.com/..., or shorthand owner/repo
  const full = url.match(/github\.com\/([^\/\s]+)\/([^\/\s?#]+)/);
  if (full) return { owner: full[1], repo: full[2].replace(/\.git$/, '') };
  // Shorthand: expressjs/express  (two parts, no protocol/domain)
  const short = url.match(/^([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)$/);
  if (short) return { owner: short[1], repo: short[2] };
  return null;
}
const SCAN_EXTENSIONS = ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.py', '.json', '.sh'];
const SKIP_FETCH_DIRS = new Set(['node_modules', 'dist', 'build', 'out', '.git', 'vendor', '__pycache__']);

async function fetchGitHubFiles(owner, repo, customToken) {
  const token = customToken || process.env.GITHUB_TOKEN || DEFAULT_GITHUB_TOKEN;
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': 'AgentShield/2.0',
    Authorization: `Bearer ${token}`
  };

  const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`, { headers });
  if (!treeRes.ok) {
    const msg = treeRes.status === 404 ? `Repository "${owner}/${repo}" not found or private.`
      : treeRes.status === 403 ? 'GitHub API rate limit hit. Try again in 60 seconds.'
        : `GitHub API error ${treeRes.status}`;
    throw new Error(msg);
  }
  const tree = await treeRes.json();
  if (!tree.tree) throw new Error('Cannot read repository tree.');

  const targets = tree.tree
    .filter(f => f.type === 'blob' && f.size < 200000)
    .filter(f => SCAN_EXTENSIONS.some(e => f.path.toLowerCase().endsWith(e)))
    .filter(f => !SKIP_FETCH_DIRS.has(f.path.split('/')[0]))
    .sort((a, b) => {
      // Prioritise package.json + runtime dirs
      const aRuntime = RUNTIME_TOP_DIRS.has(a.path.split('/')[0]) || a.path === 'package.json';
      const bRuntime = RUNTIME_TOP_DIRS.has(b.path.split('/')[0]) || b.path === 'package.json';
      return (bRuntime ? 1 : 0) - (aRuntime ? 1 : 0);
    })
    .slice(0, 1000); // Increased to scan larger swathes typical of massive repos

  const results = [];
  // Batch processing to respect secondary rate limits
  for (let i = 0; i < targets.length; i += 50) {
    const chunk = targets.slice(i, i + 50);
    const chunkResults = await Promise.all(chunk.map(async f => {
      try {
        const r = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${f.path}`, { headers });
        if (!r.ok) return null;
        const d = await r.json();
        if (d.encoding === 'base64' && d.content) {
          return { path: f.path, content: Buffer.from(d.content.replace(/\n/g, ''), 'base64').toString('utf-8') };
        }
      } catch { /* skip file */ }
      return null;
    }));
    results.push(...chunkResults.filter(Boolean));
  }

  return results;
}

async function fetchNpmFiles(pkg) {
  const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg)}/latest`);
  if (!r.ok) throw new Error(r.status === 404 ? `Package "${pkg}" not found on npm.` : `npm registry error ${r.status}`);
  const meta = await r.json();
  const files = [];

  files.push({
    path: 'package.json',
    content: JSON.stringify({ name: meta.name, version: meta.version, scripts: meta.scripts, dependencies: meta.dependencies, devDependencies: meta.devDependencies, main: meta.main, bin: meta.bin }, null, 2)
  });

  const candidates = [...new Set([meta.main || 'index.js', 'index.js', 'src/index.js', 'lib/index.js', 'cli.js', 'bin/cli.js'])];
  for (const f of candidates) {
    if (files.length >= 8) break;
    try {
      const res = await fetch(`https://unpkg.com/${pkg}@${meta.version}/${f}`, { headers: { 'User-Agent': 'AgentShield/2.0' } });
      if (!res.ok) continue;
      const content = await res.text();
      if (content?.trim().length > 20 && !content.trim().startsWith('<!')) {
        files.push({ path: f, content });
      }
    } catch { /* skip */ }
  }
  return files;
}

// ═══════════════════════════════════════════════════════════════════════════════
// API ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/health', (_, res) => res.json({ status: 'ok', version: '2.0.0', rules: RULES.filter(r => !r.synthetic).length }));

app.post('/api/scan', async (req, res) => {
  const { target, customToken, simulatePR } = req.body ?? {};
  if (!target?.trim()) return res.status(400).json({ error: 'Provide a GitHub URL or npm package name.' });

  const t = target.trim();
  let files = [], targetType = '', displayName = t;

  try {
    const ghInfo = parseGitHubURL(t);
    if (ghInfo) {
      // Matches github.com URLs or owner/repo shorthand
      targetType = 'github';
      displayName = `${ghInfo.owner}/${ghInfo.repo}`;
      files = await fetchGitHubFiles(ghInfo.owner, ghInfo.repo, customToken);
    } else {
      // Treat as npm package name
      targetType = 'npm';
      files = await fetchNpmFiles(t);
    }

    if (!files.length) return res.status(400).json({ error: 'No scannable source files found.' });

    // Scan each file
    const fileResults = files.map(f => ({ file: f.path, ...scanFile(f, displayName) }));

    // Gather all per-file findings
    const allFindings = fileResults.flatMap(r => r.findings);

    // Extract ports
    const portsDetected = new Set();
    const portRegex = /(?:listen|server\.listen|app\.listen)\s*\(\s*(?:process\.env\.[A-Z_]+(?:\s*\|\|\s*)?)?(\d{2,5}|['"]\d{2,5}['"]|[A-Za-z_][A-Za-z0-9_]*)/i;
    files.forEach(f => {
      const lines = f.content.split('\n');
      lines.forEach(line => {
        const match = line.match(portRegex);
        if (match && match[1]) {
          let p = match[1].replace(/['"]/g, '');
          if (p.toUpperCase() === 'PORT' || isNaN(parseInt(p))) {
            portsDetected.add(`Variable: ${p}`);
          } else {
            portsDetected.add(p);
          }
        }
      });
    });

    // Run correlation checks
    const correlatedFindings = runCorrelation(fileResults);
    allFindings.push(...correlatedFindings);

    // Deduplicate (same ruleId) and merge paths
    const groupedMap = new Map();
    for (const f of allFindings) {
      if (!groupedMap.has(f.ruleId)) {
        groupedMap.set(f.ruleId, {
          ...f,
          files: [f.file],
          allOccurrences: f.occurrences || 1
        });
      } else {
        const existing = groupedMap.get(f.ruleId);
        if (!existing.files.includes(f.file)) {
          existing.files.push(f.file);
        }
        existing.allOccurrences += (f.occurrences || 1);
        existing.confidence = Math.max(existing.confidence, f.confidence);
      }
    }

    // Sort: severity order, then descending confidence
    const ORDER = { high: 0, medium: 1, low: 2 };
    const unique = Array.from(groupedMap.values()).sort((a, b) => ORDER[a.severity] - ORDER[b.severity] || b.confidence - a.confidence);

    const riskScore = calculateRiskScore(unique);
    const counts = unique.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc; }, { high: 0, medium: 0, low: 0 });

    // Capability Footprint Extract
    const capabilities = {
      fsRead: 0,
      fsWrite: 0,
      fsDelete: 0,
      shellImport: 0,
      shellExec: 0,
      network: 0,
      dynamicModule: 0,
      dynamicEval: 0,
      environment: 0,
      envSensitive: 0
    };

    files.forEach(f => {
      const c = f.content;
      capabilities.fsRead += (c.match(/readFile|createReadStream|readDir|readdirSync/ig) || []).length;
      capabilities.fsWrite += (c.match(/writeFile|createWriteStream|appendFile|writeFileSync/ig) || []).length;
      capabilities.fsDelete += (c.match(/unlink|rmdir|rmSync|rmdirSync|unlinkSync/ig) || []).length;
      capabilities.shellImport += (c.match(/require\s*\(\s*['"`]child_process['"`]\)|from\s+['"`]child_process['"`]/ig) || []).length;
      capabilities.shellExec += (c.match(/exec\s*\(|spawn\s*\(|execSync/ig) || []).length;
      capabilities.network += (c.match(/fetch\s*\(|axios\.|\.request\s*\(|WebSocket/ig) || []).length;
      capabilities.dynamicModule += (c.match(/require\s*\(\s*(?!['"`])/ig) || []).length;
      capabilities.dynamicEval += (c.match(/eval\s*\(|new Function/ig) || []).length;
      capabilities.environment += (c.match(/process\.env/ig) || []).length;
      capabilities.envSensitive += (c.match(/AWS_|SECRET|KEY|PASSWORD|TOKEN|AUTH|CREDENTIAL/ig) || []).length;
    });

    let privilegeScore = 0;
    const privilegeReasons = [];
    if (capabilities.shellImport > 0 || capabilities.shellExec > 0) { privilegeScore += 3; privilegeReasons.push('Shell execution capabilities'); }
    if (capabilities.network > 0) { privilegeScore += 2; privilegeReasons.push('Network outbound access'); }
    if (capabilities.fsWrite > 0 || capabilities.fsDelete > 0) { privilegeScore += 2; privilegeReasons.push('Filesystem mutating operations'); }
    if (capabilities.fsRead > 0) { privilegeScore += 1; privilegeReasons.push('Filesystem read surface'); }
    if (capabilities.environment > 0) { privilegeScore += 1; privilegeReasons.push('Environment variable probing'); }
    if (capabilities.envSensitive > 0) { privilegeScore += 1; privilegeReasons.push('Sensitive credential access'); }
    if (capabilities.dynamicModule > 0) { privilegeScore += 2; privilegeReasons.push('Dynamic module loading'); }
    if (capabilities.dynamicEval > 0) { privilegeScore += 3; privilegeReasons.push('Dynamic code evaluation'); }

    let privilegeSurface = 'Minimal';
    if (privilegeScore >= 9) privilegeSurface = 'High';
    else if (privilegeScore >= 6) privilegeSurface = 'Elevated';
    else if (privilegeScore >= 3) privilegeSurface = 'Moderate';

    capabilities.privilegeScore = privilegeScore;
    capabilities.privilegeSurface = privilegeSurface;
    capabilities.privilegeReasons = privilegeReasons;

    // Simulate previous state for PR Mode Showcase
    let previousCapabilities = null;
    if (simulatePR) {
      previousCapabilities = {
        fsRead: Math.max(0, capabilities.fsRead - 2),
        fsWrite: Math.max(0, capabilities.fsWrite - 1),
        fsDelete: capabilities.fsDelete,
        shellImport: capabilities.shellImport > 0 ? capabilities.shellImport - 1 : 0,
        shellExec: capabilities.shellExec > 0 ? 0 : 0,
        network: Math.max(0, capabilities.network - 3),
        dynamicModule: capabilities.dynamicModule,
        dynamicEval: capabilities.dynamicEval,
        environment: Math.max(0, capabilities.environment - 1),
        envSensitive: Math.max(0, capabilities.envSensitive - 1)
      };

      let pScore = 0;
      if (previousCapabilities.shellImport > 0 || previousCapabilities.shellExec > 0) pScore += 3;
      if (previousCapabilities.network > 0) pScore += 2;
      if (previousCapabilities.fsWrite > 0 || previousCapabilities.fsDelete > 0) pScore += 2;
      if (previousCapabilities.fsRead > 0) pScore += 1;
      if (previousCapabilities.environment > 0) pScore += 1;
      if (previousCapabilities.envSensitive > 0) pScore += 1;
      if (previousCapabilities.dynamicModule > 0) pScore += 2;
      if (previousCapabilities.dynamicEval > 0) pScore += 3;

      let pSurface = 'Minimal';
      if (pScore >= 9) pSurface = 'High';
      else if (pScore >= 6) pSurface = 'Elevated';
      else if (pScore >= 3) pSurface = 'Moderate';

      previousCapabilities.privilegeScore = pScore;
      previousCapabilities.privilegeSurface = pSurface;
    }

    // File summary for transparency
    const fileSummary = fileResults.map(r => ({ path: r.file, context: r.context, findings: r.findings.length }));

    res.json({
      target: displayName,
      targetType,
      filesScanned: files.length,
      portsDetected: Array.from(portsDetected),
      capabilities,
      previousCapabilities,
      riskScore,
      riskLevel: riskLevel(riskScore),
      counts,
      findings: unique,
      fileSummary,
      scannedAt: new Date().toISOString()
    });

  } catch (err) {
    console.error('[SCAN ERROR]', err.message);
    res.status(500).json({ error: err.message || 'Scan failed.' });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n🛡️  AgentShield API v2 → http://localhost:${PORT}`);
  console.log(`   Rules loaded: ${RULES.filter(r => !r.synthetic).length} pattern rules + 1 correlation engine`);
  console.log(`   Contexts: runtime=1.0x | dev=0.30x | test=0.15x\n`);
});
